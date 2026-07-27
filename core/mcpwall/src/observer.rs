//! L'observateur qui relie le relais au journal.
//!
//! C'est lui qui tient l'état de session : capture de l'`initialize`, écoute
//! passive des racines, résolution du scope. Le relais, lui, ne connaît que des
//! octets et des verdicts — la sémantique de session vit ici.
//!
//! Aucune méthode ne rend d'erreur : par construction, un observateur en
//! difficulté ne peut pas interrompre le trafic.

use std::sync::{Arc, Mutex};

use crate::frame::SplitterStats;
use crate::journal::{Entry, Journal, SessionRow, now_ms};
use crate::mcp::{MethodScan, Verdict, parse_client_hello, parse_server_hello};
use crate::scope::{ScopeResolver, ScopeSource, parse_root_uri};
use crate::wrap::{Anomaly, Direction, FrameEvent, Observer};

/// Longueur maximale d'un extrait d'arguments stocké.
///
/// Le journal ne doit **jamais** contenir la valeur d'un secret détecté. On
/// tronque, et en M1 le moteur de politique remplacera l'extrait par le type du
/// secret et un préfixe.
const PREVIEW_MAX: usize = 200;

#[derive(Default)]
struct State {
    session_id: i64,
    row: SessionRow,
    scope: ScopeResolver,
    /// `id` de la requête `initialize`, pour reconnaître sa réponse dans le flux
    /// descendant — c'est elle qui porte la version négociée et le `serverInfo`.
    initialize_id: Option<String>,
    dirty: bool,
}

pub struct JournalObserver {
    journal: Journal,
    state: Mutex<State>,
}

impl JournalObserver {
    /// Ouvre la session en base et rend l'observateur prêt à l'emploi.
    pub async fn new(
        journal: Journal,
        command: String,
        project: Option<std::path::PathBuf>,
    ) -> Arc<Self> {
        let mut scope = ScopeResolver::new();

        // Maillon 1 : le chemin injecté par `mcpwall init`.
        if let Some(p) = project {
            scope.set_injected(crate::scope::canonicalize_for_scope(&p));
        }
        // Maillon 3 : le cwd hérité du client, canonicalisé.
        if let Ok(cwd) = std::env::current_dir() {
            scope.set_cwd(crate::scope::canonicalize_for_scope(&cwd));
        }

        let resolved = scope.resolve();
        let row = SessionRow {
            started_ms: now_ms(),
            scope_key: resolved.key(),
            scope_source: resolved.source().as_str().to_owned(),
            command,
            ..Default::default()
        };

        let session_id = journal.open_session(row.clone()).await.unwrap_or(0);

        Arc::new(Self {
            journal,
            state: Mutex::new(State {
                session_id,
                row,
                scope,
                initialize_id: None,
                dirty: false,
            }),
        })
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Extrait de `params`, tronqué sur une frontière de caractère.
    fn preview(frame: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(frame).ok()?;
        let params = text.find("\"params\"").unwrap_or(0);
        let slice = &text[params..];
        let end = slice
            .char_indices()
            .map(|(i, c)| i + c.len_utf8())
            .take_while(|&i| i <= PREVIEW_MAX)
            .last()
            .unwrap_or(0);
        Some(slice[..end].to_owned())
    }

    /// Capture ce qui a de la valeur dans le trafic OBSERVE.
    fn observe_semantics(&self, event: &FrameEvent<'_>) {
        let Ok(mut st) = self.state.lock() else {
            // Verrou empoisonné : on renonce à la sémantique, pas au relais.
            return;
        };

        match (event.direction, event.method) {
            (Direction::ToServer, Some("initialize")) => {
                if let Some(hello) = parse_client_hello(event.frame.content()) {
                    st.row.client_name = hello.client_name;
                    st.row.client_version = hello.client_version;
                    st.dirty = true;
                }
                st.initialize_id = request_id(event.frame.content());
            }

            // La réponse à `initialize` porte la version **négociée** et le
            // `serverInfo`. C'est elle qu'on stocke, pas la demande du client.
            (Direction::ToClient, None) => {
                let is_init_reply = match (&st.initialize_id, request_id(event.frame.content())) {
                    (Some(expected), Some(got)) => *expected == got,
                    _ => false,
                };
                if is_init_reply && let Some(hello) = parse_server_hello(event.frame.content()) {
                    st.row.server_name = hello.server_name;
                    st.row.server_version = hello.server_version;
                    st.row.protocol_version = hello.protocol_version;
                    st.dirty = true;
                }
            }

            // Maillon 2 du scope : les racines, observées passivement. La
            // requête vient du serveur, la réponse du client — elle circule donc
            // dans le sens montant.
            (Direction::ToServer, None) => {
                if let Some(roots) = parse_roots(event.frame.content()) {
                    st.scope.observe_roots(roots);
                    let resolved = st.scope.resolve();
                    st.row.scope_key = resolved.key();
                    st.row.scope_source = resolved.source().as_str().to_owned();
                    st.dirty = true;
                }
            }

            _ => {}
        }

        if st.dirty {
            st.dirty = false;
            let (id, row) = (st.session_id, st.row.clone());
            drop(st); // jamais de verrou tenu pendant un envoi
            self.journal.update_session(id, row);
        }
    }
}

impl Observer for JournalObserver {
    fn on_frame(&self, event: &FrameEvent<'_>) {
        if !matches!(event.scan, MethodScan::NoMethod) || event.direction == Direction::ToClient {
            self.observe_semantics(event);
        }

        let session_id = self.state.lock().map(|s| s.session_id).unwrap_or(0);

        let (verdict, rule) = match event.verdict {
            Some(Verdict::Allow) => (Some("allow".to_owned()), None),
            Some(Verdict::Deny { rule, .. }) => (Some("deny".to_owned()), Some(rule.clone())),
            None => (None, None),
        };

        self.journal.log(Entry {
            ts_ms: now_ms(),
            session_id,
            direction: event.direction.as_str(),
            method: event.method.map(str::to_owned),
            disposition: event.disposition.to_string(),
            verdict,
            rule,
            preview: matches!(event.disposition, crate::mcp::Disposition::Decide)
                .then(|| Self::preview(event.frame.content()))
                .flatten(),
            bytes: event.frame.len() as i64,
        });
    }

    fn on_anomaly(&self, anomaly: &Anomaly) {
        let session_id = self.state.lock().map(|s| s.session_id).unwrap_or(0);

        let (direction, kind, rule) = match anomaly {
            Anomaly::Oversize { direction, limit } => {
                tracing::warn!(limite = limit, "frame surdimensionnée rejetée");
                (*direction, "oversize", Some("frame_oversize"))
            }
            Anomaly::Unterminated { direction } => (*direction, "unterminated", None),
            Anomaly::DeniedWithoutId { direction } => (*direction, "denied_without_id", None),
            Anomaly::DecisionUnavailable {
                direction,
                reason,
                fail_closed,
            } => {
                tracing::warn!(raison = %reason, fail_closed, "point de décision indisponible");
                (*direction, "decision_unavailable", Some("fail_open"))
            }
        };

        self.journal.log(Entry {
            rule: rule.map(str::to_owned),
            ..Entry::now(session_id, direction.as_str(), kind)
        });
    }

    fn on_eof(&self, direction: Direction, stats: SplitterStats) {
        tracing::debug!(
            %direction,
            frames = stats.frames,
            octets = stats.bytes_in,
            vides = stats.empty_skipped,
            surdimensionnées = stats.oversize,
            non_terminées = stats.unterminated,
            "fin de flux"
        );
    }
}

/// `id` d'une requête ou d'une réponse, rendu sous forme textuelle.
///
/// La spec autorise un entier ou une chaîne ; on normalise pour comparer sans
/// se soucier du type.
fn request_id(frame: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    match v.get("id")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Extrait les racines d'une réponse à `roots/list`.
///
/// Une racine dont l'URI n'est pas comprise est ignorée plutôt que rapprochée
/// de force d'un chemin : elle ne doit jamais devenir une clé de permission.
fn parse_roots(frame: &[u8]) -> Option<Vec<std::path::PathBuf>> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let roots = v.get("result")?.get("roots")?.as_array()?;
    let paths: Vec<_> = roots
        .iter()
        .filter_map(|r| r.get("uri")?.as_str().and_then(parse_root_uri))
        .map(|p| crate::scope::canonicalize_for_scope(&p))
        .collect();
    (!paths.is_empty()).then_some(paths)
}

/// Provenance courante du scope, pour l'UI et les tests.
impl JournalObserver {
    pub fn scope_source(&self) -> ScopeSource {
        self.state
            .lock()
            .map(|s| s.scope.resolve().source())
            .unwrap_or(ScopeSource::Unknown)
    }

    pub fn scope_key(&self) -> String {
        self.state
            .lock()
            .map(|s| s.scope.resolve().key())
            .unwrap_or_else(|_| "unknown".to_owned())
    }

    pub fn scope_paths(&self) -> Vec<std::path::PathBuf> {
        self.state
            .lock()
            .map(|s| s.scope.resolve().paths().to_vec())
            .unwrap_or_default()
    }

    pub fn session_id(&self) -> i64 {
        self.state.lock().map(|s| s.session_id).unwrap_or(0)
    }
}

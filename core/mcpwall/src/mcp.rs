//! Sémantique MCP : identification de la méthode, classement des frames, point
//! de décision, capture de l'`initialize`.
//!
//! Deux régimes, volontairement asymétriques :
//!
//! - Le **scan de méthode** est bon marché et tourne sur chaque frame. Il ne
//!   construit aucune structure, n'alloue que le nom de la méthode, et suit la
//!   profondeur des accolades pour n'accepter `method` que comme clé de l'objet
//!   racine.
//! - La **capture de l'`initialize`** parse pour de bon avec `serde_json`. Elle
//!   tourne deux fois par session, jamais dans le chemin critique.
//!
//! Sans I/O, comme `frame`.

use std::fmt;

/// Fenêtre de scan bon marché, en octets.
///
/// Au-delà, [`scan_method`] repart pour une passe complète plutôt que de
/// conclure « pas de méthode » par silence. Un `id` de type chaîne un peu long,
/// ou un sérialiseur qui place `params` avant `method`, suffit à repousser la
/// clé hors fenêtre — ce n'est pas un cas tordu, c'est du trafic ordinaire.
pub const METHOD_SCAN_WINDOW: usize = 200;

// ---------------------------------------------------------------------------
// Scan de méthode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodScan {
    /// Méthode extraite d'une clé de l'objet racine.
    Found {
        method: String,
        /// La fenêtre n'a pas suffi, il a fallu scanner toute la frame. Compté,
        /// parce qu'un taux élevé signifie qu'il faut élargir [`METHOD_SCAN_WINDOW`].
        full_scan: bool,
    },
    /// Aucune clé `method` à la racine dans toute la frame.
    ///
    /// Ce n'est pas une anomalie : une réponse JSON-RPC (`result` ou `error`)
    /// n'a légitimement pas de méthode.
    NoMethod,
    /// Une clé `method` existe mais sa valeur n'a pas pu être lue : valeur non
    /// textuelle, échappement, ou frame tronquée.
    ///
    /// Jamais silencieux. Le classement retombe sur [`Disposition::Observe`] —
    /// on journalise, on ne décide pas sur une base qu'on ne comprend pas.
    Unparsable,
}

/// Identifie la méthode d'une frame.
///
/// Tente d'abord la fenêtre, puis la frame entière. Les frames dont la taille
/// tient déjà dans la fenêtre ne sont scannées qu'une fois.
pub fn scan_method(frame: &[u8]) -> MethodScan {
    if frame.len() <= METHOD_SCAN_WINDOW {
        return match scan_within(frame, frame.len()) {
            Scan::Found(m) => MethodScan::Found {
                method: m,
                full_scan: false,
            },
            Scan::Absent => MethodScan::NoMethod,
            // Une frame plus courte que la fenêtre qui s'épuise quand même est
            // tronquée, pas incomplète.
            Scan::Truncated | Scan::Bad => MethodScan::Unparsable,
        };
    }

    match scan_within(frame, METHOD_SCAN_WINDOW) {
        Scan::Found(m) => MethodScan::Found {
            method: m,
            full_scan: false,
        },
        Scan::Bad => MethodScan::Unparsable,
        // Fenêtre épuisée, ou clé absente de la fenêtre : on ne conclut rien,
        // on repart sur la frame complète.
        Scan::Truncated | Scan::Absent => match scan_within(frame, frame.len()) {
            Scan::Found(m) => MethodScan::Found {
                method: m,
                full_scan: true,
            },
            Scan::Absent => MethodScan::NoMethod,
            Scan::Truncated | Scan::Bad => MethodScan::Unparsable,
        },
    }
}

enum Scan {
    Found(String),
    /// Aucune clé `method` à la racine dans la portion examinée.
    Absent,
    /// La limite a été atteinte avant de pouvoir conclure.
    Truncated,
    /// Clé trouvée mais valeur illisible.
    Bad,
}

/// Automate à états sur les `limit` premiers octets.
///
/// Suit la profondeur des accolades et l'état « dans une chaîne » pour ne
/// retenir `method` que s'il s'agit d'une clé de l'objet racine. C'est ce qui
/// distingue ce scan d'une recherche de sous-chaîne : sur
/// `{"params":{"method":"x"},"method":"tools/call"}`, une recherche naïve
/// rendrait `x`.
fn scan_within(frame: &[u8], limit: usize) -> Scan {
    let end = limit.min(frame.len());
    let truncated = end < frame.len();

    let mut i = 0;

    // Saute jusqu'à l'ouverture de l'objet racine.
    while i < end && frame[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= end {
        return if truncated {
            Scan::Truncated
        } else {
            Scan::Absent
        };
    }
    if frame[i] != b'{' {
        // Tableau (batch, retiré de la spec depuis 2025-06-18) ou scalaire.
        // Pas notre affaire ici ; la violation est signalée ailleurs.
        return Scan::Absent;
    }
    let mut depth: i32 = 1;
    i += 1;

    while i < end {
        match frame[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Scan::Absent; // objet racine refermé, pas de `method`
                }
            }
            b'"' => {
                let Some((content, next, key_escaped)) = read_string(frame, i, end) else {
                    return if truncated {
                        Scan::Truncated
                    } else {
                        Scan::Bad
                    };
                };

                // Une chaîne à la profondeur 1 suivie de `:` est une clé racine.
                let mut j = next;
                while j < end && frame[j].is_ascii_whitespace() {
                    j += 1;
                }
                let is_key = j < end && frame[j] == b':';

                if depth == 1 && is_key && !key_escaped && content == b"method" {
                    j += 1;
                    while j < end && frame[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j >= end {
                        return if truncated {
                            Scan::Truncated
                        } else {
                            Scan::Bad
                        };
                    }
                    if frame[j] != b'"' {
                        return Scan::Bad; // `method` non textuelle
                    }
                    let Some((value, _, value_escaped)) = read_string(frame, j, end) else {
                        return if truncated {
                            Scan::Truncated
                        } else {
                            Scan::Bad
                        };
                    };
                    if value_escaped {
                        // Aucune méthode MCP légitime ne contient d'échappement.
                        // On refuse de deviner : `Observe`, jamais `Decide`.
                        return Scan::Bad;
                    }
                    return match std::str::from_utf8(value) {
                        Ok(s) => Scan::Found(s.to_owned()),
                        Err(_) => Scan::Bad,
                    };
                }

                i = if is_key { j } else { next };
            }
            _ => i += 1,
        }
    }

    if truncated {
        Scan::Truncated
    } else {
        Scan::Absent
    }
}

/// Lit la chaîne JSON commençant au guillemet `start`.
///
/// Rend le contenu brut, l'index suivant le guillemet fermant, et si la chaîne
/// contenait un échappement. Rend `None` uniquement si elle n'est pas close
/// avant `end`.
///
/// Les échappements sont traversés correctement plutôt qu'abandonnés, et ce
/// n'est pas un détail de confort : un scan qui renonce sur le premier `\`
/// classe la frame en `Unparsable` donc en `Observe`, c'est-à-dire hors du
/// point de décision. Un `tools/call` dont l'`id` contient `\"` suffirait alors
/// à contourner la politique. Le contenu rendu reste brut — on ne décode rien,
/// on sait seulement où la chaîne s'arrête.
fn read_string(frame: &[u8], start: usize, end: usize) -> Option<(&[u8], usize, bool)> {
    debug_assert_eq!(frame[start], b'"');
    let mut i = start + 1;
    let mut escaped = false;
    while i < end {
        match frame[i] {
            b'"' => return Some((&frame[start + 1..i], i + 1, escaped)),
            b'\\' => {
                escaped = true;
                // Le caractère suivant est littéral, y compris `"` et `\`.
                i += 2;
            }
            _ => i += 1,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Classement
// ---------------------------------------------------------------------------

/// Ce que le shim a le droit de faire d'une frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Relais immédiat, journalisation sommaire. Zéro parsing supplémentaire.
    Passthrough,
    /// Journalisation enrichie, mais **jamais** soumise au point de décision.
    Observe,
    /// Passe par le point de décision. Peut être bloquée.
    Decide,
}

/// Méthodes soumises au point de décision.
///
/// N'ajouter ici que ce dont le blocage est à la fois utile et survivable pour
/// la session de l'agent.
const DECIDE: &[&str] = &[
    "tools/call",
    "resources/read",
    "sampling/createMessage",
    "elicitation/create",
];

/// Méthodes journalisées en détail mais jamais bloquables.
///
/// `initialize` y figure et doit y rester : le bloquer ne protège de rien et
/// tue la session entière. La séparation des deux ensembles existe précisément
/// pour qu'on ne puisse pas le déplacer par inadvertance — voir
/// [`initialize_is_never_decidable`](../tests/mcp.rs).
const OBSERVE: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
    "prompts/get",
    // `roots/list` alimente le maillon 2 de la chaîne de provenance de scope, et
    // sa notification de changement l'invalide. Le shim ne les émet pas, il les
    // voit passer — d'où `Observe` et pas `Passthrough`.
    "roots/list",
    "notifications/roots/list_changed",
];

pub fn disposition(method: &str) -> Disposition {
    if DECIDE.contains(&method) {
        Disposition::Decide
    } else if OBSERVE.contains(&method) {
        Disposition::Observe
    } else {
        Disposition::Passthrough
    }
}

/// Classe une frame à partir de son scan.
pub fn classify(scan: &MethodScan) -> Disposition {
    match scan {
        MethodScan::Found { method, .. } => disposition(method),
        // Une réponse ne porte pas de méthode ; elle est corrélée par `id` en
        // amont, pas classée ici.
        MethodScan::NoMethod => Disposition::Passthrough,
        // On ne décide jamais sur une frame qu'on n'a pas comprise, et on ne la
        // laisse pas filer sans trace non plus.
        MethodScan::Unparsable => Disposition::Observe,
    }
}

// ---------------------------------------------------------------------------
// Point de décision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Le shim répondra par un `result` valide avec `isError: true`. Jamais une
    /// erreur de protocole, jamais une fermeture de connexion.
    Deny {
        rule: String,
        message: String,
    },
}

/// Ce qu'on présente au point de décision.
#[derive(Debug, Clone)]
pub struct CallContext<'a> {
    pub method: &'a str,
    /// Frame brute. En M1 le daemon la parsera pour évaluer la politique sur le
    /// contenu des arguments.
    pub frame: &'a [u8],
}

/// En M0 l'unique implémentation est [`AllowAll`]. En M1 c'est le client du
/// socket Unix qui l'implémente.
///
/// **Faillible exprès.** Un client de socket doit pouvoir dire « je n'ai pas pu
/// joindre le daemon » sans avoir à mentir `Allow` ni à paniquer. L'appelant
/// traite tout `Err` comme un `Allow` journalisé : c'est la règle de
/// disponibilité §4 appliquée au code de mcpwall lui-même. Sans ce `Result`, le
/// seul recours en M1 serait un `unwrap` déguisé dans le chemin du shim.
pub trait DecisionPoint: Send + Sync {
    fn decide(&self, ctx: &CallContext<'_>) -> Result<Verdict, DecisionError>;
}

/// Le point de décision n'a pas pu se prononcer. Jamais fatal.
#[derive(Debug, Clone)]
pub struct DecisionError {
    pub reason: String,
    /// La politique demande-t-elle de fermer en cas de panne ? Renseigné par le
    /// client du daemon à partir de `fail_closed`, faute de quoi l'appelant
    /// laisse passer.
    pub fail_closed: bool,
}

impl DecisionError {
    pub fn open(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            fail_closed: false,
        }
    }
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

/// M0 : observation seule.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl DecisionPoint for AllowAll {
    fn decide(&self, _ctx: &CallContext<'_>) -> Result<Verdict, DecisionError> {
        Ok(Verdict::Allow)
    }
}

/// Fabrique la réponse à renvoyer au client quand un appel est bloqué.
///
/// Forme imposée par la §5 de la spec projet : jamais une erreur JSON-RPC de
/// protocole, jamais une fermeture de connexion. Un `result` valide portant
/// `isError: true`, que l'agent lit comme un échec d'outil ordinaire, auquel il
/// s'adapte, et après lequel il continue.
///
/// Rend `None` si la frame bloquée n'a pas d'`id` : c'est une notification, elle
/// n'attend aucune réponse et il n'y a rien à renvoyer. La frame est simplement
/// jetée.
///
/// La sortie est terminée par `\n` : c'est une frame prête à écrire.
pub fn deny_response(frame: &[u8], rule: &str, message: &str) -> Option<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let id = v.get("id")?;
    if id.is_null() {
        return None;
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "isError": true,
            "content": [{
                "type": "text",
                "text": format!("blocked by mcpwall: {message} (rule: {rule})"),
            }],
        },
    });

    let mut out = serde_json::to_vec(&body).ok()?;
    out.push(b'\n');
    Some(out)
}

// ---------------------------------------------------------------------------
// Capture de l'`initialize`
// ---------------------------------------------------------------------------

/// Ce qu'on retient de la requête `initialize` du client.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    /// Version **demandée**. La version retenue est celle de [`ServerHello`].
    pub requested_protocol_version: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    /// Le client annonce-t-il la capacité `roots` ? Détermine si le maillon 2 de
    /// la chaîne de provenance de scope a une chance d'être alimenté.
    pub supports_roots: bool,
    pub roots_list_changed: bool,
}

/// Ce qu'on retient de la réponse `initialize` du serveur.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerHello {
    /// Version **négociée**. C'est ce champ qu'on stocke : la spec veut que le
    /// serveur réponde avec la version retenue, qui peut différer de celle que
    /// le client a demandée.
    pub protocol_version: Option<String>,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
    /// Clés de premier niveau de `capabilities`, triées. Suffit au journal sans
    /// stocker l'objet entier.
    pub capabilities: Vec<String>,
}

pub fn parse_client_hello(frame: &[u8]) -> Option<ClientHello> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let params = v.get("params")?;
    let roots = params.get("capabilities").and_then(|c| c.get("roots"));

    Some(ClientHello {
        requested_protocol_version: str_at(params, "protocolVersion"),
        client_name: params.get("clientInfo").and_then(|i| str_at(i, "name")),
        client_version: params.get("clientInfo").and_then(|i| str_at(i, "version")),
        supports_roots: roots.is_some(),
        roots_list_changed: roots
            .and_then(|r| r.get("listChanged"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

pub fn parse_server_hello(frame: &[u8]) -> Option<ServerHello> {
    let v: serde_json::Value = serde_json::from_slice(frame).ok()?;
    let result = v.get("result")?;

    let mut capabilities: Vec<String> = result
        .get("capabilities")
        .and_then(serde_json::Value::as_object)
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    capabilities.sort();

    Some(ServerHello {
        protocol_version: str_at(result, "protocolVersion"),
        server_name: result.get("serverInfo").and_then(|i| str_at(i, "name")),
        server_version: result.get("serverInfo").and_then(|i| str_at(i, "version")),
        capabilities,
    })
}

fn str_at(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_owned)
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Passthrough => "passthrough",
            Self::Observe => "observe",
            Self::Decide => "decide",
        })
    }
}

//! Résolution du projet auquel rattacher une session.
//!
//! Le scoping par projet n'est pas un confort d'affichage : c'est lui qui
//! empêche un « toujours autoriser » accordé dans un dépôt de s'appliquer à un
//! autre. Un scope faux est une fuite de permission silencieuse. D'où deux
//! principes tenus dans tout ce module :
//!
//! 1. **On ne devine jamais.** L'absence de signal donne [`ScopeSource::Unknown`],
//!    pas une valeur plausible.
//! 2. **La provenance voyage avec la valeur.** [`Scope`] transporte toujours son
//!    [`ScopeSource`], parce que la portée `forever` n'est offerte qu'aux
//!    provenances fiables — voir [`Scope::allows_forever`].
//!
//! Deux couches, séparées exprès : la résolution de précédence est pure et
//! testable sans système de fichiers ; la canonicalisation, qui touche le
//! disque, tient dans [`canonicalize_for_scope`].

use std::path::{Path, PathBuf};

/// Séparateur interne des chemins dans une clé de scope.
///
/// `\u{1f}` (unit separator) n'apparaît pas dans un chemin réel. Pour le cas
/// courant — une seule racine — la clé se lit exactement comme dans la spec :
/// `project:/Users/marc/monrepo`.
const KEY_SEP: char = '\u{1f}';

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// D'où vient le chemin de projet, par ordre de fiabilité décroissante.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeSource {
    /// 1 — `--project` écrit par `mcpwall init` dans la commande enveloppée.
    ///
    /// Le signal le plus fort : au moment où `init` réécrit `~/monrepo/.mcp.json`,
    /// il sait de quel projet il s'agit. Déterministe, identique sur tous les
    /// clients, indépendant du protocole.
    Injected,
    /// 2 — racines observées passivement dans une réponse à `roots/list`.
    ///
    /// Sémantiquement juste, mais optionnel : le shim ne reçoit rien, il voit
    /// passer — et seulement si un serveur amont pense à demander.
    Roots,
    /// 3 — répertoire de travail hérité, canonicalisé.
    ///
    /// Sa sémantique change selon le client : correct depuis Claude Code, sans
    /// rapport avec un projet depuis Claude Desktop. Utilisable pour regrouper
    /// et afficher, pas pour accorder une permission permanente.
    Cwd,
    /// 4 — aucun signal. Sentinelle explicite.
    Unknown,
}

impl ScopeSource {
    /// Rang de précédence, 1 étant le plus fiable.
    pub fn rank(self) -> u8 {
        match self {
            Self::Injected => 1,
            Self::Roots => 2,
            Self::Cwd => 3,
            Self::Unknown => 4,
        }
    }

    /// Étiquette stable pour le journal et les overrides. Ne jamais la changer
    /// sans migration : elle est persistée.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Injected => "injected",
            Self::Roots => "roots",
            Self::Cwd => "cwd",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ScopeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Un projet résolu, avec sa provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    source: ScopeSource,
    /// Trié et dédupliqué. Un monorepo peut légitimement exposer plusieurs
    /// racines ; le scope est l'ensemble, pas la première.
    paths: Vec<PathBuf>,
}

impl Scope {
    /// Construit un scope à partir de chemins **déjà canonicalisés**.
    ///
    /// Rend [`Scope::unknown`] si la liste est vide après normalisation : une
    /// provenance sans chemin n'est pas une provenance.
    pub fn new(source: ScopeSource, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut paths: Vec<PathBuf> = paths.into_iter().collect();
        paths.sort();
        paths.dedup();

        if paths.is_empty() || source == ScopeSource::Unknown {
            return Self::unknown();
        }
        Self { source, paths }
    }

    pub fn unknown() -> Self {
        Self {
            source: ScopeSource::Unknown,
            paths: Vec::new(),
        }
    }

    pub fn source(&self) -> ScopeSource {
        self.source
    }

    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Clé de scoping persistée dans le journal et les overrides.
    ///
    /// Deux scopes de provenances différentes mais de mêmes chemins donnent la
    /// même clé : c'est voulu. Une session qui démarre en `cwd` puis se voit
    /// confirmer par `roots` doit retomber sur les mêmes règles, pas en créer un
    /// jeu parallèle. La provenance est stockée à côté, pour la décision
    /// `forever`, pas dans la clé.
    pub fn key(&self) -> String {
        if self.paths.is_empty() {
            return "unknown".to_owned();
        }
        let joined: Vec<String> = self
            .paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        format!("project:{}", joined.join(&KEY_SEP.to_string()))
    }

    /// Rendu lisible pour l'UI et `mcpwall log`.
    pub fn display(&self) -> String {
        if self.paths.is_empty() {
            return "projet inconnu".to_owned();
        }
        let joined: Vec<String> = self
            .paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        joined.join(", ")
    }

    /// La portée `forever` est-elle offrable pour ce scope ?
    ///
    /// Seulement en provenance [`Injected`](ScopeSource::Injected) ou
    /// [`Roots`](ScopeSource::Roots). En `cwd`, la sémantique du chemin dépend
    /// du client qui a lancé le shim ; accorder une permission permanente sur
    /// cette base la ferait fuir vers d'autres projets. L'UI n'offre alors que
    /// `once` et `session`.
    pub fn allows_forever(&self) -> bool {
        matches!(self.source, ScopeSource::Injected | ScopeSource::Roots)
    }
}

// ---------------------------------------------------------------------------
// Chaîne de précédence
// ---------------------------------------------------------------------------

/// Accumule les signaux de scope et rend le meilleur disponible.
///
/// Les signaux n'arrivent pas en même temps : `--project` et le cwd sont connus
/// au démarrage, les racines seulement si un serveur amont demande `roots/list`
/// en cours de session. Le scope peut donc **monter** en fiabilité en cours de
/// route. Chaque entrée de journal fige la provenance du moment ; on ne réécrit
/// pas le passé.
#[derive(Debug, Default, Clone)]
pub struct ScopeResolver {
    injected: Option<PathBuf>,
    roots: Vec<PathBuf>,
    cwd: Option<PathBuf>,
}

impl ScopeResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Maillon 1. Chemin déjà canonicalisé.
    pub fn set_injected(&mut self, path: PathBuf) {
        self.injected = Some(path);
    }

    /// Maillon 3. Chemin déjà canonicalisé.
    pub fn set_cwd(&mut self, path: PathBuf) {
        self.cwd = Some(path);
    }

    /// Maillon 2. **Remplace** l'ensemble courant.
    ///
    /// `notifications/roots/list_changed` signifie que la liste précédente n'est
    /// plus valide. Fusionner ferait grossir le scope indéfiniment et lui ferait
    /// couvrir des répertoires que le client n'expose plus.
    pub fn observe_roots(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        self.roots = paths.into_iter().collect();
    }

    /// Rend le meilleur scope disponible.
    pub fn resolve(&self) -> Scope {
        if let Some(p) = &self.injected {
            return Scope::new(ScopeSource::Injected, [p.clone()]);
        }
        if !self.roots.is_empty() {
            return Scope::new(ScopeSource::Roots, self.roots.clone());
        }
        if let Some(p) = &self.cwd {
            return Scope::new(ScopeSource::Cwd, [p.clone()]);
        }
        Scope::unknown()
    }
}

// ---------------------------------------------------------------------------
// URI de racine
// ---------------------------------------------------------------------------

/// Convertit l'`uri` d'une racine MCP en chemin.
///
/// La spec (révision 2025-11-25, `client/roots`) : « This **MUST** be a `file://`
/// URI in the current specification ». Tout autre schéma est ignoré plutôt que
/// rapproché de force d'un chemin — une racine qu'on ne comprend pas ne doit pas
/// devenir une clé de permission.
///
/// Le chemin rendu n'est pas canonicalisé : c'est [`canonicalize_for_scope`] qui
/// s'en charge, pour garder cette fonction pure.
pub fn parse_root_uri(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://").or_else(|| {
        // Le schéma est insensible à la casse.
        let (scheme, rest) = uri.split_once("://")?;
        scheme.eq_ignore_ascii_case("file").then_some(rest)
    })?;

    // On coupe requête et fragment : ils n'ont pas de sens pour un chemin.
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);

    // `file:///chemin` (autorité vide) ou `file://localhost/chemin`.
    let path = if let Some(p) = rest.strip_prefix('/') {
        // L'autorité était vide : `rest` commence directement par le chemin.
        format!("/{p}")
    } else {
        let (authority, p) = rest.split_once('/')?;
        if !authority.eq_ignore_ascii_case("localhost") {
            // Une racine sur un hôte distant n'est pas un chemin local.
            return None;
        }
        format!("/{p}")
    };

    let decoded = percent_decode(&path)?;
    let decoded = String::from_utf8(decoded).ok()?;

    if decoded.contains('\0') {
        return None;
    }

    // Une barre finale ne change pas le répertoire désigné, mais changerait la
    // clé de scope. On normalise, sans toucher à la racine `/`.
    let trimmed = decoded.trim_end_matches('/');
    let path = if trimmed.is_empty() { "/" } else { trimmed };

    Some(PathBuf::from(path))
}

/// Décode les séquences `%XX`. Rend `None` si l'une d'elles est malformée —
/// on préfère ignorer une racine à en fabriquer un chemin approximatif.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = *bytes.get(i + 1)?;
            let lo = *bytes.get(i + 2)?;
            let hi = (hi as char).to_digit(16)?;
            let lo = (lo as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Couche disque
// ---------------------------------------------------------------------------

/// Canonicalise un chemin destiné à devenir une clé de scope.
///
/// Résout liens symboliques et `..`. Sans ça, `/tmp` et `/private/tmp` sur macOS
/// donnent deux clés distinctes pour le même répertoire, et les overrides d'une
/// session ne se retrouvent pas à la suivante.
///
/// En cas d'échec — chemin inexistant, permission refusée — on rend le chemin
/// d'origine tel quel. Perdre la canonicalisation dégrade la qualité du
/// regroupement ; refuser de démarrer casserait la session de l'agent, ce qui
/// est le mauvais côté de l'arbitrage.
pub fn canonicalize_for_scope(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

//! Moteur de politique.
//!
//! Déterministe et lisible : aucune analyse par LLM, aucune heuristique
//! opaque. Une règle qui déclenche doit pouvoir être expliquée à l'utilisateur
//! en une phrase, sans quoi il ne peut pas décider.
//!
//! Deux principes de conception, tous deux dictés par la fatigue d'alerte :
//!
//! - **Première règle qui matche, dans l'ordre du fichier.** Pas de score, pas
//!   de combinaison. L'utilisateur doit pouvoir prédire ce qui va se passer en
//!   lisant son fichier de haut en bas.
//! - **Un faux positif coûte plus cher qu'un faux négatif.** Une règle qui
//!   interrompt à tort forme l'utilisateur à cliquer « autoriser » sans lire,
//!   ce qui annule le produit entier.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;

use crate::scope::Scope;

// ---------------------------------------------------------------------------
// Modèle du fichier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Allow,
    Ask,
    Deny,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Portée d'un override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Until {
    #[default]
    Once,
    Session,
    Forever,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct When {
    /// Motifs glob sur les chemins trouvés dans les arguments.
    #[serde(default)]
    pub arg_path_matches: Vec<String>,
    /// Motifs glob sur le nom de l'outil.
    #[serde(default)]
    pub tool_matches: Vec<String>,
    /// Un chemin d'argument sort-il du projet ?
    #[serde(default)]
    pub path_outside_cwd: bool,
    /// Un argument ressemble-t-il à un secret ?
    #[serde(default)]
    pub arg_matches_secret: bool,
    /// Un argument contient-il des données locales marquées. **M3.**
    #[serde(default)]
    pub arg_contains_tainted: bool,
    /// L'outil est-il considéré comme sortant ? **M3.**
    #[serde(default)]
    pub tool_is_outbound: bool,
    /// La description de l'outil a-t-elle changé ? **M3.**
    #[serde(default)]
    pub tool_description_drift: bool,
    /// Méthodes MCP concernées. Vide = toutes celles de l'ensemble DECIDE.
    #[serde(default)]
    pub method_matches: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub when: When,
    pub action: Action,
    #[serde(default)]
    pub severity: Severity,
    /// Explication montrée à l'utilisateur. À défaut, l'`id` sert de message.
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// Clé de scope, telle que produite par [`Scope::key`].
    pub scope: String,
    /// Nom d'outil, motif glob accepté.
    pub tool: String,
    pub action: Action,
    #[serde(default)]
    pub until: Until,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    #[serde(default)]
    pub default: Action,
    /// Bloquer quand le daemon est injoignable. **Faux par défaut, et ce défaut
    /// est un choix produit** : si fermer l'app casse tous les serveurs MCP de
    /// l'utilisateur, mcpwall est désinstallé dans l'heure.
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default = "default_ask_timeout")]
    pub ask_timeout_seconds: u64,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub overrides: Vec<Override>,
}

fn default_ask_timeout() -> u64 {
    60
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            default: Action::Allow,
            fail_closed: false,
            ask_timeout_seconds: default_ask_timeout(),
            rules: Vec::new(),
            overrides: Vec::new(),
        }
    }
}

/// Politique par défaut, écrite au premier lancement.
///
/// Volontairement courte et entièrement en `ask` : au repos mcpwall ne doit
/// rien demander, et seules les règles à haute confiance interrompent.
pub const DEFAULT_POLICY_YAML: &str = r#"# Politique mcpwall.
# Première règle qui correspond, dans l'ordre de lecture.

default: allow
fail_closed: false
ask_timeout_seconds: 60

rules:
  # Lecture d'un secret local. Haute confiance : ces chemins ne sont pas lus
  # par accident.
  - id: secrets_paths
    when:
      arg_path_matches:
        - "**/.env"
        - "**/.env.*"
        - "~/.ssh/**"
        - "~/.aws/**"
        - "**/id_rsa"
        - "**/id_ed25519"
        - "**/.netrc"
    action: ask
    severity: high
    message: "accès à un fichier de secrets"

  # Un secret repéré dans les arguments d'un appel.
  - id: secret_pattern
    when:
      arg_matches_secret: true
    action: ask
    severity: high
    message: "un argument ressemble à un identifiant secret"

  # Écriture hors du projet courant.
  - id: outside_project_write
    when:
      tool_matches: ["*write*", "*edit*", "*delete*", "*remove*", "*move*"]
      path_outside_cwd: true
    action: ask
    severity: medium
    message: "écriture en dehors du projet"

  # M3 : nécessite le suivi de teinte, inactif pour l'instant.
  - id: taint_exfil
    when:
      arg_contains_tainted: true
      tool_is_outbound: true
    action: deny
    severity: critical
    message: "donnée locale marquée dans un argument sortant"

  # M3 : nécessite la détection de dérive des descriptions.
  - id: tool_description_changed
    when:
      tool_description_drift: true
    action: ask
    severity: high
    message: "la description de cet outil a changé depuis la dernière session"

overrides: []
"#;

// ---------------------------------------------------------------------------
// Politique compilée
// ---------------------------------------------------------------------------

/// Une règle avec ses globs compilés.
struct CompiledRule {
    rule: Rule,
    arg_paths: Option<GlobSet>,
    tools: Option<GlobSet>,
    methods: Option<GlobSet>,
}

pub struct Policy {
    file: PolicyFile,
    rules: Vec<CompiledRule>,
    overrides: Vec<(Override, Option<GlobSet>)>,
    /// Date du fichier au chargement, pour le rechargement à chaud.
    loaded_mtime: Option<SystemTime>,
    path: Option<PathBuf>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::compile(PolicyFile::default(), None, None)
    }
}

impl Policy {
    pub fn parse(text: &str) -> Result<PolicyFile> {
        // Un fichier vide se désérialiserait en « tout par défaut », c'est-à-dire
        // en `default: allow` sans aucune règle : le pare-feu se désactiverait
        // en silence. Ça n'arrive pas qu'en théorie — disque plein, éditeur
        // interrompu, écriture partielle. On refuse, et l'appelant conserve la
        // politique précédente.
        if text.trim().is_empty() {
            anyhow::bail!(
                "politique vide — refusée pour ne pas désactiver le filtrage sans le dire"
            );
        }
        serde_norway::from_str(text).context("politique illisible")
    }

    /// Charge depuis un fichier, en l'écrivant s'il n'existe pas.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, DEFAULT_POLICY_YAML)
                .with_context(|| format!("écriture de {}", path.display()))?;
        }
        Self::load(path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("lecture de {}", path.display()))?;
        let file = Self::parse(&text)?;
        let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
        Ok(Self::compile(file, Some(path.to_path_buf()), mtime))
    }

    fn compile(file: PolicyFile, path: Option<PathBuf>, mtime: Option<SystemTime>) -> Self {
        let rules = file
            .rules
            .iter()
            .map(|r| CompiledRule {
                rule: r.clone(),
                arg_paths: build_globs(&r.when.arg_path_matches),
                tools: build_globs(&r.when.tool_matches),
                methods: build_globs(&r.when.method_matches),
            })
            .collect();

        let overrides = file
            .overrides
            .iter()
            .map(|o| (o.clone(), build_globs(std::slice::from_ref(&o.tool))))
            .collect();

        Self {
            file,
            rules,
            overrides,
            loaded_mtime: mtime,
            path,
        }
    }

    /// Recharge si le fichier a changé.
    ///
    /// Comparaison de date plutôt que surveillance du système de fichiers : un
    /// `stat` coûte moins qu'un observateur, et le rechargement n'a pas besoin
    /// d'être instantané.
    pub fn reload_if_changed(&mut self) -> bool {
        let Some(path) = self.path.clone() else {
            return false;
        };
        let mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        if mtime == self.loaded_mtime {
            return false;
        }
        match Self::load(&path) {
            Ok(fresh) => {
                *self = fresh;
                tracing::info!(fichier = %path.display(), "politique rechargée");
                true
            }
            Err(e) => {
                // On garde l'ancienne politique : un fichier à moitié édité ne
                // doit pas ouvrir le pare-feu en grand ni le fermer d'un coup.
                tracing::error!(erreur = %e, "politique invalide, l'ancienne reste active");
                self.loaded_mtime = mtime;
                false
            }
        }
    }

    pub fn fail_closed(&self) -> bool {
        self.file.fail_closed
    }

    pub fn ask_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.file.ask_timeout_seconds)
    }

    pub fn default_action(&self) -> Action {
        self.file.default
    }

    /// Évalue une requête.
    pub fn evaluate(&self, req: &Request<'_>) -> Decision {
        // Les overrides passent avant les règles : ils traduisent une décision
        // déjà prise par l'utilisateur, qu'on ne lui redemande pas.
        for (ov, tools) in &self.overrides {
            if ov.scope != req.scope_key {
                continue;
            }
            let matches = tools
                .as_ref()
                .map(|g| g.is_match(req.tool.unwrap_or("")))
                .unwrap_or(false);
            if matches {
                return Decision {
                    action: ov.action,
                    rule: Some("override".to_owned()),
                    severity: Severity::Info,
                    message: format!("décision enregistrée pour {}", ov.scope),
                    findings: Vec::new(),
                };
            }
        }

        let findings = collect_findings(req);

        for c in &self.rules {
            if let Some(d) = self.try_rule(c, req, &findings) {
                return d;
            }
        }

        Decision {
            action: self.file.default,
            rule: None,
            severity: Severity::Info,
            message: "politique par défaut".to_owned(),
            findings,
        }
    }

    fn try_rule(
        &self,
        c: &CompiledRule,
        req: &Request<'_>,
        findings: &[Finding],
    ) -> Option<Decision> {
        let w = &c.rule.when;

        // Une règle dont toutes les conditions sont vides ne matche rien : sinon
        // une faute de frappe dans un nom de condition bloquerait tout le
        // trafic. `deny_unknown_fields` attrape déjà la faute, ceci est la
        // seconde barrière.
        if is_empty_condition(w) {
            return None;
        }

        if let Some(g) = &c.methods
            && !g.is_match(req.method)
        {
            return None;
        }

        if let Some(g) = &c.tools {
            let tool = req.tool?;
            if !g.is_match(tool) {
                return None;
            }
        }

        if let Some(g) = &c.arg_paths {
            let hit = req
                .paths
                .iter()
                .any(|p| g.is_match(p) || g.is_match(expand_tilde_str(p)));
            if !hit {
                return None;
            }
        }

        if w.path_outside_cwd && !req.has_path_outside_scope() {
            return None;
        }

        if w.arg_matches_secret && !findings.iter().any(|f| matches!(f, Finding::Secret { .. })) {
            return None;
        }

        // M3. Tant que le suivi de teinte n'existe pas, ces conditions ne sont
        // jamais vraies — et une règle qui les porte ne déclenche donc jamais.
        // C'est volontaire : mieux vaut une règle inerte et visible dans le
        // fichier qu'une règle absente qu'on oublierait d'écrire.
        if w.arg_contains_tainted || w.tool_is_outbound || w.tool_description_drift {
            return None;
        }

        Some(Decision {
            action: c.rule.action,
            rule: Some(c.rule.id.clone()),
            severity: c.rule.severity,
            message: c
                .rule
                .message
                .clone()
                .unwrap_or_else(|| c.rule.id.replace('_', " ")),
            findings: findings.to_vec(),
        })
    }
}

fn is_empty_condition(w: &When) -> bool {
    w.arg_path_matches.is_empty()
        && w.tool_matches.is_empty()
        && w.method_matches.is_empty()
        && !w.path_outside_cwd
        && !w.arg_matches_secret
        && !w.arg_contains_tainted
        && !w.tool_is_outbound
        && !w.tool_description_drift
}

fn build_globs(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        // `~` est développé pour que la politique reste lisible ; les deux
        // formes sont ajoutées, l'argument pouvant arriver sous l'une ou
        // l'autre.
        if let Ok(g) = Glob::new(p) {
            b.add(g);
        }
        if let Some(expanded) = expand_tilde(p)
            && let Ok(g) = Glob::new(&expanded)
        {
            b.add(g);
        }
    }
    b.build().ok()
}

fn expand_tilde(p: &str) -> Option<String> {
    let rest = p.strip_prefix("~/")?;
    Some(format!(
        "{}/{rest}",
        crate::journal::home_dir().to_string_lossy()
    ))
}

fn expand_tilde_str(p: &str) -> &str {
    p
}

// ---------------------------------------------------------------------------
// Requête et décision
// ---------------------------------------------------------------------------

/// Ce qu'on soumet au moteur.
pub struct Request<'a> {
    pub method: &'a str,
    /// Nom de l'outil, pour `tools/call`.
    pub tool: Option<&'a str>,
    /// Chemins repérés dans les arguments.
    pub paths: Vec<String>,
    /// Valeurs textuelles des arguments, pour la détection de secrets.
    pub values: Vec<String>,
    pub scope_key: &'a str,
    pub scope_paths: &'a [PathBuf],
}

impl Request<'_> {
    /// Un chemin d'argument sort-il du projet ?
    ///
    /// Un scope inconnu ne rend jamais vrai : sans savoir où est le projet, on
    /// ne peut pas dire qu'on en sort, et prétendre le contraire ferait
    /// déclencher la règle sur tout le trafic de Claude Desktop.
    fn has_path_outside_scope(&self) -> bool {
        if self.scope_paths.is_empty() {
            return false;
        }
        self.paths.iter().any(|p| {
            let abs = PathBuf::from(p);
            if !abs.is_absolute() {
                return false; // relatif au cwd du serveur : hors de notre portée
            }
            !self.scope_paths.iter().any(|root| abs.starts_with(root))
        })
    }
}

/// Extrait ce qui est évaluable d'un `tools/call` ou d'un `resources/read`.
pub fn request_from_frame<'a>(
    method: &'a str,
    frame: &[u8],
    scope: &'a Scope,
    tool_buf: &'a mut String,
) -> Request<'a> {
    let mut paths = Vec::new();
    let mut values = Vec::new();

    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(frame)
        && let Some(params) = v.get("params")
    {
        if let Some(name) = params.get("name").and_then(|n| n.as_str()) {
            tool_buf.push_str(name);
        }
        // `resources/read` porte son chemin dans `uri`.
        if let Some(uri) = params.get("uri").and_then(|u| u.as_str()) {
            if let Some(p) = crate::scope::parse_root_uri(uri) {
                paths.push(p.to_string_lossy().into_owned());
            }
            values.push(uri.to_owned());
        }
        walk(params, &mut paths, &mut values, 0);
    }

    Request {
        method,
        tool: (!tool_buf.is_empty()).then_some(tool_buf.as_str()),
        paths,
        values,
        scope_key: "",
        scope_paths: scope.paths(),
    }
}

/// Parcourt les arguments en collectant chaînes et chemins.
fn walk(v: &serde_json::Value, paths: &mut Vec<String>, values: &mut Vec<String>, depth: u8) {
    // Une profondeur bornée évite qu'un argument profondément imbriqué coûte du
    // temps dans le chemin critique.
    if depth > 8 {
        return;
    }
    match v {
        serde_json::Value::String(s) => {
            if looks_like_path(s) {
                paths.push(s.clone());
            }
            values.push(s.clone());
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, paths, values, depth + 1)),
        serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, paths, values, depth + 1)),
        _ => {}
    }
}

fn looks_like_path(s: &str) -> bool {
    (s.starts_with('/') || s.starts_with("~/") || s.starts_with("./") || s.starts_with("../"))
        && !s.contains('\n')
        && s.len() < 4096
}

/// Ce que le moteur a repéré dans les arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Un secret probable. **On ne stocke jamais la valeur** — seulement son
    /// type et un préfixe tronqué, conformément aux conventions du projet.
    Secret { kind: &'static str, prefix: String },
}

impl Finding {
    pub fn describe(&self) -> String {
        match self {
            Self::Secret { kind, prefix } => format!("{kind} ({prefix}…)"),
        }
    }
}

fn collect_findings(req: &Request<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for v in &req.values {
        if let Some(f) = detect_secret(v)
            && !out.contains(&f)
        {
            out.push(f);
        }
    }
    out
}

/// Détecteurs de secrets, délibérément peu nombreux et à forte confiance.
///
/// Chaque motif ajouté ici est une source potentielle de faux positifs, et un
/// faux positif bruyant coûte plus cher qu'un faux négatif : il apprend à
/// l'utilisateur à cliquer « autoriser » sans lire.
fn detect_secret(s: &str) -> Option<Finding> {
    let kind = if s.contains("-----BEGIN") && s.contains("PRIVATE KEY") {
        "clé privée"
    } else if starts_with_aws_key(s) {
        "clé d'accès AWS"
    } else if (s.starts_with("ghp_") && s.len() >= 36)
        || (s.starts_with("github_pat_") && s.len() >= 40)
    {
        // Deux préfixes, un seul type : les longueurs minimales diffèrent parce
        // que les formats diffèrent, pas la nature du secret.
        "jeton GitHub"
    } else if s.starts_with("sk-") && s.len() >= 20 {
        "clé d'API"
    } else if s.starts_with("xoxb-") || s.starts_with("xoxp-") {
        "jeton Slack"
    } else {
        return None;
    };

    Some(Finding::Secret {
        kind,
        prefix: prefix(s),
    })
}

fn starts_with_aws_key(s: &str) -> bool {
    // AKIA suivi de 16 caractères alphanumériques majuscules.
    let Some(rest) = s.strip_prefix("AKIA") else {
        return false;
    };
    rest.len() >= 16
        && rest[..16]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Préfixe tronqué, sûr à écrire en journal.
fn prefix(s: &str) -> String {
    s.chars().take(6).collect()
}

/// Ajoute un override permanent au fichier de politique.
///
/// Écriture par ajout textuel plutôt que par réécriture du document : un
/// `policy.yaml` est un fichier que l'utilisateur édite à la main, avec ses
/// commentaires et son ordre de règles. Le relire, le sérialiser et le
/// réécrire lui ferait perdre les deux — et la première fois que mcpwall
/// détruit les commentaires de quelqu'un, il perd sa confiance.
pub fn append_override(path: &Path, scope_key: &str, tool: &str, allow: bool) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("lecture de {}", path.display()))?;

    // On valide avant d'écrire : mieux vaut refuser d'enregistrer une décision
    // que de produire un fichier que le daemon ne saura plus relire.
    Policy::parse(&text).context("politique existante illisible, override non ajouté")?;

    let action = if allow { "allow" } else { "deny" };
    let entry = format!(
        "  - scope: \"{}\"\n    tool: \"{}\"\n    action: {action}\n    until: forever\n",
        scope_key.replace('"', "\\\""),
        tool.replace('"', "\\\"")
    );

    let mut updated = if text.contains("\noverrides:") || text.starts_with("overrides:") {
        // `overrides: []` doit devenir une liste ouverte avant qu'on y ajoute.
        text.replace("overrides: []", "overrides:")
    } else {
        format!("{}\noverrides:\n", text.trim_end())
    };

    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&entry);

    // Relecture de contrôle : on n'écrit pas un fichier qu'on vient de casser.
    Policy::parse(&updated).context("l'ajout aurait produit une politique invalide")?;

    std::fs::write(path, updated).with_context(|| format!("écriture de {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub rule: Option<String>,
    pub severity: Severity,
    pub message: String,
    pub findings: Vec<Finding>,
}

impl Decision {
    /// Message destiné à l'agent, tel qu'il apparaîtra dans `isError`.
    pub fn agent_message(&self) -> String {
        if self.findings.is_empty() {
            return self.message.clone();
        }
        let details: Vec<String> = self.findings.iter().map(Finding::describe).collect();
        format!("{} [{}]", self.message, details.join(", "))
    }
}

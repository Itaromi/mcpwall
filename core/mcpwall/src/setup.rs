//! `mcpwall init` et `mcpwall restore`.
//!
//! L'onboarding est l'endroit où ce produit se gagne ou se perd. Trois règles
//! en découlent :
//!
//! 1. **Rien n'est écrit sans que le diff ait été montré.** Réécrire en silence
//!    la configuration d'un outil de travail est le meilleur moyen de perdre la
//!    confiance de quelqu'un du premier coup.
//! 2. **Toute écriture est réversible en une commande.** Chaque fichier touché
//!    est sauvegardé en `.bak.<timestamp>`, et `restore` les remet.
//! 3. **Les configurations pointent vers un lien symbolique stable**, jamais
//!    vers le chemin du bundle : déplacer l'app casserait sinon tous les
//!    serveurs MCP de l'utilisateur.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use crate::journal::home_dir;

/// Emplacement stable du binaire, vers lequel pointent toutes les configs.
pub fn shim_link() -> PathBuf {
    home_dir().join(".mcpwall").join("bin").join("mcpwall")
}

/// Crée ou rafraîchit le lien symbolique vers le binaire courant.
///
/// Appelé au premier lancement de l'app et par `init`. Le lien est refait à
/// chaque fois : c'est ce qui permet de déplacer l'app sans rien casser.
pub fn ensure_shim_link(target: &Path) -> Result<PathBuf> {
    let link = shim_link();
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(&link);

    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &link)
        .with_context(|| format!("lien {} -> {}", link.display(), target.display()))?;

    Ok(link)
}

/// Un fichier de configuration client qu'on sait manipuler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `~/.claude.json` — serveurs globaux et par projet.
    ClaudeGlobal,
    /// `.mcp.json` d'un projet.
    ProjectMcp,
    /// `~/.cursor/mcp.json`.
    Cursor,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ClaudeGlobal => "Claude Code (global)",
            Self::ProjectMcp => "projet",
            Self::Cursor => "Cursor",
        }
    }
}

#[derive(Debug)]
pub struct Target {
    pub path: PathBuf,
    pub kind: Kind,
    /// Projet auquel rattacher les serveurs de ce fichier.
    ///
    /// Renseigné pour un `.mcp.json` — le fichier vit dans le projet, donc on
    /// sait de quoi il s'agit. **Vide pour les fichiers globaux** : un serveur
    /// déclaré dans `~/.claude.json` est utilisé depuis n'importe quel projet,
    /// et lui coller un `--project` serait mentir sur la provenance.
    pub project: Option<PathBuf>,
}

/// Découvre les configurations existantes.
pub fn discover(extra_projects: &[PathBuf]) -> Vec<Target> {
    let mut out = Vec::new();
    let home = home_dir();

    let claude = home.join(".claude.json");
    if claude.exists() {
        out.push(Target {
            path: claude,
            kind: Kind::ClaudeGlobal,
            project: None,
        });
    }

    let cursor = home.join(".cursor").join("mcp.json");
    if cursor.exists() {
        out.push(Target {
            path: cursor,
            kind: Kind::Cursor,
            project: None,
        });
    }

    let mut projects: Vec<PathBuf> = extra_projects.to_vec();
    if let Ok(cwd) = std::env::current_dir() {
        projects.push(cwd);
    }
    for p in projects {
        let f = p.join(".mcp.json");
        if f.exists() && !out.iter().any(|t| t.path == f) {
            out.push(Target {
                path: f,
                kind: Kind::ProjectMcp,
                project: Some(crate::scope::canonicalize_for_scope(&p)),
            });
        }
    }
    out
}

/// Ce qu'`init` ferait à un fichier.
#[derive(Debug)]
pub struct Plan {
    pub path: PathBuf,
    pub kind: Kind,
    pub before: String,
    pub after: String,
    pub wrapped: Vec<String>,
    pub already: Vec<String>,
}

impl Plan {
    pub fn is_noop(&self) -> bool {
        self.wrapped.is_empty()
    }
}

/// Calcule la réécriture, sans rien écrire.
pub fn plan(target: &Target, shim: &Path) -> Result<Plan> {
    let before = std::fs::read_to_string(&target.path)
        .with_context(|| format!("lecture de {}", target.path.display()))?;
    let mut doc: Value = serde_json::from_str(&before)
        .with_context(|| format!("{} n'est pas du JSON valide", target.path.display()))?;

    let mut wrapped = Vec::new();
    let mut already = Vec::new();

    // `~/.claude.json` porte des serveurs à la racine *et* par projet. Les deux
    // emplacements sont traités successivement plutôt que collectés : deux
    // emprunts mutables simultanés sur le même document n'existeraient que pour
    // la commodité d'une boucle unique.
    //
    // La distinction compte pour le scope : sous `projects.<dir>`, on sait de
    // quel projet il s'agit et on peut injecter `--project` (rang 1). À la
    // racine, on ne sait pas — ce serveur est utilisé depuis n'importe où — et
    // lui inventer un projet serait mentir sur la provenance.
    if let Some(projects) = doc.get_mut("projects").and_then(Value::as_object_mut) {
        for (dir, entry) in projects.iter_mut() {
            let project = PathBuf::from(dir);
            let Some(map) = entry.get_mut("mcpServers").and_then(Value::as_object_mut) else {
                continue;
            };
            for (name, cfg) in map.iter_mut() {
                match wrap_entry(cfg, shim, Some(&project)) {
                    WrapResult::Wrapped => wrapped.push(name.clone()),
                    WrapResult::Already => already.push(name.clone()),
                    WrapResult::Skipped => {}
                }
            }
        }
    }

    if let Some(map) = doc.get_mut("mcpServers").and_then(Value::as_object_mut) {
        for (name, cfg) in map.iter_mut() {
            match wrap_entry(cfg, shim, target.project.as_deref()) {
                WrapResult::Wrapped => wrapped.push(name.clone()),
                WrapResult::Already => already.push(name.clone()),
                WrapResult::Skipped => {}
            }
        }
    }

    let after = serde_json::to_string_pretty(&doc)? + "\n";

    Ok(Plan {
        path: target.path.clone(),
        kind: target.kind,
        before,
        after,
        wrapped,
        already,
    })
}

enum WrapResult {
    Wrapped,
    Already,
    Skipped,
}

/// Enveloppe une entrée de serveur, en conservant `env`, `args` et le reste à
/// l'identique.
fn wrap_entry(cfg: &mut Value, shim: &Path, project: Option<&Path>) -> WrapResult {
    let Some(obj) = cfg.as_object_mut() else {
        return WrapResult::Skipped;
    };

    // Les serveurs HTTP/SSE n'ont pas de commande à envelopper : le transport
    // HTTP arrive en M3.
    let Some(command) = obj
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return WrapResult::Skipped;
    };

    let shim_str = shim.to_string_lossy().into_owned();
    if command == shim_str {
        return WrapResult::Already;
    }

    let old_args: Vec<Value> = obj
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut new_args: Vec<Value> = vec![Value::String("wrap".into())];
    if let Some(p) = project {
        new_args.push(Value::String("--project".into()));
        new_args.push(Value::String(p.to_string_lossy().into_owned()));
    }
    new_args.push(Value::String("--".into()));
    new_args.push(Value::String(command.clone()));
    new_args.extend(old_args.iter().cloned());

    // Trace de la commande d'origine : `restore` s'appuie sur les sauvegardes,
    // mais un humain qui lit le fichier doit pouvoir comprendre ce qui a été
    // fait sans les chercher.
    obj.insert(
        "x-mcpwall-original".into(),
        Value::Object(Map::from_iter([
            ("command".into(), Value::String(command)),
            ("args".into(), Value::Array(old_args)),
        ])),
    );
    obj.insert("command".into(), Value::String(shim_str));
    obj.insert("args".into(), Value::Array(new_args));

    WrapResult::Wrapped
}

/// Sauvegarde puis écrit.
pub fn apply(plan: &Plan) -> Result<PathBuf> {
    let backup = backup_path(&plan.path);
    std::fs::copy(&plan.path, &backup)
        .with_context(|| format!("sauvegarde vers {}", backup.display()))?;
    std::fs::write(&plan.path, &plan.after)
        .with_context(|| format!("écriture de {}", plan.path.display()))?;
    Ok(backup)
}

fn backup_path(path: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut p = path.as_os_str().to_owned();
    p.push(format!(".bak.{stamp}"));
    PathBuf::from(p)
}

/// Sauvegardes disponibles, la plus récente en premier pour chaque fichier.
pub fn backups() -> BTreeMap<PathBuf, Vec<PathBuf>> {
    let mut out: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    let home = home_dir();

    let mut dirs = vec![home.clone(), home.join(".cursor")];
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if let Some(idx) = name.find(".bak.") {
                let original = dir.join(&name[..idx]);
                out.entry(original).or_default().push(path);
            }
        }
    }

    for v in out.values_mut() {
        v.sort();
        v.reverse(); // la plus récente d'abord
    }
    out
}

/// Restaure chaque fichier depuis sa sauvegarde la plus récente.
pub fn restore() -> Result<Vec<PathBuf>> {
    let mut restored = Vec::new();
    for (original, saves) in backups() {
        let Some(latest) = saves.first() else {
            continue;
        };
        std::fs::copy(latest, &original)
            .with_context(|| format!("restauration de {}", original.display()))?;
        restored.push(original);
    }
    Ok(restored)
}

/// Diff unifié minimal, suffisant pour être lu avant d'accepter.
pub fn diff(before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();

    let mut out = String::new();
    let mut i = 0;
    let mut j = 0;

    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            i += 1;
            j += 1;
            continue;
        }
        // Cherche la prochaine resynchronisation. Fenêtre bornée : on affiche
        // un diff lisible, on n'implémente pas Myers.
        let mut resync = None;
        'outer: for da in 0..40usize {
            for db in 0..40usize {
                if i + da < a.len() && j + db < b.len() && a[i + da] == b[j + db] {
                    resync = Some((da, db));
                    break 'outer;
                }
            }
        }
        let (da, db) = resync.unwrap_or((a.len() - i, b.len() - j));
        for line in a.iter().skip(i).take(da) {
            out.push_str("- ");
            out.push_str(line);
            out.push('\n');
        }
        for line in b.iter().skip(j).take(db) {
            out.push_str("+ ");
            out.push_str(line);
            out.push('\n');
        }
        i += da;
        j += db;
    }
    out
}

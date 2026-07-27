//! Tests de l'onboarding.
//!
//! Ce module réécrit les fichiers de configuration d'outils dont les gens se
//! servent pour travailler. Une erreur ici ne provoque pas un bug, elle
//! provoque une désinstallation. Les tests portent donc autant sur ce qui est
//! **préservé** que sur ce qui est modifié.

use std::path::{Path, PathBuf};

use mcpwall::setup::{Kind, Plan, Target, diff, plan};
use serde_json::{Value, json};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mcpwall-setup-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("répertoire");
    d
}

fn write_config(dir: &Path, name: &str, v: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_string_pretty(v).expect("json")).expect("écriture");
    p
}

fn shim() -> PathBuf {
    PathBuf::from("/Users/x/.mcpwall/bin/mcpwall")
}

fn plan_for(path: &Path, kind: Kind, project: Option<PathBuf>) -> Plan {
    plan(
        &Target {
            path: path.to_path_buf(),
            kind,
            project,
        },
        &shim(),
    )
    .expect("plan")
}

fn parsed(plan: &Plan) -> Value {
    serde_json::from_str(&plan.after).expect("le résultat doit rester du JSON valide")
}

// --- Ce qui doit être préservé ---

#[test]
fn env_et_args_sont_conserves_a_lidentique() {
    // Perdre une variable d'environnement casse silencieusement un serveur, et
    // l'utilisateur accusera mcpwall — à juste titre.
    let dir = tmpdir("preserve");
    let cfg = json!({
        "mcpServers": {
            "postgres": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db"],
                "env": { "PGPASSWORD": "secret", "NODE_ENV": "production" },
                "disabled": false
            }
        }
    });
    let path = write_config(&dir, ".mcp.json", &cfg);

    let p = plan_for(
        &path,
        Kind::ProjectMcp,
        Some(PathBuf::from("/Users/x/projet")),
    );
    let after = parsed(&p);
    let entry = &after["mcpServers"]["postgres"];

    assert_eq!(entry["env"]["PGPASSWORD"], "secret", "env perdu");
    assert_eq!(entry["env"]["NODE_ENV"], "production");
    assert_eq!(entry["disabled"], false, "champ inconnu perdu");

    // La commande d'origine et ses arguments se retrouvent après `--`.
    let args: Vec<&str> = entry["args"]
        .as_array()
        .expect("args")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let sep = args.iter().position(|a| *a == "--").expect("séparateur --");
    assert_eq!(args[sep + 1], "npx");
    assert_eq!(
        &args[sep + 2..],
        [
            "-y",
            "@modelcontextprotocol/server-postgres",
            "postgresql://localhost/db"
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn la_commande_pointe_vers_le_lien_et_non_vers_le_bundle() {
    // Si les configs pointaient vers le chemin du bundle, déplacer l'app
    // casserait tous les serveurs MCP de l'utilisateur.
    let dir = tmpdir("lien");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": ["s.js"]}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    assert_eq!(
        parsed(&p)["mcpServers"]["fs"]["command"],
        shim().to_string_lossy().as_ref()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn la_commande_dorigine_reste_lisible_dans_le_fichier() {
    // `restore` s'appuie sur les sauvegardes, mais un humain qui ouvre le
    // fichier doit pouvoir comprendre ce qui a été fait sans les chercher.
    let dir = tmpdir("trace");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": ["s.js", "--flag"]}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    let orig = &parsed(&p)["mcpServers"]["fs"]["x-mcpwall-original"];
    assert_eq!(orig["command"], "node");
    assert_eq!(orig["args"][0], "s.js");
    assert_eq!(orig["args"][1], "--flag");

    let _ = std::fs::remove_dir_all(&dir);
}

// --- L'injection de --project ---

#[test]
fn un_mcp_json_de_projet_recoit_son_project() {
    // Maillon 1 de la chaîne de provenance : le fichier vit dans le projet,
    // donc `init` sait de quel projet il s'agit.
    let dir = tmpdir("projet");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": []}}}),
    );

    let p = plan_for(
        &path,
        Kind::ProjectMcp,
        Some(PathBuf::from("/Users/x/monrepo")),
    );
    let after = parsed(&p);
    let args: Vec<&str> = after["mcpServers"]["fs"]["args"]
        .as_array()
        .expect("args")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    let i = args
        .iter()
        .position(|a| *a == "--project")
        .expect("--project");
    assert_eq!(args[i + 1], "/Users/x/monrepo");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn un_serveur_global_ne_recoit_pas_de_project() {
    // Un serveur déclaré à la racine de `~/.claude.json` est utilisé depuis dix
    // projets différents. Lui coller un `--project` serait mentir sur la
    // provenance, et cette provenance décide de l'offre du `forever`.
    let dir = tmpdir("global");
    let path = write_config(
        &dir,
        ".claude.json",
        &json!({"mcpServers": {"github": {"command": "npx", "args": ["-y", "srv"]}}}),
    );

    let p = plan_for(&path, Kind::ClaudeGlobal, None);
    let after = parsed(&p);
    let args: Vec<&str> = after["mcpServers"]["github"]["args"]
        .as_array()
        .expect("args")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    assert!(
        !args.contains(&"--project"),
        "un serveur global ne doit pas se voir attribuer un projet : {args:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn les_serveurs_par_projet_de_claude_json_recoivent_le_bon_project() {
    // `~/.claude.json` porte aussi des serveurs sous `projects.<dir>`. Là, le
    // projet est connu.
    let dir = tmpdir("par-projet");
    let path = write_config(
        &dir,
        ".claude.json",
        &json!({
            "projects": {
                "/Users/x/repo-a": { "mcpServers": { "a": { "command": "node", "args": [] } } },
                "/Users/x/repo-b": { "mcpServers": { "b": { "command": "node", "args": [] } } }
            }
        }),
    );

    let p = plan_for(&path, Kind::ClaudeGlobal, None);
    let after = parsed(&p);

    for (repo, srv) in [("/Users/x/repo-a", "a"), ("/Users/x/repo-b", "b")] {
        let args: Vec<&str> = after["projects"][repo]["mcpServers"][srv]["args"]
            .as_array()
            .expect("args")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let i = args
            .iter()
            .position(|a| *a == "--project")
            .expect("--project");
        assert_eq!(args[i + 1], repo);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// --- Idempotence et cas limites ---

#[test]
fn appliquer_deux_fois_nenveloppe_pas_deux_fois() {
    // Relancer `init` est un réflexe. Une double enveloppe produirait un shim
    // qui lance un shim, avec deux journaux et deux fois la latence.
    let dir = tmpdir("idempotent");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": []}}}),
    );

    let first = plan_for(&path, Kind::ProjectMcp, None);
    assert_eq!(first.wrapped, vec!["fs"]);
    std::fs::write(&path, &first.after).expect("écriture");

    let second = plan_for(&path, Kind::ProjectMcp, None);
    assert!(
        second.wrapped.is_empty(),
        "réenveloppé : {:?}",
        second.wrapped
    );
    assert_eq!(second.already, vec!["fs"]);
    assert!(second.is_noop());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn un_serveur_http_est_ignore() {
    // Pas de `command` à envelopper : le transport HTTP arrive en M3, et on ne
    // prétend pas le couvrir en attendant.
    let dir = tmpdir("http");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"remote": {"type": "http", "url": "https://example.com/mcp"}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    assert!(p.wrapped.is_empty());
    assert_eq!(
        parsed(&p)["mcpServers"]["remote"]["url"],
        "https://example.com/mcp"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn un_fichier_sans_serveur_ne_produit_aucun_changement() {
    let dir = tmpdir("vide");
    let path = write_config(&dir, ".mcp.json", &json!({"autreChose": 1}));

    let p = plan_for(&path, Kind::ProjectMcp, None);
    assert!(p.is_noop());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn un_json_invalide_est_refuse_sans_ecraser() {
    let dir = tmpdir("invalide");
    let path = dir.join(".mcp.json");
    std::fs::write(&path, "{ ceci n'est pas du json").expect("écriture");

    let r = plan(
        &Target {
            path: path.clone(),
            kind: Kind::ProjectMcp,
            project: None,
        },
        &shim(),
    );
    assert!(
        r.is_err(),
        "un fichier illisible doit faire échouer le plan"
    );

    // Le fichier est intact.
    let after = std::fs::read_to_string(&path).expect("lecture");
    assert_eq!(after, "{ ceci n'est pas du json");

    let _ = std::fs::remove_dir_all(&dir);
}

// --- Le diff montré avant écriture ---

#[test]
fn le_diff_montre_ce_qui_change() {
    // Rien ne doit être écrit sans que l'utilisateur ait pu lire ce qui va lui
    // arriver.
    let dir = tmpdir("diff");
    let path = write_config(
        &dir,
        ".mcp.json",
        &json!({"mcpServers": {"fs": {"command": "node", "args": ["s.js"]}}}),
    );

    let p = plan_for(&path, Kind::ProjectMcp, None);
    let d = diff(&p.before, &p.after);

    assert!(d.contains("- "), "aucune ligne retirée : {d}");
    assert!(d.contains("+ "), "aucune ligne ajoutée : {d}");
    assert!(d.contains("mcpwall"), "le diff doit montrer le shim : {d}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn le_diff_dun_fichier_inchange_est_vide() {
    assert!(diff("a\nb\n", "a\nb\n").is_empty());
}

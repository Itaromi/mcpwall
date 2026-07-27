//! Tests du moteur de politique.
//!
//! L'obsession ici est le **faux positif** : une règle qui interrompt à tort
//! forme l'utilisateur à cliquer « autoriser » sans lire, ce qui annule le
//! produit entier. Presque autant de tests vérifient qu'une règle *ne*
//! déclenche *pas* que l'inverse.

use std::path::PathBuf;

use mcpwall::policy::{Action, DEFAULT_POLICY_YAML, Finding, Policy, request_from_frame};
use mcpwall::scope::{Scope, ScopeSource};

fn scope(paths: &[&str]) -> Scope {
    Scope::new(
        ScopeSource::Injected,
        paths.iter().map(PathBuf::from).collect::<Vec<_>>(),
    )
}

/// Évalue un `tools/call` contre une politique.
fn eval(
    policy: &Policy,
    tool: &str,
    args: serde_json::Value,
    sc: &Scope,
) -> mcpwall::policy::Decision {
    let frame = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": tool, "arguments": args }
    })
    .to_string();

    let mut buf = String::new();
    let key = sc.key();
    let mut req = request_from_frame("tools/call", frame.as_bytes(), sc, &mut buf);
    req.scope_key = &key;
    policy.evaluate(&req)
}

/// Écrit une politique dans un répertoire propre à l'appelant et la charge.
///
/// Un répertoire par test, pas un pour tous : les tests tournent en parallèle,
/// et un fichier tronqué par une écriture concurrente se relisait en « tout
/// autoriser » — un test vert pour la mauvaise raison.
fn policy_from(tag: &str, yaml: &str) -> Policy {
    let dir = std::env::temp_dir().join(format!("mcpwall-pol-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("répertoire");
    let path = dir.join("policy.yaml");
    std::fs::write(&path, yaml).expect("écriture");
    Policy::load(&path).expect("chargement")
}

fn default_policy(tag: &str) -> Policy {
    let file = Policy::parse(DEFAULT_POLICY_YAML).expect("politique par défaut valide");
    assert_eq!(file.default, Action::Allow);
    // On passe par le même chemin que la production.
    policy_from(tag, DEFAULT_POLICY_YAML)
}

// --- La politique par défaut est valide et discrète ---

#[test]
fn la_politique_par_defaut_se_parse() {
    let f = Policy::parse(DEFAULT_POLICY_YAML).expect("doit se parser");
    assert_eq!(f.default, Action::Allow);
    assert!(!f.fail_closed, "fail_closed doit rester faux par défaut");
    assert_eq!(f.ask_timeout_seconds, 60);
    assert!(f.rules.len() >= 4);
}

#[test]
fn au_repos_la_politique_par_defaut_ne_demande_rien() {
    // Le test anti-fatigue d'alerte. Du trafic ordinaire ne doit produire
    // aucune interruption.
    let p = default_policy("au_repos_la_politique_par_defaut_ne_demande_rien");
    let sc = scope(&["/Users/x/projet"]);

    for (tool, args) in [
        (
            "read_file",
            serde_json::json!({"path": "/Users/x/projet/src/main.rs"}),
        ),
        (
            "list_directory",
            serde_json::json!({"path": "/Users/x/projet"}),
        ),
        ("search", serde_json::json!({"query": "fn main"})),
        ("git_status", serde_json::json!({})),
        (
            "write_file",
            serde_json::json!({"path": "/Users/x/projet/out.txt", "content": "bonjour"}),
        ),
    ] {
        let d = eval(&p, tool, args, &sc);
        assert_eq!(d.action, Action::Allow, "{tool} ne doit pas interrompre");
    }
}

// --- Chemins de secrets ---

#[test]
fn la_lecture_dun_env_declenche() {
    let p = default_policy("la_lecture_dun_env_declenche");
    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/Users/x/projet/.env"}),
        &scope(&["/Users/x/projet"]),
    );
    assert_eq!(d.action, Action::Ask);
    assert_eq!(d.rule.as_deref(), Some("secrets_paths"));
}

#[test]
fn les_cles_ssh_declenchent() {
    let p = default_policy("les_cles_ssh_declenchent");
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    for chemin in [
        format!("{home}/.ssh/id_rsa"),
        format!("{home}/.aws/credentials"),
    ] {
        let d = eval(
            &p,
            "read_file",
            serde_json::json!({ "path": chemin }),
            &scope(&["/Users/x/projet"]),
        );
        assert_eq!(d.action, Action::Ask, "{chemin}");
    }
}

#[test]
fn un_fichier_nomme_environment_ne_declenche_pas() {
    // `**/.env` ne doit pas attraper `environment.ts` ni `.envrc`.
    let p = default_policy("un_fichier_nomme_environment_ne_declenche_pas");
    for chemin in [
        "/Users/x/projet/src/environment.ts",
        "/Users/x/projet/env.example",
        "/Users/x/projet/docs/environnement.md",
    ] {
        let d = eval(
            &p,
            "read_file",
            serde_json::json!({ "path": chemin }),
            &scope(&["/Users/x/projet"]),
        );
        assert_eq!(d.action, Action::Allow, "faux positif sur {chemin}");
    }
}

// --- Détection de secrets ---

#[test]
fn une_cle_aws_dans_les_arguments_declenche() {
    let p = default_policy("une_cle_aws_dans_les_arguments_declenche");
    let d = eval(
        &p,
        "http_post",
        serde_json::json!({"body": "AKIAIOSFODNN7EXAMPLE"}),
        &scope(&["/Users/x/projet"]),
    );
    assert_eq!(d.action, Action::Ask);
    assert_eq!(d.rule.as_deref(), Some("secret_pattern"));
}

#[test]
fn le_journal_ne_recoit_jamais_la_valeur_du_secret() {
    // Convention du projet : on stocke le type et un préfixe tronqué, jamais la
    // valeur. Un journal d'audit qui recopie les secrets est un aggravateur de
    // fuite, pas une protection.
    let p = default_policy("le_journal_ne_recoit_jamais_la_valeur_du_secret");
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let d = eval(
        &p,
        "http_post",
        serde_json::json!({ "body": secret }),
        &scope(&["/Users/x/projet"]),
    );

    let message = d.agent_message();
    assert!(!message.contains(secret), "secret recopié : {message}");
    assert!(message.contains("AKIAIO"), "préfixe attendu : {message}");

    match d.findings.first() {
        Some(Finding::Secret { kind, prefix }) => {
            assert_eq!(*kind, "clé d'accès AWS");
            assert_eq!(prefix.len(), 6);
            assert!(!secret.ends_with(prefix.as_str()) || prefix.len() < secret.len());
        }
        other => panic!("découverte attendue, obtenu {other:?}"),
    }
}

#[test]
fn les_detecteurs_de_secrets_sont_avares() {
    // Chaque motif est une source potentielle de faux positifs. Ces valeurs
    // ressemblent à des secrets sans en être.
    let p = default_policy("les_detecteurs_de_secrets_sont_avares");
    for valeur in [
        "AKIA",                 // trop court
        "akiaiosfodnn7example", // minuscules
        "sk-",                  // trop court
        "ghp_court",            // trop court
        "un texte qui parle de sk- et de tokens",
    ] {
        let d = eval(
            &p,
            "http_post",
            serde_json::json!({ "body": valeur }),
            &scope(&["/Users/x/projet"]),
        );
        assert_eq!(d.action, Action::Allow, "faux positif sur {valeur:?}");
    }
}

#[test]
fn une_cle_privee_est_reconnue() {
    let p = default_policy("une_cle_privee_est_reconnue");
    let d = eval(
        &p,
        "http_post",
        serde_json::json!({"body": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"}),
        &scope(&["/Users/x/projet"]),
    );
    assert_eq!(d.action, Action::Ask);
}

// --- Sortie de projet ---

#[test]
fn une_ecriture_hors_projet_declenche() {
    let p = default_policy("une_ecriture_hors_projet_declenche");
    let d = eval(
        &p,
        "write_file",
        serde_json::json!({"path": "/etc/hosts", "content": "x"}),
        &scope(&["/Users/x/projet"]),
    );
    assert_eq!(d.action, Action::Ask);
    assert_eq!(d.rule.as_deref(), Some("outside_project_write"));
}

#[test]
fn une_lecture_hors_projet_ne_declenche_pas() {
    // La règle vise les écritures. Lire une doc système est banal.
    let p = default_policy("une_lecture_hors_projet_ne_declenche_pas");
    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/usr/share/doc/readme"}),
        &scope(&["/Users/x/projet"]),
    );
    assert_eq!(d.action, Action::Allow);
}

#[test]
fn un_scope_inconnu_ne_declenche_jamais_la_sortie_de_projet() {
    // Sans savoir où est le projet, on ne peut pas dire qu'on en sort.
    // Prétendre le contraire ferait déclencher la règle sur tout le trafic de
    // Claude Desktop, dont le cwd n'a aucun rapport avec un projet.
    let p = default_policy("un_scope_inconnu_ne_declenche_jamais_la_sortie_de_projet");
    let d = eval(
        &p,
        "write_file",
        serde_json::json!({"path": "/etc/hosts", "content": "x"}),
        &Scope::unknown(),
    );
    assert_eq!(d.action, Action::Allow);
}

// --- Règles M3 inertes ---

#[test]
fn les_regles_de_teinte_ne_declenchent_pas_encore() {
    // `taint_exfil` et `tool_description_drift` sont présentes dans le fichier
    // mais inertes tant que M3 n'existe pas. Une règle inerte et visible vaut
    // mieux qu'une règle absente qu'on oublierait d'écrire — mais elle ne doit
    // surtout pas bloquer par accident.
    let p = default_policy("les_regles_de_teinte_ne_declenchent_pas_encore");
    let d = eval(
        &p,
        "http_post",
        serde_json::json!({"body": "des données quelconques"}),
        &scope(&["/Users/x/projet"]),
    );
    assert_eq!(d.action, Action::Allow);
    assert_ne!(d.rule.as_deref(), Some("taint_exfil"));
}

// --- Robustesse du fichier ---

#[test]
fn une_condition_vide_ne_matche_rien() {
    // Sans cette garde, une faute de frappe dans un nom de condition
    // produirait une règle sans condition, donc un blocage de tout le trafic.
    let yaml = r#"
default: allow
rules:
  - id: vide
    when: {}
    action: deny
"#;
    let file = Policy::parse(yaml).expect("parse");
    assert_eq!(file.rules.len(), 1);

    let p = policy_from("une_condition_vide_ne_matche_rien", yaml);

    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/x"}),
        &scope(&["/x"]),
    );
    assert_eq!(
        d.action,
        Action::Allow,
        "une règle vide ne doit rien bloquer"
    );
}

#[test]
fn une_politique_vide_est_refusee() {
    // Trouvé par un test devenu instable : tous les champs ayant un défaut, un
    // fichier vide se désérialisait en `default: allow` sans aucune règle. Un
    // `policy.yaml` tronqué — disque plein, éditeur interrompu, écriture
    // partielle — aurait donc désactivé le pare-feu sans un mot.
    for vide in ["", "   ", "\n\n", "\t\n  "] {
        assert!(
            Policy::parse(vide).is_err(),
            "une politique vide ne doit jamais valoir « tout autoriser » : {vide:?}"
        );
    }
}

#[test]
fn une_politique_tronquee_laisse_lancienne_active() {
    // Le corollaire à chaud : si le fichier est vidé pendant une session, on
    // continue avec ce qu'on avait plutôt que d'ouvrir en grand.
    let dir = std::env::temp_dir().join(format!("mcpwall-tronq-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("répertoire");
    let path = dir.join("policy.yaml");

    std::fs::write(&path, "default: deny\nrules: []\n").expect("écriture");
    let mut p = Policy::load(&path).expect("chargement");
    assert_eq!(p.default_action(), Action::Deny);

    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&path, "").expect("troncature");

    assert!(!p.reload_if_changed());
    assert_eq!(
        p.default_action(),
        Action::Deny,
        "un fichier vidé ne doit pas désactiver le filtrage"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn un_champ_inconnu_est_refuse() {
    // Mieux vaut refuser le fichier que d'ignorer silencieusement une règle que
    // l'utilisateur croit active.
    let yaml = r#"
default: allow
rules:
  - id: faute
    when:
      arg_path_matchez: ["**/.env"]
    action: deny
"#;
    assert!(Policy::parse(yaml).is_err());
}

#[test]
fn la_premiere_regle_qui_matche_gagne() {
    let yaml = r#"
default: allow
rules:
  - id: premiere
    when:
      tool_matches: ["read_*"]
    action: allow
  - id: seconde
    when:
      arg_path_matches: ["**/.env"]
    action: deny
"#;
    let p = policy_from("la_premiere_regle_qui_matche_gagne", yaml);

    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/x/.env"}),
        &scope(&["/x"]),
    );
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.rule.as_deref(), Some("premiere"));
}

// --- Overrides ---

#[test]
fn un_override_prime_sur_les_regles() {
    let yaml = r#"
default: allow
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env"]
    action: deny
overrides:
  - scope: "project:/Users/x/projet"
    tool: "read_file"
    action: allow
    until: forever
"#;
    let p = policy_from("un_override_prime_sur_les_regles", yaml);

    let sc = scope(&["/Users/x/projet"]);
    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/Users/x/projet/.env"}),
        &sc,
    );
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.rule.as_deref(), Some("override"));
}

#[test]
fn un_override_ne_fuit_pas_vers_un_autre_projet() {
    // Le contrôle que toute la chaîne de provenance existe pour garantir.
    let yaml = r#"
default: allow
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env"]
    action: deny
overrides:
  - scope: "project:/Users/x/projet-a"
    tool: "read_file"
    action: allow
    until: forever
"#;
    let p = policy_from("un_override_ne_fuit_pas_vers_un_autre_projet", yaml);

    let autre = scope(&["/Users/x/projet-b"]);
    let d = eval(
        &p,
        "read_file",
        serde_json::json!({"path": "/Users/x/projet-b/.env"}),
        &autre,
    );
    assert_eq!(
        d.action,
        Action::Deny,
        "l'override a fui vers un autre projet"
    );
}

// --- Rechargement à chaud ---

#[test]
fn la_politique_se_recharge_quand_le_fichier_change() {
    let dir = std::env::temp_dir().join(format!("mcpwall-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("p.yaml");

    std::fs::write(&path, "default: allow\nrules: []\n").expect("écriture");
    let mut p = Policy::load(&path).expect("chargement");
    assert_eq!(p.default_action(), Action::Allow);

    // La granularité des mtime impose d'attendre un peu.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&path, "default: deny\nrules: []\n").expect("réécriture");

    assert!(p.reload_if_changed());
    assert_eq!(p.default_action(), Action::Deny);
}

#[test]
fn une_politique_invalide_laisse_lancienne_active() {
    // Un fichier à moitié édité ne doit ni ouvrir le pare-feu en grand, ni le
    // fermer d'un coup au milieu d'une session de travail.
    let dir = std::env::temp_dir().join(format!("mcpwall-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("p.yaml");

    std::fs::write(&path, "default: deny\nrules: []\n").expect("écriture");
    let mut p = Policy::load(&path).expect("chargement");
    assert_eq!(p.default_action(), Action::Deny);

    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&path, "default: [ceci n'est pas valide\n").expect("réécriture");

    assert!(
        !p.reload_if_changed(),
        "un fichier invalide ne doit pas être adopté"
    );
    assert_eq!(
        p.default_action(),
        Action::Deny,
        "l'ancienne politique doit rester"
    );
}

//! Tests d'intégration M1 : daemon réel, shim réel, socket réel.
//!
//! Le test qui définit le jalon est [`une_lecture_de_env_est_bloquee_sans_casser_la_session`] :
//! bloquer doit ressembler à un échec d'outil ordinaire, pas à une panne.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn mcpwall() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcpwall"))
}

fn server(name: &str) -> PathBuf {
    let mut p = mcpwall();
    p.pop();
    p.push(name);
    p
}

/// Répertoire de travail court.
///
/// `sockaddr_un.sun_path` ne fait que 104 octets sur macOS ; le répertoire
/// temporaire de la CI suffit à le dépasser.
fn workdir(tag: &str) -> PathBuf {
    let d = PathBuf::from(format!("/tmp/mw-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("répertoire de travail");
    d
}

/// Daemon lancé pour la durée d'un test, tué à la sortie.
struct Daemon {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
}

impl Daemon {
    fn start(tag: &str, policy: &str) -> Self {
        let dir = workdir(tag);
        let socket = dir.join("d.sock");
        let policy_path = dir.join("policy.yaml");
        std::fs::write(&policy_path, policy).expect("politique");

        let child = Command::new(mcpwall())
            .arg("daemon")
            .args(["--socket".as_ref(), socket.as_os_str()])
            .args(["--policy".as_ref(), policy_path.as_os_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("lancement du daemon");

        // Attendre que le socket apparaisse plutôt que de dormir au hasard.
        let start = Instant::now();
        while !socket.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(socket.exists(), "le daemon n'a pas créé son socket");

        Self { child, socket, dir }
    }

    /// Conduit une session à travers le shim et rend sa sortie.
    fn session(&self, input: &str) -> String {
        let mut child = Command::new(mcpwall())
            .args(["--db".as_ref(), self.dir.join("j.db").as_os_str()])
            .arg("wrap")
            .args(["--socket".as_ref(), self.socket.as_os_str()])
            .arg("--")
            .arg(server("normal"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("lancement du shim");

        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(input.as_bytes());
        }
        let out = child.wait_with_output().expect("attente du shim");
        assert_eq!(
            out.status.code(),
            Some(0),
            "la session doit sortir proprement"
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"T","version":"1"}}}"#;

const POLICY: &str = r#"
default: allow
fail_closed: false
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env", "**/id_rsa"]
    action: deny
    severity: high
    message: "accès à un fichier de secrets"
  - id: secret_pattern
    when:
      arg_matches_secret: true
    action: deny
    message: "un argument ressemble à un identifiant secret"
overrides: []
"#;

/// Extrait les réponses indexées par `id`.
fn by_id(out: &str) -> std::collections::BTreeMap<i64, serde_json::Value> {
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| Some((v.get("id")?.as_i64()?, v)))
        .collect()
}

// --- Le critère de sortie du jalon ---

#[test]
fn une_lecture_de_env_est_bloquee_sans_casser_la_session() {
    let d = Daemon::start("m1-env", POLICY);

    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/Users/x/projet/.env\"}}}}}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/Users/x/projet/README.md\"}}}}}}\n"
    );
    let out = d.session(&input);
    let responses = by_id(&out);

    // L'initialize passe : le bloquer tuerait la session entière.
    let init = responses.get(&1).expect("réponse d'initialize");
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25");

    // Le .env est bloqué, sous la forme d'un échec d'outil ordinaire.
    let denied = responses.get(&2).expect("réponse au .env");
    assert_eq!(denied["result"]["isError"], true);
    assert!(
        denied.get("error").is_none(),
        "jamais d'erreur de protocole"
    );
    let text = denied["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.starts_with("blocked by mcpwall:"), "{text}");
    assert!(text.contains("secrets_paths"), "{text}");

    // Et surtout : la session continue, l'appel suivant aboutit normalement.
    let allowed = responses.get(&3).expect("réponse au README");
    assert_eq!(allowed["result"]["content"][0]["text"], "ok");
    assert!(allowed["result"].get("isError").is_none());
}

#[test]
fn un_secret_dans_les_arguments_est_bloque_sans_etre_recopie() {
    let d = Daemon::start("m1-secret", POLICY);
    let secret = "AKIAIOSFODNN7EXAMPLE";

    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"http_post\",\"arguments\":{{\"body\":\"{secret}\"}}}}}}\n"
    );
    let out = d.session(&input);
    let denied = by_id(&out).remove(&2).expect("réponse");

    assert_eq!(denied["result"]["isError"], true);
    let text = denied["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("AKIAIO"),
        "le préfixe doit être montré : {text}"
    );
    assert!(
        !text.contains(secret),
        "le secret ne doit jamais être recopié : {text}"
    );
}

#[test]
fn le_trafic_ordinaire_traverse_le_daemon_sans_encombre() {
    let d = Daemon::start("m1-ordinaire", POLICY);

    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"text\":\"bonjour\"}}}}}}\n"
    );
    let out = d.session(&input);
    let r = by_id(&out);

    assert_eq!(r.len(), 3, "toutes les réponses doivent revenir : {out}");
    for id in [1, 2, 3] {
        assert!(
            r[&id]["result"].get("isError").is_none(),
            "id {id} bloqué à tort : {out}"
        );
    }
}

// --- Le mode dégradé ---

#[test]
fn sans_daemon_le_shim_relaie_quand_meme() {
    // La règle de disponibilité §4. Si fermer l'app paralysait les serveurs MCP,
    // mcpwall serait désinstallé dans l'heure.
    let dir = workdir("m1-sans-daemon");
    let absent = dir.join("inexistant.sock");

    let mut child = Command::new(mcpwall())
        .args(["--db".as_ref(), dir.join("j.db").as_os_str()])
        .arg("wrap")
        .args(["--socket".as_ref(), absent.as_os_str()])
        .arg("--")
        .arg(server("normal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim");

    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(
            format!(
                "{INIT}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/Users/x/.env\"}}}}}}\n"
            )
            .as_bytes(),
        );
    }
    let out = child.wait_with_output().expect("attente");
    let text = String::from_utf8_lossy(&out.stdout);
    let r = by_id(&text);

    assert_eq!(out.status.code(), Some(0));
    assert_eq!(r.len(), 2, "le trafic doit passer sans daemon : {text}");
    assert!(
        r[&2]["result"].get("isError").is_none(),
        "sans daemon, rien ne doit être bloqué : {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn un_daemon_qui_meurt_en_cours_de_session_ne_la_casse_pas() {
    let mut d = Daemon::start("m1-mort", POLICY);

    // Une première session confirme que le blocage fonctionne.
    let bloqué = d.session(&format!(
        "{INIT}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/x/.env\"}}}}}}\n"
    ));
    assert_eq!(by_id(&bloqué)[&2]["result"]["isError"], true);

    // Le daemon disparaît — mise à jour, app fermée, crash.
    let _ = d.child.kill();
    let _ = d.child.wait();

    let out = d.session(&format!(
        "{INIT}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":\"/x/.env\"}}}}}}\n"
    ));
    let r = by_id(&out);
    assert_eq!(r.len(), 2, "la session doit rester utilisable : {out}");
    assert!(
        r[&2]["result"].get("isError").is_none(),
        "fail-open attendu : {out}"
    );
}

// --- Handshake de version ---

#[test]
fn un_shim_de_version_incompatible_passe_en_fail_open() {
    // Le cas du client MCP resté ouvert pendant une mise à jour. On simule un
    // vieux shim en parlant directement au socket.
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let d = Daemon::start("m1-version", POLICY);

    let stream = UnixStream::connect(&d.socket).expect("connexion");
    let mut write = stream.try_clone().expect("clone");
    let mut lines = BufReader::new(stream).lines();

    // Version volontairement fausse.
    writeln!(write, r#"{{"mcpwall_ipc": 99, "build": "ancien"}}"#).expect("hello");

    let reply = lines.next().expect("réponse").expect("ligne");
    let hello: serde_json::Value = serde_json::from_str(&reply).expect("json");
    assert_eq!(hello["mcpwall_ipc"], 1, "le daemon annonce sa version");

    // Le daemon ferme la connexion plutôt que de risquer un verdict mal
    // interprété : un verdict incompris, c'est soit un blocage fantôme, soit un
    // trou dans le pare-feu.
    writeln!(write, r#"{{"method":"tools/call","frame":"{{}}","scope_key":"x","scope_source":"cwd","scope_paths":[],"server":null,"session_id":0}}"#).ok();
    assert!(
        lines.next().is_none(),
        "aucun verdict ne doit être rendu après un handshake incompatible"
    );
}

#[test]
fn un_handshake_compatible_est_accepte() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let d = Daemon::start("m1-handshake", POLICY);

    let stream = UnixStream::connect(&d.socket).expect("connexion");
    let mut write = stream.try_clone().expect("clone");
    let mut lines = BufReader::new(stream).lines();

    writeln!(write, r#"{{"mcpwall_ipc": 1, "build": "test"}}"#).expect("hello");
    let _ = lines.next().expect("hello du daemon");

    let frame = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/p/.env" } }
    })
    .to_string();
    let req = serde_json::json!({
        "method": "tools/call",
        "frame": frame,
        "scope_key": "project:/p",
        "scope_source": "injected",
        "scope_paths": ["/p"],
        "server": null,
        "session_id": 1,
    });
    writeln!(write, "{req}").expect("requête");

    let reply = lines.next().expect("verdict").expect("ligne");
    let v: serde_json::Value = serde_json::from_str(&reply).expect("json");
    assert_eq!(v["outcome"], "deny");
    assert_eq!(v["rule"], "secrets_paths");
    // Provenance de rang 1 : `forever` est offrable.
    assert_eq!(v["forever_allowed"], true);
}

#[test]
fn forever_est_refuse_en_provenance_faible() {
    // La garde de sécurité du scope, vue depuis le protocole : c'est le daemon
    // qui calcule `forever_allowed`, pour que l'UI n'ait pas à refaire le
    // raisonnement — et ne puisse pas se tromper en le refaisant.
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let d = Daemon::start("m1-forever", POLICY);

    let stream = UnixStream::connect(&d.socket).expect("connexion");
    let mut write = stream.try_clone().expect("clone");
    let mut lines = BufReader::new(stream).lines();
    writeln!(write, r#"{{"mcpwall_ipc": 1, "build": "test"}}"#).expect("hello");
    let _ = lines.next();

    for (source, attendu) in [
        ("injected", true),
        ("roots", true),
        ("cwd", false),
        ("unknown", false),
    ] {
        let req = serde_json::json!({
            "method": "tools/call",
            "frame": r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#,
            "scope_key": "project:/p",
            "scope_source": source,
            "scope_paths": ["/p"],
            "server": null,
            "session_id": 1,
        });
        writeln!(write, "{req}").expect("requête");
        let reply = lines.next().expect("verdict").expect("ligne");
        let v: serde_json::Value = serde_json::from_str(&reply).expect("json");
        assert_eq!(v["forever_allowed"], attendu, "provenance {source}");
    }
}

//! Tests du flux de confirmation.
//!
//! C'est la mécanique que le panneau de décision de l'app pilote. Les cas qui
//! comptent ne sont pas « l'utilisateur clique autoriser » — c'est ce qui se
//! passe quand il ne clique pas, quand l'interface meurt, ou quand elle demande
//! plus que ce que la provenance du scope permet.

use std::io::{BufRead, BufReader, Lines, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn mcpwall() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcpwall"))
}

/// Répertoire court : `sun_path` ne fait que 104 octets sur macOS.
fn workdir(tag: &str) -> PathBuf {
    let d = PathBuf::from(format!("/tmp/mwa-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("répertoire");
    d
}

const POLICY: &str = r#"
default: allow
ask_timeout_seconds: 3
rules:
  - id: secrets_paths
    when:
      arg_path_matches: ["**/.env"]
    action: ask
    severity: high
    message: "accès à un fichier de secrets"
overrides: []
"#;

struct Harness {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
}

/// Une connexion au daemon, après handshake.
struct Conn {
    write: UnixStream,
    lines: Lines<BufReader<UnixStream>>,
}

impl Conn {
    fn send(&mut self, v: Value) {
        writeln!(self.write, "{v}").expect("envoi");
        self.write.flush().ok();
    }

    fn recv(&mut self) -> Option<Value> {
        let line = self.lines.next()?.ok()?;
        serde_json::from_str(&line).ok()
    }
}

impl Harness {
    fn start(tag: &str, policy: &str) -> Self {
        let dir = workdir(tag);
        let socket = dir.join("d.sock");
        let policy_path = dir.join("policy.yaml");
        std::fs::write(&policy_path, policy).expect("politique");

        let child = Command::new(mcpwall())
            .args(["--db".as_ref(), dir.join("j.db").as_os_str()])
            .arg("daemon")
            .args(["--socket".as_ref(), socket.as_os_str()])
            .args(["--policy".as_ref(), policy_path.as_os_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("daemon");

        let start = Instant::now();
        while !socket.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(socket.exists(), "socket non créé");

        Self { child, socket, dir }
    }

    fn connect(&self) -> Conn {
        let stream = UnixStream::connect(&self.socket).expect("connexion");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let write = stream.try_clone().expect("clone");
        let mut lines = BufReader::new(stream).lines();

        writeln!(
            &write as &UnixStream,
            r#"{{"mcpwall_ipc": 2, "build": "test"}}"#
        )
        .expect("hello");
        let hello = lines.next().expect("hello daemon").expect("ligne");
        let v: Value = serde_json::from_str(&hello).expect("json");
        assert_eq!(v["mcpwall_ipc"], 2);

        Conn { write, lines }
    }

    /// Connexion d'interface, abonnée aux demandes.
    fn ui(&self) -> Conn {
        let mut c = self.connect();
        c.send(json!({"type": "subscribe"}));
        // Laisser le daemon enregistrer l'abonnement avant qu'un shim ne
        // demande : sinon on teste une course, pas le comportement.
        std::thread::sleep(Duration::from_millis(150));
        c
    }

    fn decide_request(scope_source: &str) -> Value {
        let frame = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/p/.env" } }
        })
        .to_string();
        json!({
            "type": "decide",
            "method": "tools/call",
            "frame": frame,
            "scope_key": "project:/p",
            "scope_source": scope_source,
            "scope_paths": ["/p"],
            "server": "srv",
            "session_id": 1,
        })
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// --- Le chemin nominal ---

#[test]
fn une_demande_atteint_linterface_avec_de_quoi_decider() {
    let h = Harness::start("prompt", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));

    let prompt = ui.recv().expect("demande");
    assert_eq!(prompt["type"], "prompt");

    // Tout ce qu'il faut pour décider sans aller chercher ailleurs. Si
    // l'utilisateur doit ouvrir le journal pour comprendre, il cliquera
    // « autoriser » à la place.
    assert_eq!(prompt["tool"], "read_file");
    assert_eq!(prompt["server"], "srv");
    assert_eq!(prompt["rule"], "secrets_paths");
    assert_eq!(prompt["severity"], "high");
    assert_eq!(prompt["scope_key"], "project:/p");
    assert!(
        prompt["preview"].as_str().unwrap_or("").contains(".env"),
        "l'extrait doit montrer l'argument : {prompt}"
    );
    assert_eq!(prompt["forever_allowed"], true);
    assert_eq!(prompt["timeout_seconds"], 3);

    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "once"
    }));

    let verdict = shim.recv().expect("verdict");
    assert_eq!(verdict["type"], "verdict");
    assert_eq!(verdict["outcome"], "allow");
}

#[test]
fn un_refus_de_lutilisateur_bloque() {
    let h = Harness::start("refus", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("demande");

    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": false,
        "until": "once"
    }));

    let verdict = shim.recv().expect("verdict");
    assert_eq!(verdict["outcome"], "deny");
    assert!(
        verdict["message"]
            .as_str()
            .unwrap_or("")
            .contains("refusé par l'utilisateur"),
        "{verdict}"
    );
}

// --- Quand personne ne répond ---

#[test]
fn sans_interface_une_demande_est_refusee_et_le_dit() {
    // Pas d'UI abonnée : personne ne peut confirmer. On refuse plutôt que
    // d'autoriser en silence, mais l'agent doit comprendre pourquoi — sinon il
    // conclut à une panne de l'outil et réessaie en boucle.
    let h = Harness::start("sans-ui", POLICY);
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let verdict = shim.recv().expect("verdict");

    assert_eq!(verdict["outcome"], "deny");
    let msg = verdict["message"].as_str().unwrap_or("");
    assert!(msg.contains("aucune interface"), "{msg}");
}

#[test]
fn une_demande_sans_reponse_expire_en_refus() {
    let h = Harness::start("timeout", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    let start = Instant::now();
    shim.send(Harness::decide_request("injected"));

    let prompt = ui.recv().expect("demande");
    assert_eq!(prompt["type"], "prompt");

    // On ne répond pas. `ask_timeout_seconds: 3`.
    let verdict = shim.recv().expect("verdict");
    assert_eq!(verdict["outcome"], "deny");
    assert!(
        verdict["message"].as_str().unwrap_or("").contains("délai"),
        "{verdict}"
    );

    let d = start.elapsed();
    assert!(d >= Duration::from_secs(3), "expiré trop tôt : {d:?}");
    assert!(d < Duration::from_secs(15), "expiré trop tard : {d:?}");
}

#[test]
fn une_demande_expiree_est_retiree_de_linterface() {
    // Sans ce retrait, le panneau resterait affiché avec des boutons qui ne
    // feraient plus rien — l'utilisateur croirait avoir décidé.
    let h = Harness::start("withdraw", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("demande");
    let id = prompt["prompt_id"].clone();

    let withdraw = ui.recv().expect("retrait");
    assert_eq!(withdraw["type"], "withdraw");
    assert_eq!(withdraw["prompt_id"], id);

    let _ = shim.recv();
}

#[test]
fn une_reponse_tardive_est_ignoree_sans_casse() {
    let h = Harness::start("tardif", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("demande");
    let _ = ui.recv(); // le retrait
    let _ = shim.recv(); // le refus par expiration

    // L'utilisateur clique après coup. Rien ne doit se casser, et surtout la
    // décision ne doit pas être enregistrée pour la suite.
    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "session"
    }));

    shim.send(Harness::decide_request("injected"));
    let prompt2 = ui.recv().expect("une nouvelle demande doit être posée");
    assert_eq!(prompt2["type"], "prompt");
}

// --- Les portées ---

#[test]
fn une_decision_de_session_evite_de_redemander() {
    let h = Harness::start("session", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("demande");
    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "session"
    }));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "allow");

    // Deuxième appel identique : autorisé sans redemander.
    shim.send(Harness::decide_request("injected"));
    let verdict = shim.recv().expect("verdict");
    assert_eq!(verdict["outcome"], "allow");
    assert_eq!(verdict["rule"], "override");
}

#[test]
fn une_decision_once_fait_redemander() {
    // `once` ne vaut que pour cet appel. Le confondre avec `session`
    // accorderait silencieusement plus que ce que l'utilisateur a coché.
    let h = Harness::start("once", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let p1 = ui.recv().expect("demande");
    ui.send(json!({"type":"answer","prompt_id":p1["prompt_id"],"allow":true,"until":"once"}));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "allow");

    shim.send(Harness::decide_request("injected"));
    let p2 = ui.recv().expect("une seconde demande est attendue");
    assert_eq!(p2["type"], "prompt");
    ui.send(json!({"type":"answer","prompt_id":p2["prompt_id"],"allow":false,"until":"once"}));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "deny");
}

#[test]
fn forever_est_persiste_dans_la_politique() {
    let h = Harness::start("forever", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("injected"));
    let prompt = ui.recv().expect("demande");
    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "forever"
    }));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "allow");

    // L'écriture est asynchrone par rapport au verdict.
    std::thread::sleep(Duration::from_millis(300));
    let yaml = std::fs::read_to_string(h.dir.join("policy.yaml")).expect("politique");

    assert!(
        yaml.contains("project:/p"),
        "override non persisté : {yaml}"
    );
    assert!(yaml.contains("read_file"), "{yaml}");
    assert!(yaml.contains("until: forever"), "{yaml}");
    // Les commentaires de l'utilisateur survivent : on ajoute, on ne réécrit pas.
    assert!(
        yaml.contains("ask_timeout_seconds: 3"),
        "le fichier a été réécrit au lieu d'être complété : {yaml}"
    );
}

#[test]
fn forever_est_retrograde_sur_un_scope_non_fiable() {
    // Le contrôle central : l'interface est un client, pas une autorité. Si la
    // provenance du scope ne permet pas `forever`, le daemon rétrograde même
    // quand l'UI l'a demandé — sinon une permission permanente accordée sur un
    // cwd fuirait vers d'autres projets.
    let h = Harness::start("degrade", POLICY);
    let mut ui = h.ui();
    let mut shim = h.connect();

    shim.send(Harness::decide_request("cwd"));
    let prompt = ui.recv().expect("demande");
    assert_eq!(
        prompt["forever_allowed"], false,
        "l'UI ne doit pas proposer `forever` ici"
    );

    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": true,
        "until": "forever"
    }));
    assert_eq!(shim.recv().expect("verdict")["outcome"], "allow");

    std::thread::sleep(Duration::from_millis(300));
    let yaml = std::fs::read_to_string(h.dir.join("policy.yaml")).expect("politique");
    assert!(
        !yaml.contains("project:/p"),
        "une décision permanente a été écrite sur un scope non fiable : {yaml}"
    );
}

// --- État pour le popover ---

#[test]
fn linterface_peut_demander_letat() {
    let h = Harness::start("status", POLICY);
    let mut ui = h.ui();

    ui.send(json!({"type": "status"}));
    let st = ui.recv().expect("état");

    assert_eq!(st["type"], "status");
    assert_eq!(st["ui_connected"], true);
    assert!(
        st["policy_path"]
            .as_str()
            .unwrap_or("")
            .ends_with("policy.yaml")
    );
}

#[test]
fn une_interface_deconnectee_ne_bloque_pas_les_shims() {
    // L'app peut être fermée à tout moment. Les demandes redeviennent des refus
    // expliqués, mais rien ne doit rester suspendu.
    let h = Harness::start("ui-morte", POLICY);
    {
        let _ui = h.ui();
    } // l'UI se déconnecte ici
    std::thread::sleep(Duration::from_millis(200));

    let mut shim = h.connect();
    let start = Instant::now();
    shim.send(Harness::decide_request("injected"));
    let verdict = shim.recv().expect("verdict");

    assert_eq!(verdict["outcome"], "deny");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "le shim a attendu une UI absente : {:?}",
        start.elapsed()
    );
}

// --- Le délai du shim ---

#[test]
fn le_shim_attend_que_lutilisateur_ait_repondu() {
    // Le défaut le plus dangereux trouvé en M2, et invisible tant que
    // l'interface n'existait pas : le shim abandonnait au bout de 5 secondes
    // avec son propre délai de socket, pendant que le daemon attendait encore
    // le clic. Or abandonner **laisse passer** — toute règle `ask` se
    // dégradait donc en `allow` dès que la personne réfléchissait plus de cinq
    // secondes, ce qui est le cas normal quand on lit une demande.
    //
    // Le daemon annonce son délai dans le hello ; le shim en dérive le sien.
    let policy = POLICY.replace("ask_timeout_seconds: 3", "ask_timeout_seconds: 30");
    let h = Harness::start("shim-attend", &policy);
    let mut ui = h.ui();

    // Le vrai shim, pas une simulation : c'est son client qui est en cause.
    let mut shim = Command::new(mcpwall())
        .args(["--db".as_ref(), h.dir.join("j.db").as_os_str()])
        .arg("wrap")
        .args(["--socket".as_ref(), h.socket.as_os_str()])
        .arg("--")
        .arg({
            let mut p = mcpwall();
            p.pop();
            p.push("normal");
            p
        })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim");

    let input = format!(
        "{}\n{}\n",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"T","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/p/.env"}}}"#
    );
    if let Some(mut si) = shim.stdin.take() {
        let _ = si.write_all(input.as_bytes());
    }

    let prompt = ui.recv().expect("demande");
    assert_eq!(prompt["type"], "prompt");

    // L'utilisateur prend son temps — bien au-delà des 5 secondes de l'ancien
    // délai codé en dur.
    std::thread::sleep(Duration::from_secs(8));
    ui.send(json!({
        "type": "answer",
        "prompt_id": prompt["prompt_id"],
        "allow": false,
        "until": "once"
    }));

    let out = shim.wait_with_output().expect("attente du shim");
    let text = String::from_utf8_lossy(&out.stdout);
    let responses: std::collections::BTreeMap<i64, Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| Some((v.get("id")?.as_i64()?, v)))
        .collect();

    let denied = responses.get(&2).expect("réponse à l'appel");
    assert_eq!(
        denied["result"]["isError"], true,
        "le refus tardif de l'utilisateur doit être respecté, pas contourné par \
         un abandon du shim : {text}"
    );
    assert!(
        denied["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("refusé par l'utilisateur"),
        "{text}"
    );
}

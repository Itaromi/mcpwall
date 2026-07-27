//! Tests d'intégration sur de vrais processus.
//!
//! Les défauts de ce module — orphelins, interblocages, descripteurs mal
//! fermés, codes de sortie perdus — sont précisément ceux qu'aucun test moqué
//! ne verra jamais. Ici on lance de vrais binaires et on les fait mal se
//! comporter.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Le binaire du shim.
fn mcpwall() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcpwall"))
}

/// Un serveur factice. Il vit dans le même répertoire de cibles que le shim.
fn server(name: &str) -> PathBuf {
    let mut p = mcpwall();
    p.pop();
    p.push(name);
    assert!(p.exists(), "serveur factice absent : {}", p.display());
    p
}

fn db_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mcpwall-test-{tag}-{}-{}.db",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

/// Conduit une session complète et rend (sortie, code de sortie).
fn session(server_name: &str, input: &str, tag: &str) -> (String, i32) {
    let db = db_path(tag);
    let mut child = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .arg("--")
        .arg(server(server_name))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("lancement du shim");

    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(input.as_bytes());
        // Fermer stdin est le signal d'arrêt normal d'une session MCP stdio.
    }

    let out = child.wait_with_output().expect("attente du shim");
    let _ = std::fs::remove_file(&db);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"T","version":"1"}}}"#;

// --- Session nominale ---

#[test]
fn session_complete_contre_un_serveur_normal() {
    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\"}}}}\n"
    );
    let (out, code) = session("normal", &input, "normal");

    assert_eq!(code, 0, "le code de sortie de l'amont doit remonter");
    assert!(out.contains("\"protocolVersion\":\"2025-11-25\""), "{out}");
    assert!(out.contains("\"name\":\"normal\""), "{out}");
    assert_eq!(out.lines().count(), 3, "une réponse par requête : {out}");
}

// --- Modes de défaillance de l'amont ---

#[test]
fn un_amont_muet_ne_suspend_pas_le_shim() {
    let start = Instant::now();
    let (out, code) = session("silent", &format!("{INIT}\n"), "silent");

    assert!(
        start.elapsed() < Duration::from_secs(10),
        "le shim est resté suspendu {:?}",
        start.elapsed()
    );
    assert!(out.is_empty(), "rien ne doit être inventé : {out}");
    assert_eq!(code, 0);
}

#[test]
fn un_amont_qui_meurt_en_plein_message_fait_sortir_le_shim() {
    let start = Instant::now();
    let (out, code) = session("dies_midmessage", &format!("{INIT}\n"), "dies");

    assert!(
        start.elapsed() < Duration::from_secs(10),
        "le shim a attendu une frame qui ne viendrait jamais"
    );
    assert_eq!(code, 3, "le code de sortie de l'amont doit être propagé");
    // La frame partielle est relayée, avec son délimiteur ajouté : perdre le
    // dernier message serait pire que le transmettre incomplet.
    assert!(out.contains("resu"), "frame partielle attendue : {out:?}");
    assert!(out.ends_with('\n'), "délimiteur manquant : {out:?}");
}

#[test]
fn une_reponse_de_huit_megaoctets_ne_provoque_pas_dinterblocage() {
    let start = Instant::now();
    let (out, code) = session("huge", &format!("{INIT}\n"), "huge");

    assert!(
        start.elapsed() < Duration::from_secs(30),
        "interblocage probable : {:?}",
        start.elapsed()
    );
    assert_eq!(code, 0);
    assert!(
        out.len() > 8 * 1024 * 1024,
        "charge tronquée : {} octets",
        out.len()
    );
    assert!(out.ends_with("}\n"));
}

#[test]
fn un_amont_qui_viole_la_spec_ne_casse_pas_le_relais() {
    let (out, code) = session("malformed", &format!("{INIT}\n"), "malformed");

    assert_eq!(code, 0);
    // Lignes vides absorbées, JSON invalide relayé tel quel, CRLF préservé,
    // dernière frame non terminée complétée.
    assert!(out.contains("ceci n'est pas du json"), "{out:?}");
    assert!(out.contains("\"id\":1"), "{out:?}");
    assert!(out.contains("\"id\":2"), "{out:?}");
    assert!(
        !out.starts_with('\n'),
        "lignes vides non absorbées : {out:?}"
    );
    assert!(out.ends_with('\n'));
}

// --- Le cas des orphelins ---

#[test]
fn aucun_processus_ne_survit_a_larret_du_shim() {
    // Le mode de défaillance le plus visible en usage réel : trente `node`
    // fantômes après une journée de travail, et mcpwall comme coupable
    // désigné. Le serveur utilisé ici ignore délibérément SIGTERM, ce qui
    // oblige le shim à escalader.
    let db = db_path("orphan");
    let mut shim = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .arg("--")
        .arg(server("ignores_sigterm"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("lancement du shim");

    let shim_pid = shim.id();

    // Attendre que le petit-fils existe.
    let child_pid = wait_for(Duration::from_secs(5), || {
        children_of(shim_pid).first().copied()
    })
    .expect("le serveur amont n'a jamais démarré");

    assert!(alive(child_pid), "l'amont devrait tourner");

    // On tue le shim comme le ferait un client qui se ferme.
    signal(shim_pid, nix::sys::signal::Signal::SIGTERM);

    let _ = shim.wait();

    // L'amont ignore SIGTERM ; sans escalade il survivrait. On laisse au shim
    // le temps de sa fenêtre de grâce puis on vérifie.
    let mort = wait_for(Duration::from_secs(20), || {
        (!alive(child_pid)).then_some(())
    });

    if mort.is_none() {
        // Ne pas laisser de trace derrière un test qui échoue.
        signal(child_pid, nix::sys::signal::Signal::SIGKILL);
    }
    let _ = std::fs::remove_file(&db);

    assert!(
        mort.is_some(),
        "le serveur amont (pid {child_pid}) a survécu à l'arrêt du shim"
    );
}

#[test]
fn la_fermeture_de_stdin_arrete_lamont() {
    // Chemin d'arrêt normal de la spec MCP stdio : fermer stdin, l'amont sort.
    let db = db_path("stdin-close");
    let mut shim = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .arg("--")
        .arg(server("normal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("lancement du shim");

    let shim_pid = shim.id();
    let child_pid = wait_for(Duration::from_secs(5), || {
        children_of(shim_pid).first().copied()
    })
    .expect("amont non démarré");

    drop(shim.stdin.take());

    let start = Instant::now();
    let _ = shim.wait();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "le shim n'est pas sorti après fermeture de stdin"
    );

    let mort = wait_for(Duration::from_secs(10), || {
        (!alive(child_pid)).then_some(())
    });
    let _ = std::fs::remove_file(&db);
    assert!(mort.is_some(), "l'amont a survécu à la fermeture de stdin");
}

// --- Journal ---

#[test]
fn le_journal_retrouve_tous_les_appels() {
    // Critère de sortie M0 : « retrouver tous les appels dans le journal ».
    let db = db_path("journal");
    let input = format!(
        "{INIT}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"echo\"}}}}\n"
    );

    let mut child = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .arg("--")
        .arg(server("normal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim");
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(input.as_bytes());
    }
    let _ = child.wait_with_output();

    let out = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .args(["log", "-n", "50", "--json"])
        .output()
        .expect("log");
    let text = String::from_utf8_lossy(&out.stdout);

    let lignes: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    let methodes: Vec<&str> = lignes
        .iter()
        .filter_map(|l| l.get("method")?.as_str())
        .collect();
    assert!(methodes.contains(&"initialize"), "{methodes:?}");
    assert!(methodes.contains(&"tools/list"), "{methodes:?}");
    assert!(methodes.contains(&"tools/call"), "{methodes:?}");

    // Les trois réponses de l'amont sont là aussi.
    let reponses = lignes
        .iter()
        .filter(|l| l["direction"] == "to_client")
        .count();
    assert_eq!(reponses, 3, "réponses manquantes : {text}");

    // La capture de l'`initialize` a renseigné le serveur.
    assert!(
        lignes.iter().any(|l| l["server"] == "normal"),
        "serverInfo non capturé : {text}"
    );

    // Le scope est résolu et sa provenance stockée.
    let source = lignes[0]["scope_source"].as_str().unwrap_or("");
    assert!(
        ["injected", "roots", "cwd"].contains(&source),
        "provenance inattendue : {source}"
    );

    let stats = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .args(["log", "--stats"])
        .output()
        .expect("stats");
    let stats = String::from_utf8_lossy(&stats.stdout);
    assert!(stats.contains("sessions        1"), "{stats}");
    assert!(stats.contains("bloqués         0"), "{stats}");

    let _ = std::fs::remove_file(&db);
}

#[test]
fn le_projet_injecte_prime_sur_le_cwd() {
    // Maillon 1 de la chaîne de provenance : `--project`, écrit par
    // `mcpwall init`. Il doit l'emporter et débloquer la portée `forever`.
    let db = db_path("project");
    let projet = std::env::temp_dir();

    let mut child = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .arg("wrap")
        .args(["--project".as_ref(), projet.as_os_str()])
        .arg("--")
        .arg(server("normal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim");
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(format!("{INIT}\n").as_bytes());
    }
    let _ = child.wait_with_output();

    let out = Command::new(mcpwall())
        .args(["--db".as_ref(), db.as_os_str()])
        .args(["log", "-n", "10", "--json"])
        .output()
        .expect("log");
    let text = String::from_utf8_lossy(&out.stdout);
    let first: serde_json::Value = text
        .lines()
        .next()
        .and_then(|l| serde_json::from_str(l).ok())
        .expect("au moins une ligne");

    assert_eq!(first["scope_source"], "injected", "{text}");
    let _ = std::fs::remove_file(&db);
}

// --- Outillage processus ---

fn signal(pid: u32, sig: nix::sys::signal::Signal) {
    if let Ok(pid) = i32::try_from(pid) {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig);
    }
}

/// Le processus existe-t-il encore ?
///
/// `kill(pid, 0)` ne fait que tester. Un zombie répond encore présent, d'où le
/// filtrage sur l'état dans `ps`.
fn alive(pid: u32) -> bool {
    let Ok(out) = Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output()
    else {
        return false;
    };
    let state = String::from_utf8_lossy(&out.stdout);
    let state = state.trim();
    !state.is_empty() && !state.starts_with('Z')
}

fn children_of(pid: u32) -> Vec<u32> {
    let Ok(out) = Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .output()
    else {
        return Vec::new();
    };
    BufReader::new(out.stdout.as_slice())
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

fn wait_for<T>(limit: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    f()
}

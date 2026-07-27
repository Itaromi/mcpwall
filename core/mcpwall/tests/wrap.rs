//! Tests du relais.
//!
//! Tout se joue sur des tampons en mémoire : pas de processus, pas de SQLite.
//! Ce que ces tests vérifient avant tout, c'est qu'aucune anomalie d'inspection
//! n'interrompt le trafic.

use std::sync::{Arc, Mutex};

use mcpwall::frame::SplitterStats;
use mcpwall::mcp::{AllowAll, CallContext, DecisionError, DecisionPoint, Disposition, Verdict};
use mcpwall::wrap::{Anomaly, Direction, FrameEvent, Observer, Pump};
use tokio::sync::mpsc;

// --- Outillage ---

/// Trace d'une frame vue par l'observateur.
struct Seen {
    #[allow(dead_code)]
    direction: Direction,
    #[allow(dead_code)]
    disposition: Disposition,
    method: Option<String>,
    #[allow(dead_code)]
    denied: bool,
}

#[derive(Default)]
struct Recorder {
    frames: Mutex<Vec<Seen>>,
    anomalies: Mutex<Vec<String>>,
    eof: Mutex<Vec<(Direction, SplitterStats)>>,
}

impl Observer for Recorder {
    fn on_frame(&self, e: &FrameEvent<'_>) {
        let denied = matches!(e.verdict, Some(Verdict::Deny { .. }));
        if let Ok(mut g) = self.frames.lock() {
            g.push(Seen {
                direction: e.direction,
                disposition: e.disposition,
                method: e.method.map(str::to_owned),
                denied,
            });
        }
    }

    fn on_anomaly(&self, a: &Anomaly) {
        if let Ok(mut g) = self.anomalies.lock() {
            g.push(format!("{a:?}"));
        }
    }

    fn on_eof(&self, d: Direction, s: SplitterStats) {
        if let Ok(mut g) = self.eof.lock() {
            g.push((d, s));
        }
    }
}

impl Recorder {
    fn methods(&self) -> Vec<String> {
        self.frames
            .lock()
            .map(|g| g.iter().filter_map(|f| f.method.clone()).collect())
            .unwrap_or_default()
    }

    fn count(&self) -> usize {
        self.frames.lock().map(|g| g.len()).unwrap_or(0)
    }

    fn anomalies(&self) -> Vec<String> {
        self.anomalies.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

/// Bloque tout ce qui atteint le point de décision.
struct DenyAll;

impl DecisionPoint for DenyAll {
    fn decide(&self, _ctx: &CallContext<'_>) -> Result<Verdict, DecisionError> {
        Ok(Verdict::Deny {
            rule: "test_rule".into(),
            message: "tainted local data in outbound argument".into(),
        })
    }
}

/// Point de décision en panne. Simule un daemon injoignable.
struct Broken {
    fail_closed: bool,
}

impl DecisionPoint for Broken {
    fn decide(&self, _ctx: &CallContext<'_>) -> Result<Verdict, DecisionError> {
        Err(DecisionError {
            reason: "daemon injoignable".into(),
            fail_closed: self.fail_closed,
        })
    }
}

fn pump(direction: Direction, obs: Arc<Recorder>, dp: Arc<dyn DecisionPoint>) -> Pump {
    Pump {
        direction,
        max_frame_bytes: 1024,
        observer: obs,
        decision: dp,
        denied_tx: None,
    }
}

/// Relaie `input` et rend ce qui est sorti côté amont.
async fn relay(direction: Direction, input: &[u8], obs: Arc<Recorder>) -> Vec<u8> {
    let mut out = Vec::new();
    pump(direction, obs, Arc::new(AllowAll))
        .run(input, &mut out, None)
        .await
        .expect("le relais ne doit pas échouer");
    out
}

// --- Transparence ---

#[tokio::test]
async fn le_relais_est_transparent() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
    let obs = Arc::new(Recorder::default());
    let out = relay(Direction::ToServer, input, obs.clone()).await;

    assert_eq!(out, input, "octet pour octet");
    assert_eq!(obs.count(), 2);
    assert_eq!(obs.methods(), vec!["tools/call"]);
}

#[tokio::test]
async fn crlf_amont_preserve() {
    // On ne normalise pas ce qu'on ne comprend pas : le pair reçoit ses octets.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n";
    let obs = Arc::new(Recorder::default());
    assert_eq!(relay(Direction::ToClient, input, obs).await, input);
}

#[tokio::test]
async fn charge_utile_de_plusieurs_megaoctets() {
    let big = "z".repeat(4 * 1024 * 1024);
    let input = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"t\":\"{big}\"}}}}\n");

    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();
    Pump {
        direction: Direction::ToClient,
        max_frame_bytes: 32 * 1024 * 1024,
        observer: obs.clone(),
        decision: Arc::new(AllowAll),
        denied_tx: None,
    }
    .run(input.as_bytes(), &mut out, None)
    .await
    .expect("relais");

    assert_eq!(out, input.as_bytes());
    assert_eq!(obs.count(), 1);
}

#[tokio::test]
async fn frame_finale_sans_delimiteur_recoit_le_sien() {
    // Sinon le pair attend indéfiniment la suite d'un message complet.
    let obs = Arc::new(Recorder::default());
    let out = relay(
        Direction::ToClient,
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
        obs.clone(),
    )
    .await;

    assert!(out.ends_with(b"}\n"));
    assert_eq!(obs.count(), 1);
    assert!(
        obs.anomalies().iter().any(|a| a.contains("Unterminated")),
        "l'anomalie doit être signalée : {:?}",
        obs.anomalies()
    );
}

// --- Aucune anomalie n'interrompt le trafic ---

#[tokio::test]
async fn frame_surdimensionnee_jetee_mais_le_flux_continue() {
    let mut input = vec![b'x'; 4096];
    input.push(b'\n');
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n");

    let obs = Arc::new(Recorder::default());
    let out = relay(Direction::ToServer, &input, obs.clone()).await;

    assert_eq!(
        out, b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        "les octets rejetés ne doivent pas atteindre l'amont, la suite si"
    );
    assert!(obs.anomalies().iter().any(|a| a.contains("Oversize")));
    assert_eq!(obs.methods(), vec!["tools/list"]);
}

#[tokio::test]
async fn json_malforme_relaye_quand_meme() {
    // Ce n'est pas au shim de décider qu'un message est invalide : c'est au
    // serveur amont de répondre son erreur. On journalise et on passe.
    let input = b"pas du json du tout\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    let obs = Arc::new(Recorder::default());
    assert_eq!(relay(Direction::ToServer, input, obs.clone()).await, input);
    assert_eq!(obs.count(), 2);
}

#[tokio::test]
async fn lignes_vides_amont_absorbees() {
    let input = b"\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    let obs = Arc::new(Recorder::default());
    let out = relay(Direction::ToClient, input, obs.clone()).await;
    assert_eq!(out, b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    assert_eq!(obs.count(), 1);
}

#[tokio::test]
async fn frames_eclatees_en_petits_morceaux() {
    // Le relais doit être insensible au découpage des lectures, comme le
    // découpeur qu'il utilise.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";

    let obs = Arc::new(Recorder::default());
    let (mut client, mut server) = tokio::io::duplex(8);
    let mut out = Vec::new();

    let feeder = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        for chunk in input.chunks(3) {
            let _ = client.write_all(chunk).await;
        }
        let _ = client.shutdown().await;
    });

    pump(Direction::ToServer, obs.clone(), Arc::new(AllowAll))
        .run(&mut server, &mut out, None)
        .await
        .expect("relais");
    let _ = feeder.await;

    assert_eq!(out, input);
    assert_eq!(obs.methods(), vec!["tools/call", "tools/list"]);
}

// --- Point de décision ---

#[tokio::test]
async fn m0_ne_bloque_rien() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n";
    let obs = Arc::new(Recorder::default());
    assert_eq!(relay(Direction::ToServer, input, obs).await, input);
}

#[tokio::test]
async fn seul_le_sens_montant_consulte_le_point_de_decision() {
    // Une réponse qui descend ne doit jamais être soumise à un verdict.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n";
    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();

    pump(Direction::ToClient, obs.clone(), Arc::new(DenyAll))
        .run(&input[..], &mut out, None)
        .await
        .expect("relais");

    assert_eq!(out, input, "DenyAll ne doit pas s'appliquer en descente");
}

#[tokio::test]
async fn initialize_ne_peut_pas_etre_bloque() {
    // La garde structurelle vue de bout en bout : même avec un point de décision
    // qui refuse tout, `initialize` passe. Le bloquer tuerait la session.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n";
    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();

    pump(Direction::ToServer, obs.clone(), Arc::new(DenyAll))
        .run(&input[..], &mut out, None)
        .await
        .expect("relais");

    assert_eq!(out, input, "initialize doit atteindre l'amont");
}

#[tokio::test]
async fn un_deny_ne_monte_pas_et_repond_au_client() {
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/call\",\
                  \"params\":{\"name\":\"http_post\"}}\n";

    let (tx, mut rx) = mpsc::unbounded_channel();
    let obs = Arc::new(Recorder::default());
    let mut upstream = Vec::new();

    Pump {
        direction: Direction::ToServer,
        max_frame_bytes: 1024,
        observer: obs.clone(),
        decision: Arc::new(DenyAll),
        denied_tx: Some(tx),
    }
    .run(&input[..], &mut upstream, None)
    .await
    .expect("relais");

    assert!(
        upstream.is_empty(),
        "la frame ne doit jamais atteindre l'amont"
    );

    let payload = rx
        .recv()
        .await
        .expect("une réponse de blocage est attendue");
    let v: serde_json::Value = serde_json::from_slice(payload.trim_ascii_end()).expect("json");

    // Forme §5 : un result valide, pas une erreur de protocole.
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 42, "l'id doit être celui de la requête bloquée");
    assert_eq!(v["result"]["isError"], true);
    assert!(v.get("error").is_none(), "jamais d'erreur JSON-RPC");

    let text = v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.starts_with("blocked by mcpwall:"), "{text}");
    assert!(text.contains("rule: test_rule"), "{text}");
    assert!(payload.ends_with(b"\n"), "frame prête à écrire");
}

#[tokio::test]
async fn une_notification_bloquee_ne_produit_pas_de_reponse() {
    // Pas d'id, donc rien n'attend de réponse. On jette et on le note.
    let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{}}\n";

    let (tx, mut rx) = mpsc::unbounded_channel();
    let obs = Arc::new(Recorder::default());
    let mut upstream = Vec::new();

    Pump {
        direction: Direction::ToServer,
        max_frame_bytes: 1024,
        observer: obs.clone(),
        decision: Arc::new(DenyAll),
        denied_tx: Some(tx),
    }
    .run(&input[..], &mut upstream, None)
    .await
    .expect("relais");

    assert!(upstream.is_empty());
    assert!(
        rx.try_recv().is_err(),
        "aucune réponse ne doit être fabriquée"
    );
    assert!(
        obs.anomalies()
            .iter()
            .any(|a| a.contains("DeniedWithoutId")),
        "{:?}",
        obs.anomalies()
    );
}

// --- Voie de retour ---

#[tokio::test]
async fn les_reponses_de_blocage_sortent_par_la_pompe_descendante() {
    // Le blocage se décide en montée mais la réponse redescend : sans cette
    // voie de retour, le client attendrait indéfiniment.
    let (tx, rx) = mpsc::unbounded_channel();
    tx.send(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"isError\":true}}\n".to_vec())
        .expect("envoi");
    drop(tx);

    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();
    let amont = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";

    pump(Direction::ToClient, obs.clone(), Arc::new(AllowAll))
        .run(&amont[..], &mut out, Some(rx))
        .await
        .expect("relais");

    let texte = String::from_utf8_lossy(&out);
    assert!(
        texte.contains("\"id\":7"),
        "la frame injectée manque : {texte}"
    );
    assert!(
        texte.contains("\"id\":1"),
        "le trafic amont manque : {texte}"
    );
}

// --- Compteurs ---

#[tokio::test]
async fn les_compteurs_remontent_en_fin_de_flux() {
    let input = b"\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n";
    let obs = Arc::new(Recorder::default());
    relay(Direction::ToClient, input, obs.clone()).await;

    let eof = obs.eof.lock().expect("verrou");
    let (direction, stats) = eof.first().expect("un eof attendu");
    assert_eq!(*direction, Direction::ToClient);
    assert_eq!(stats.frames, 1);
    assert_eq!(stats.empty_skipped, 1);
    assert_eq!(stats.crlf, 1);
}

// --- Panne du point de décision ---

#[tokio::test]
async fn un_point_de_decision_en_panne_laisse_passer() {
    // Règle de disponibilité §4 appliquée à notre propre code : si le daemon
    // est tombé, on ne casse pas la session de l'agent.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n";
    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();

    pump(
        Direction::ToServer,
        obs.clone(),
        Arc::new(Broken { fail_closed: false }),
    )
    .run(&input[..], &mut out, None)
    .await
    .expect("relais");

    assert_eq!(out, input, "le trafic doit passer malgré la panne");
    assert!(
        obs.anomalies()
            .iter()
            .any(|a| a.contains("DecisionUnavailable")),
        "l'incident doit être signalé : {:?}",
        obs.anomalies()
    );
}

#[tokio::test]
async fn fail_closed_bloque_quand_la_politique_le_demande() {
    // L'utilisateur qui a explicitement demandé fail_closed obtient un blocage,
    // pas un passage silencieux.
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{}}\n";
    let (tx, mut rx) = mpsc::unbounded_channel();
    let obs = Arc::new(Recorder::default());
    let mut out = Vec::new();

    Pump {
        direction: Direction::ToServer,
        max_frame_bytes: 1024,
        observer: obs.clone(),
        decision: Arc::new(Broken { fail_closed: true }),
        denied_tx: Some(tx),
    }
    .run(&input[..], &mut out, None)
    .await
    .expect("relais");

    assert!(out.is_empty(), "rien ne doit atteindre l'amont");
    let payload = rx.recv().await.expect("réponse de blocage attendue");
    let v: serde_json::Value = serde_json::from_slice(payload.trim_ascii_end()).expect("json");
    assert_eq!(v["result"]["isError"], true);
    assert!(
        v["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("fail_closed")
    );
}

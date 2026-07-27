//! Tests de sémantique MCP.
//!
//! Deux obsessions : le scan de méthode ne doit jamais se tromper de clé, et
//! `initialize` ne doit jamais pouvoir être bloqué.

use mcpwall::mcp::{
    AllowAll, CallContext, ClientHello, DecisionPoint, Disposition, METHOD_SCAN_WINDOW, MethodScan,
    ServerHello, classify, disposition, parse_client_hello, parse_server_hello, scan_method,
};

fn found(frame: &[u8]) -> (String, bool) {
    match scan_method(frame) {
        MethodScan::Found { method, full_scan } => (method, full_scan),
        other => panic!("méthode attendue, obtenu {other:?}"),
    }
}

// --- Scan de méthode : cas nominaux ---

#[test]
fn methode_en_tete_de_frame() {
    let (m, full) = found(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#);
    assert_eq!(m, "tools/call");
    assert!(!full, "doit tenir dans la fenêtre");
}

#[test]
fn notification_sans_id() {
    let (m, _) = found(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert_eq!(m, "notifications/initialized");
}

#[test]
fn reponse_sans_methode() {
    let frame = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;
    assert_eq!(scan_method(frame), MethodScan::NoMethod);
    assert_eq!(classify(&MethodScan::NoMethod), Disposition::Passthrough);
}

#[test]
fn espaces_autour_des_deux_points() {
    let (m, _) = found(br#"{ "method" : "tools/call" , "id" : 1 }"#);
    assert_eq!(m, "tools/call");
}

// --- Scan de méthode : les pièges ---

#[test]
fn clef_method_imbriquee_ignoree() {
    // Une recherche de sous-chaîne naïve rendrait "x". Le suivi de profondeur
    // impose que `method` soit une clé de l'objet racine.
    let (m, _) = found(br#"{"params":{"method":"x"},"method":"tools/call","id":1}"#);
    assert_eq!(m, "tools/call");
}

#[test]
fn method_en_valeur_et_non_en_clef() {
    // Ici "method" apparaît comme *valeur* de "kind". Ne doit pas être retenu.
    let (m, _) = found(br#"{"kind":"method","method":"resources/read","id":1}"#);
    assert_eq!(m, "resources/read");
}

#[test]
fn method_uniquement_en_valeur_ne_donne_rien() {
    assert_eq!(
        scan_method(br#"{"kind":"method","id":1,"result":{}}"#),
        MethodScan::NoMethod
    );
}

#[test]
fn accolade_dans_une_chaine_ne_fausse_pas_la_profondeur() {
    let (m, _) = found(br#"{"id":"a{b}c","method":"tools/call"}"#);
    assert_eq!(m, "tools/call");
}

// --- Évasion de classement par échappement ---

#[test]
fn guillemet_echappe_avant_method_ne_masque_pas_la_methode() {
    // Le piège : un scan qui renonce sur le premier `\` classerait ça en
    // Unparsable, donc Observe, donc hors du point de décision. Un `id` bien
    // choisi suffirait à contourner la politique.
    let (m, _) = found(br#"{"id":"a\"b","method":"tools/call"}"#);
    assert_eq!(m, "tools/call");
    assert_eq!(
        classify(&scan_method(br#"{"id":"a\"b","method":"tools/call"}"#)),
        Disposition::Decide
    );
}

#[test]
fn accolade_echappee_ne_fausse_pas_la_profondeur() {
    let (m, _) = found(br#"{"id":"a\\","method":"resources/read"}"#);
    assert_eq!(m, "resources/read");
}

#[test]
fn faux_method_echappe_dans_une_valeur_ne_trompe_pas() {
    // `"method"` apparaît, échappé, à l'intérieur d'une valeur de chaîne.
    let (m, _) = found(br#"{"id":"x \"method\":\"evil\" y","method":"tools/call"}"#);
    assert_eq!(m, "tools/call");
}

#[test]
fn methode_avec_echappement_refuse_le_point_de_decision() {
    // On ne décode pas les échappements ; on refuse donc de conclure plutôt que
    // de deviner. Observe, jamais Decide.
    let scan = scan_method(br#"{"method":"tools\/call","id":1}"#);
    assert_eq!(scan, MethodScan::Unparsable);
    assert_eq!(classify(&scan), Disposition::Observe);
}

#[test]
fn method_non_textuelle_est_unparsable() {
    assert_eq!(
        scan_method(br#"{"method":42,"id":1}"#),
        MethodScan::Unparsable
    );
}

#[test]
fn frame_tronquee_est_unparsable_pas_nomethod() {
    // Le silence est interdit : une frame coupée ne doit pas se faire passer
    // pour une réponse légitime sans méthode.
    assert_eq!(
        scan_method(br#"{"jsonrpc":"2.0","id":1,"meth"#),
        MethodScan::Unparsable
    );
    assert_eq!(
        scan_method(br#"{"method":"tools/ca"#),
        MethodScan::Unparsable
    );
}

#[test]
fn tableau_batch_ne_donne_pas_de_methode() {
    // Le batch est retiré de la spec depuis 2025-06-18 ; on ne le traite pas
    // ici, on refuse juste d'en extraire une méthode.
    assert_eq!(
        scan_method(br#"[{"method":"tools/call","id":1}]"#),
        MethodScan::NoMethod
    );
}

// --- Le repli hors fenêtre ---

#[test]
fn method_repoussee_hors_fenetre_par_un_id_long() {
    let id = "z".repeat(METHOD_SCAN_WINDOW * 2);
    let frame = format!(r#"{{"jsonrpc":"2.0","id":"{id}","method":"tools/call"}}"#);

    let (m, full) = found(frame.as_bytes());
    assert_eq!(m, "tools/call");
    assert!(full, "le repli sur passe complète doit être signalé");
}

#[test]
fn method_repoussee_par_params_serialise_en_premier() {
    let blob = "a".repeat(METHOD_SCAN_WINDOW * 4);
    let frame = format!(r#"{{"params":{{"text":"{blob}"}},"method":"resources/read","id":1}}"#);

    let (m, full) = found(frame.as_bytes());
    assert_eq!(m, "resources/read");
    assert!(full);
}

#[test]
fn grosse_frame_sans_methode_reste_nomethod() {
    let blob = "b".repeat(METHOD_SCAN_WINDOW * 4);
    let frame = format!(r#"{{"id":1,"result":{{"text":"{blob}"}}}}"#);
    assert_eq!(scan_method(frame.as_bytes()), MethodScan::NoMethod);
}

// --- Classement ---

#[test]
fn ensemble_decide() {
    for m in [
        "tools/call",
        "resources/read",
        "sampling/createMessage",
        "elicitation/create",
    ] {
        assert_eq!(disposition(m), Disposition::Decide, "{m}");
    }
}

#[test]
fn initialize_is_never_decidable() {
    // La garde qui compte. Bloquer `initialize` ne protège de rien et tue la
    // session entière. Ce test existe pour qu'un futur déplacement d'`initialize`
    // vers l'ensemble DECIDE casse la CI plutôt que les sessions des gens.
    for m in ["initialize", "notifications/initialized"] {
        assert_eq!(disposition(m), Disposition::Observe, "{m}");
        assert_ne!(disposition(m), Disposition::Decide);
    }
}

#[test]
fn le_trafic_roots_est_observe() {
    // Ces deux-là alimentent et invalident le maillon 2 du scope. Les laisser en
    // passthrough ferait rater les changements de racines en cours de session.
    for m in ["roots/list", "notifications/roots/list_changed"] {
        assert_eq!(disposition(m), Disposition::Observe, "{m}");
    }
}

#[test]
fn methode_inconnue_passe_en_passthrough() {
    assert_eq!(disposition("completion/complete"), Disposition::Passthrough);
    assert_eq!(disposition("ping"), Disposition::Passthrough);
}

#[test]
fn unparsable_retombe_sur_observe_jamais_sur_decide() {
    let d = classify(&MethodScan::Unparsable);
    assert_eq!(d, Disposition::Observe);
    assert_ne!(d, Disposition::Decide);
}

#[test]
fn classement_de_bout_en_bout() {
    let frame = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
    assert_eq!(classify(&scan_method(frame)), Disposition::Decide);
}

// --- Point de décision ---

#[test]
fn m0_autorise_tout() {
    let ctx = CallContext {
        method: "tools/call",
        frame: b"{}",
    };
    assert_eq!(
        AllowAll.decide(&ctx).expect("AllowAll ne peut pas échouer"),
        mcpwall::mcp::Verdict::Allow
    );
}

// --- Capture de l'initialize ---

#[test]
fn capture_du_hello_client() {
    // Forme tirée de la spec 2025-11-25, basic/lifecycle.
    let frame = br#"{
      "jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{
        "protocolVersion":"2025-11-25",
        "capabilities":{"roots":{"listChanged":true},"sampling":{}},
        "clientInfo":{"name":"ExampleClient","title":"Example","version":"1.0.0"}
      }
    }"#;

    assert_eq!(
        parse_client_hello(frame).unwrap(),
        ClientHello {
            requested_protocol_version: Some("2025-11-25".into()),
            client_name: Some("ExampleClient".into()),
            client_version: Some("1.0.0".into()),
            supports_roots: true,
            roots_list_changed: true,
        }
    );
}

#[test]
fn client_sans_capacite_roots() {
    let frame = br#"{"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2025-11-25","capabilities":{},
      "clientInfo":{"name":"C","version":"1"}}}"#;
    let hello = parse_client_hello(frame).unwrap();
    assert!(!hello.supports_roots, "maillon 2 du scope indisponible");
    assert!(!hello.roots_list_changed);
}

#[test]
fn capture_du_hello_serveur() {
    let frame = br#"{
      "jsonrpc":"2.0","id":1,
      "result":{
        "protocolVersion":"2025-11-25",
        "capabilities":{"tools":{"listChanged":true},"resources":{},"logging":{}},
        "serverInfo":{"name":"ExampleServer","version":"1.0.0"},
        "instructions":"..."
      }
    }"#;

    assert_eq!(
        parse_server_hello(frame).unwrap(),
        ServerHello {
            protocol_version: Some("2025-11-25".into()),
            server_name: Some("ExampleServer".into()),
            server_version: Some("1.0.0".into()),
            capabilities: vec!["logging".into(), "resources".into(), "tools".into()],
        }
    );
}

#[test]
fn la_version_negociee_vient_de_la_reponse_serveur() {
    // Le serveur ne supporte pas ce que le client demande et répond avec une
    // autre version. C'est celle-là qu'on stocke.
    let req = br#"{"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2025-11-25","capabilities":{},
      "clientInfo":{"name":"C","version":"1"}}}"#;
    let resp = br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",
      "capabilities":{},"serverInfo":{"name":"S","version":"1"}}}"#;

    assert_eq!(
        parse_client_hello(req).unwrap().requested_protocol_version,
        Some("2025-11-25".into())
    );
    assert_eq!(
        parse_server_hello(resp).unwrap().protocol_version,
        Some("2025-06-18".into())
    );
}

#[test]
fn hello_serveur_en_erreur_nest_pas_un_hello() {
    let frame = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,
      "message":"Unsupported protocol version"}}"#;
    assert!(parse_server_hello(frame).is_none());
}

#[test]
fn hello_sur_json_invalide_ne_panique_pas() {
    assert!(parse_client_hello(b"{ pas du json").is_none());
    assert!(parse_server_hello(b"").is_none());
}

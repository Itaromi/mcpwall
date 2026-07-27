//! Tests de découpage. Priorité aux frontières de lecture et aux serveurs qui
//! violent la spec, c'est là que se trouvent les vrais casse-gueule.

use mcpwall::frame::{FrameError, FrameSplitter};

/// Pousse tout d'un bloc et draine. Rend les *contenus*.
fn split_all(input: &[u8], max: usize) -> (Vec<Vec<u8>>, Vec<FrameError>) {
    let mut s = FrameSplitter::new(max);
    s.push(input);
    drain(&mut s)
}

fn drain(s: &mut FrameSplitter) -> (Vec<Vec<u8>>, Vec<FrameError>) {
    let (mut ok, mut err) = (Vec::new(), Vec::new());
    while let Some(r) = s.next_frame() {
        match r {
            Ok(f) => ok.push(f.content().to_vec()),
            Err(e) => err.push(e),
        }
    }
    (ok, err)
}

/// Concatène ce que le relais réémettrait.
fn relayed(input: &[u8], max: usize) -> Vec<u8> {
    let mut s = FrameSplitter::new(max);
    s.push(input);
    let mut out = Vec::new();
    while let Some(Ok(f)) = s.next_frame() {
        out.extend_from_slice(f.raw());
    }
    if let Some(f) = s.finish() {
        out.extend_from_slice(f.raw());
    }
    out
}

const MAX: usize = 1024;

#[test]
fn frames_simples() {
    let (frames, errs) = split_all(b"{\"a\":1}\n{\"b\":2}\n", MAX);
    assert_eq!(frames, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
    assert!(errs.is_empty());
}

#[test]
fn frame_incomplete_pas_rendue() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}");
    assert!(s.next_frame().is_none());
    s.push(b"\n");
    assert_eq!(s.next_frame().unwrap().unwrap().content(), b"{\"a\":1}");
}

// --- Frontières de lecture ---

#[test]
fn une_frame_en_quarante_morceaux() {
    let msg = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
    let mut s = FrameSplitter::new(MAX);

    let chunk = msg.len().div_ceil(40);
    for piece in msg.chunks(chunk) {
        s.push(piece);
        assert!(s.next_frame().is_none(), "rien ne doit sortir avant le \\n");
    }
    s.push(b"\n");

    let (frames, errs) = drain(&mut s);
    assert_eq!(frames, vec![msg.to_vec()]);
    assert!(errs.is_empty());
}

#[test]
fn six_frames_dans_un_seul_read() {
    let mut input = Vec::new();
    for i in 0..6 {
        input.extend_from_slice(format!("{{\"id\":{i}}}\n").as_bytes());
    }
    let (frames, _) = split_all(&input, MAX);
    assert_eq!(frames.len(), 6);
    assert_eq!(frames[5], b"{\"id\":5}");
}

#[test]
fn frontiere_au_milieu_dune_sequence_utf8() {
    // « é » = 0xC3 0xA9, coupé entre les deux octets. Le découpeur ne convertit
    // jamais en String, donc ça doit passer sans même être remarqué.
    let msg = "{\"text\":\"café ☕\"}".as_bytes().to_vec();
    let cut = msg.iter().position(|&b| b == 0xC3).unwrap() + 1;

    let mut s = FrameSplitter::new(MAX);
    s.push(&msg[..cut]);
    assert!(s.next_frame().is_none());
    s.push(&msg[cut..]);
    s.push(b"\n");

    assert_eq!(s.next_frame().unwrap().unwrap().content(), msg);
}

#[test]
fn coupure_juste_avant_le_terminateur() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}");
    assert!(s.next_frame().is_none());
    s.push(b"\n{\"b\":2}\n");
    let (frames, _) = drain(&mut s);
    assert_eq!(frames, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
}

#[test]
fn octets_arrivant_un_par_un() {
    let input = b"{\"a\":1}\n{\"b\":2}\n";
    let mut s = FrameSplitter::new(MAX);
    let mut frames = Vec::new();
    for b in input {
        s.push(&[*b]);
        while let Some(Ok(f)) = s.next_frame() {
            frames.push(f.content().to_vec());
        }
    }
    assert_eq!(frames, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
}

// --- Serveurs qui violent la spec ---

#[test]
fn lignes_vides_ignorees_et_comptees() {
    let (frames, _) = split_all(b"\n\n{\"a\":1}\n\n", MAX);
    assert_eq!(frames, vec![b"{\"a\":1}".to_vec()]);

    let mut s = FrameSplitter::new(MAX);
    s.push(b"\n\n{\"a\":1}\n\n");
    drain(&mut s);
    assert_eq!(s.stats().empty_skipped, 3);
    assert_eq!(s.stats().frames, 1);
}

#[test]
fn crlf_tolere_et_compte() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\r\n");
    assert_eq!(s.next_frame().unwrap().unwrap().content(), b"{\"a\":1}");
    assert_eq!(s.stats().crlf, 1);
}

#[test]
fn frame_non_terminee_en_fin_de_flux() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\n{\"b\":2}");
    assert_eq!(s.next_frame().unwrap().unwrap().content(), b"{\"a\":1}");
    assert!(s.next_frame().is_none());
    assert_eq!(s.finish().unwrap().content(), b"{\"b\":2}");
    assert_eq!(s.stats().unterminated, 1);
    assert_eq!(s.stats().frames, 2);
}

#[test]
fn finish_sur_flux_propre_ne_rend_rien() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\n");
    drain(&mut s);
    assert!(s.finish().is_none());
}

// --- Plafond de taille ---

#[test]
fn oversize_signale_puis_resynchronisation() {
    let mut s = FrameSplitter::new(64);
    s.push(&[b'x'; 200]);

    assert_eq!(
        s.next_frame(),
        Some(Err(FrameError::Oversize { limit: 64 })),
        "l'erreur doit être signalée une fois, pas à chaque push"
    );
    assert!(s.next_frame().is_none());

    // Encore des octets de la frame géante : toujours rien, et pas de seconde
    // erreur pour le même incident.
    s.push(&[b'x'; 500]);
    assert!(s.next_frame().is_none());

    // Le terminateur clôt la frame rejetée ; la suivante repart intacte.
    s.push(b"\n{\"a\":1}\n");
    assert_eq!(s.next_frame().unwrap().unwrap().content(), b"{\"a\":1}");

    let st = s.stats();
    assert_eq!(st.oversize, 1);
    assert_eq!(st.frames, 1);
    assert_eq!(st.bytes_discarded, 700);
}

#[test]
fn oversize_ne_fait_pas_croitre_le_tampon() {
    let mut s = FrameSplitter::new(1024);
    for _ in 0..64 {
        s.push(&[b'x'; 4096]);
        let _ = s.next_frame();
    }
    // 256 Ko poussés derrière un plafond de 1 Ko : en mode rejet le tampon doit
    // rester au ras du dernier push, pas accumuler.
    assert!(
        s.buffered() <= 4096,
        "tampon retenu = {} octets",
        s.buffered()
    );
}

#[test]
fn frame_juste_sous_le_plafond_passe() {
    let payload = vec![b'x'; 1024];
    let mut input = payload.clone();
    input.push(b'\n');
    let (frames, errs) = split_all(&input, 1024);
    assert_eq!(frames, vec![payload]);
    assert!(errs.is_empty());
}

#[test]
fn charge_utile_de_plusieurs_megaoctets() {
    let payload = vec![b'z'; 8 * 1024 * 1024];
    let mut s = FrameSplitter::new(32 * 1024 * 1024);
    for piece in payload.chunks(64 * 1024) {
        s.push(piece);
        assert!(s.next_frame().is_none());
    }
    s.push(b"\n");
    assert_eq!(s.next_frame().unwrap().unwrap().len(), payload.len());
}

// --- Invariant global ---

#[test]
fn le_decoupage_ne_depend_pas_de_la_taille_des_morceaux() {
    let input: &[u8] = b"{\"a\":1}\n\n{\"b\":\"caf\xc3\xa9\"}\r\n{\"c\":3}\n";
    let reference = split_all(input, MAX).0;

    for size in [1, 2, 3, 5, 7, 11, 13, 17, 64] {
        let mut s = FrameSplitter::new(MAX);
        let mut frames = Vec::new();
        for piece in input.chunks(size) {
            s.push(piece);
            while let Some(Ok(f)) = s.next_frame() {
                frames.push(f.content().to_vec());
            }
        }
        if let Some(f) = s.finish() {
            frames.push(f.content().to_vec());
        }
        assert_eq!(frames, reference, "divergence avec des morceaux de {size}");
    }
}

// --- Fidélité octet à octet du relais ---

#[test]
fn le_relais_reemet_les_octets_recus() {
    // Le principe : on ne réécrit jamais ce qu'on relaie. Terminateurs compris.
    let input: &[u8] = b"{\"a\":1}\n{\"b\":2}\r\n{\"c\":3}\n";
    assert_eq!(relayed(input, MAX), input);
}

#[test]
fn crlf_preserve_dans_raw_mais_absent_du_contenu() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\r\n");
    let f = s.next_frame().unwrap().unwrap();
    assert_eq!(f.content(), b"{\"a\":1}", "l'inspection ignore le \\r");
    assert_eq!(f.raw(), b"{\"a\":1}\r\n", "le relais le conserve");
    assert!(f.is_terminated());
}

#[test]
fn contenu_est_un_prefixe_de_raw() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\r\n{\"b\":2}\n");
    while let Some(Ok(f)) = s.next_frame() {
        assert_eq!(f.content(), &f.raw()[..f.len()]);
    }
}

#[test]
fn frame_non_terminee_signale_labsence_de_delimiteur() {
    // Le relais doit savoir qu'il lui manque un `\n` : le pair attend un
    // message délimité.
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}");
    assert!(s.next_frame().is_none());
    let f = s.finish().unwrap();
    assert_eq!(f.content(), b"{\"a\":1}");
    assert_eq!(f.raw(), b"{\"a\":1}");
    assert!(!f.is_terminated());
}

#[test]
fn ligne_vide_absente_du_relais() {
    // Une ligne vide n'est pas un message MCP et la spec interdit à l'amont
    // d'en écrire sur stdout. On ne la propage pas ; le compteur la retient.
    let mut s = FrameSplitter::new(MAX);
    s.push(b"\n{\"a\":1}\n");
    assert_eq!(relayed(b"\n{\"a\":1}\n", MAX), b"{\"a\":1}\n");
}

#[test]
fn octets_de_la_frame_surdimensionnee_jamais_relayes() {
    // Le pair ne doit rien voir de ce qu'on a rejeté.
    let mut input = vec![b'x'; 200];
    input.extend_from_slice(b"\n{\"a\":1}\n");
    assert_eq!(relayed(&input, 64), b"{\"a\":1}\n");
}

#[test]
fn le_plafond_ne_depend_pas_du_decoupage_des_lectures() {
    // Le défaut originel : le plafond n'était vérifié que faute de `\n`. Une
    // frame surdimensionnée arrivant d'un seul read(), terminateur compris,
    // passait donc au travers.
    let mut input = vec![b'x'; 200];
    input.push(b'\n');

    for size in [1, 7, 64, 201, 512] {
        let mut s = FrameSplitter::new(64);
        let (mut frames, mut errs) = (Vec::new(), Vec::new());
        for piece in input.chunks(size) {
            s.push(piece);
            while let Some(r) = s.next_frame() {
                match r {
                    Ok(f) => frames.push(f.content().to_vec()),
                    Err(e) => errs.push(e),
                }
            }
        }
        assert!(
            frames.is_empty(),
            "frame relayée malgré le plafond ({size})"
        );
        assert_eq!(errs.len(), 1, "une erreur, et une seule ({size})");
        assert_eq!(s.stats().oversize, 1);
    }
}

#[test]
fn plafond_applique_aussi_en_fin_de_flux() {
    let mut s = FrameSplitter::new(64);
    s.push(&[b'x'; 200]);
    let _ = s.next_frame();
    assert!(s.finish().is_none(), "rien ne doit sortir par finish()");
}

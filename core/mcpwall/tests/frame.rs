//! Frame splitting tests. Priority to read boundaries and to servers that
//! violate the spec — that is where the real pitfalls are.

use mcpwall::frame::{FrameError, FrameSplitter};

/// Pushes everything at once and drains. Returns the *contents*.
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

/// Concatenates what the relay would re-emit.
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
fn simple_frames() {
    let (frames, errs) = split_all(b"{\"a\":1}\n{\"b\":2}\n", MAX);
    assert_eq!(frames, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
    assert!(errs.is_empty());
}

#[test]
fn an_incomplete_frame_is_not_returned() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}");
    assert!(s.next_frame().is_none());
    s.push(b"\n");
    assert_eq!(s.next_frame().unwrap().unwrap().content(), b"{\"a\":1}");
}

// --- Read boundaries ---

#[test]
fn one_frame_in_forty_chunks() {
    let msg = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
    let mut s = FrameSplitter::new(MAX);

    let chunk = msg.len().div_ceil(40);
    for piece in msg.chunks(chunk) {
        s.push(piece);
        assert!(
            s.next_frame().is_none(),
            "nothing may come out before the \\n"
        );
    }
    s.push(b"\n");

    let (frames, errs) = drain(&mut s);
    assert_eq!(frames, vec![msg.to_vec()]);
    assert!(errs.is_empty());
}

#[test]
fn six_frames_in_a_single_read() {
    let mut input = Vec::new();
    for i in 0..6 {
        input.extend_from_slice(format!("{{\"id\":{i}}}\n").as_bytes());
    }
    let (frames, _) = split_all(&input, MAX);
    assert_eq!(frames.len(), 6);
    assert_eq!(frames[5], b"{\"id\":5}");
}

#[test]
fn a_boundary_in_the_middle_of_a_utf8_sequence() {
    // "é" = 0xC3 0xA9, cut between the two bytes. The splitter never converts
    // to String, so this must go through without even being noticed.
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
fn a_cut_just_before_the_terminator() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}");
    assert!(s.next_frame().is_none());
    s.push(b"\n{\"b\":2}\n");
    let (frames, _) = drain(&mut s);
    assert_eq!(frames, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
}

#[test]
fn bytes_arriving_one_at_a_time() {
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

// --- Servers that violate the spec ---

#[test]
fn blank_lines_skipped_and_counted() {
    let (frames, _) = split_all(b"\n\n{\"a\":1}\n\n", MAX);
    assert_eq!(frames, vec![b"{\"a\":1}".to_vec()]);

    let mut s = FrameSplitter::new(MAX);
    s.push(b"\n\n{\"a\":1}\n\n");
    drain(&mut s);
    assert_eq!(s.stats().empty_skipped, 3);
    assert_eq!(s.stats().frames, 1);
}

#[test]
fn crlf_tolerated_and_counted() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\r\n");
    assert_eq!(s.next_frame().unwrap().unwrap().content(), b"{\"a\":1}");
    assert_eq!(s.stats().crlf, 1);
}

#[test]
fn an_unterminated_frame_at_end_of_stream() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\n{\"b\":2}");
    assert_eq!(s.next_frame().unwrap().unwrap().content(), b"{\"a\":1}");
    assert!(s.next_frame().is_none());
    assert_eq!(s.finish().unwrap().content(), b"{\"b\":2}");
    assert_eq!(s.stats().unterminated, 1);
    assert_eq!(s.stats().frames, 2);
}

#[test]
fn finish_on_a_clean_stream_returns_nothing() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\n");
    drain(&mut s);
    assert!(s.finish().is_none());
}

// --- Size ceiling ---

#[test]
fn oversize_reported_then_resynchronisation() {
    let mut s = FrameSplitter::new(64);
    s.push(&[b'x'; 200]);

    assert_eq!(
        s.next_frame(),
        Some(Err(FrameError::Oversize { limit: 64 })),
        "the error must be reported once, not on every push"
    );
    assert!(s.next_frame().is_none());

    // More bytes from the giant frame: still nothing, and no second error for
    // the same incident.
    s.push(&[b'x'; 500]);
    assert!(s.next_frame().is_none());

    // The terminator closes the rejected frame; the next one starts intact.
    s.push(b"\n{\"a\":1}\n");
    assert_eq!(s.next_frame().unwrap().unwrap().content(), b"{\"a\":1}");

    let st = s.stats();
    assert_eq!(st.oversize, 1);
    assert_eq!(st.frames, 1);
    assert_eq!(st.bytes_discarded, 700);
}

#[test]
fn oversize_does_not_grow_the_buffer() {
    let mut s = FrameSplitter::new(1024);
    for _ in 0..64 {
        s.push(&[b'x'; 4096]);
        let _ = s.next_frame();
    }
    // 256 KB pushed behind a 1 KB ceiling: in discard mode the buffer must
    // stay level with the last push, not accumulate.
    assert!(s.buffered() <= 4096, "buffered = {} bytes", s.buffered());
}

#[test]
fn a_frame_just_under_the_ceiling_goes_through() {
    let payload = vec![b'x'; 1024];
    let mut input = payload.clone();
    input.push(b'\n');
    let (frames, errs) = split_all(&input, 1024);
    assert_eq!(frames, vec![payload]);
    assert!(errs.is_empty());
}

#[test]
fn a_multi_megabyte_payload() {
    let payload = vec![b'z'; 8 * 1024 * 1024];
    let mut s = FrameSplitter::new(32 * 1024 * 1024);
    for piece in payload.chunks(64 * 1024) {
        s.push(piece);
        assert!(s.next_frame().is_none());
    }
    s.push(b"\n");
    assert_eq!(s.next_frame().unwrap().unwrap().len(), payload.len());
}

// --- Global invariant ---

#[test]
fn splitting_does_not_depend_on_chunk_size() {
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
        assert_eq!(frames, reference, "divergence with chunks of {size}");
    }
}

// --- Byte-for-byte fidelity of the relay ---

#[test]
fn the_relay_re_emits_the_bytes_it_received() {
    // The principle: we never rewrite what we relay. Terminators included.
    let input: &[u8] = b"{\"a\":1}\n{\"b\":2}\r\n{\"c\":3}\n";
    assert_eq!(relayed(input, MAX), input);
}

#[test]
fn crlf_preserved_in_raw_but_absent_from_content() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\r\n");
    let f = s.next_frame().unwrap().unwrap();
    assert_eq!(f.content(), b"{\"a\":1}", "inspection ignores the \\r");
    assert_eq!(f.raw(), b"{\"a\":1}\r\n", "the relay keeps it");
    assert!(f.is_terminated());
}

#[test]
fn content_is_a_prefix_of_raw() {
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}\r\n{\"b\":2}\n");
    while let Some(Ok(f)) = s.next_frame() {
        assert_eq!(f.content(), &f.raw()[..f.len()]);
    }
}

#[test]
fn an_unterminated_frame_reports_the_missing_delimiter() {
    // The relay must know it is missing a `\n`: the peer expects a delimited
    // message.
    let mut s = FrameSplitter::new(MAX);
    s.push(b"{\"a\":1}");
    assert!(s.next_frame().is_none());
    let f = s.finish().unwrap();
    assert_eq!(f.content(), b"{\"a\":1}");
    assert_eq!(f.raw(), b"{\"a\":1}");
    assert!(!f.is_terminated());
}

#[test]
fn a_blank_line_is_absent_from_the_relay() {
    // A blank line is not an MCP message and the spec forbids the upstream from
    // writing one to stdout. We do not propagate it; the counter records it.
    let mut s = FrameSplitter::new(MAX);
    s.push(b"\n{\"a\":1}\n");
    assert_eq!(relayed(b"\n{\"a\":1}\n", MAX), b"{\"a\":1}\n");
}

#[test]
fn bytes_from_the_oversized_frame_are_never_relayed() {
    // The peer must see nothing of what we discarded.
    let mut input = vec![b'x'; 200];
    input.extend_from_slice(b"\n{\"a\":1}\n");
    assert_eq!(relayed(&input, 64), b"{\"a\":1}\n");
}

#[test]
fn the_ceiling_does_not_depend_on_how_reads_are_split() {
    // The original defect: the ceiling was only checked when no `\n` was found.
    // An oversized frame arriving from a single read(), terminator included,
    // therefore slipped through.
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
            "frame relayed despite the ceiling ({size})"
        );
        assert_eq!(errs.len(), 1, "one error, and only one ({size})");
        assert_eq!(s.stats().oversize, 1);
    }
}

#[test]
fn the_ceiling_applies_at_end_of_stream_too() {
    let mut s = FrameSplitter::new(64);
    s.push(&[b'x'; 200]);
    let _ = s.next_frame();
    assert!(s.finish().is_none(), "nothing may come out of finish()");
}

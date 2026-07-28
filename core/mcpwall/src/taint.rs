//! Taint tracking: recognising local data on its way out.
//!
//! §6 of the spec. What a local read returned is fingerprinted and kept in
//! memory; before an outbound call leaves, its arguments are fingerprinted the
//! same way and the two are compared. An overlap means data that came from the
//! machine is about to leave it.
//!
//! I/O-free on purpose, like `frame`, `mcp` and `scope`: it stays fuzzable
//! without a runtime, and `now` is a parameter rather than a clock read, so the
//! TTL is testable without sleeping.
//!
//! **The content itself is never stored.** Only 64-bit fingerprints. The store
//! can therefore say "this went out" but can never give back what did — which
//! is the only acceptable posture for a component that, by construction, sees
//! every secret the agent reads.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Words per shingle. Long enough that ordinary prose shared between a read and
/// a call does not collide, short enough to survive an agent reformatting what
/// it exfiltrates.
pub const SHINGLE_WORDS: usize = 8;

/// How long a read stays suspect. Beyond that, the link between the read and
/// the call is too weak to hold anyone to it.
pub const TTL: Duration = Duration::from_secs(600);

/// Shingles that must coincide before we call it an overlap.
///
/// The spec is explicit: a false negative is acceptable, a noisy false positive
/// is not. Two consecutive 8-word shingles in common is already 9 identical
/// words in the same order.
pub const MIN_NGRAM_OVERLAP: usize = 2;

/// Below this, a lone token is not distinctive enough to be evidence on its
/// own. Above it, we are looking at a key, a token or a private key line —
/// things that do not appear twice by chance.
pub const MIN_TOKEN_LEN: usize = 24;

/// FNV-1a, 64-bit.
///
/// Deliberately **not** `DefaultHasher`: fingerprints are computed in the shim
/// and compared in the daemon, two different processes. `RandomState` is seeded
/// per process, so the same text would hash differently on each side and
/// nothing would ever match.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// What a piece of text reduces to. Two independent kinds of evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprint {
    /// Hashes of `SHINGLE_WORDS`-word sliding windows. Catches prose, file
    /// contents, anything with structure.
    pub ngrams: Vec<u64>,
    /// Hashes of individual long tokens. Catches what shingles cannot: an API
    /// key is one word, and a one-word secret produces no 8-word window. This
    /// goes beyond the letter of the spec, which describes shingles only — but
    /// a lone credential is precisely the payload worth exfiltrating.
    pub tokens: Vec<u64>,
}

/// Ceiling on the n-grams carried for one read.
///
/// A multi-megabyte file would otherwise produce hundreds of thousands of
/// hashes to serialise and send on the shim's hot path. Tokens are never
/// capped: they are few, and they are the evidence that matters.
pub const MAX_NGRAMS: usize = 4000;

impl Fingerprint {
    pub fn is_empty(&self) -> bool {
        self.ngrams.is_empty() && self.tokens.is_empty()
    }

    /// Caps the n-grams, keeping every token.
    ///
    /// Truncating rather than sampling: two n-gram hits must be findable, and
    /// sampling would break exactly the consecutive runs the threshold looks
    /// for. Losing the tail of a very large read is a false negative, which the
    /// spec accepts.
    pub fn capped(mut self) -> Self {
        self.ngrams.truncate(MAX_NGRAMS);
        self
    }
}

/// Splits on everything that binds a secret to its surroundings, so the same
/// value hashes identically wherever it is found.
///
/// Whitespace alone is not enough: in a `.env`, `STRIPE_KEY=sk_live_…` is a
/// single word, and the agent exfiltrates only the part after the `=`. So `=`,
/// `:`, `@`, quotes, commas and brackets all cut.
///
/// `+`, `/`, `.`, `-` and `_` are kept inside tokens: they are part of base64
/// bodies, of JWTs and of key names, and cutting on them would shred a private
/// key into fragments too short to be evidence.
fn candidate_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '+' || c == '/')
    })
    .filter(|t| !t.is_empty())
}

/// Reduces text to its fingerprint.
pub fn fingerprint(text: &str) -> Fingerprint {
    let words: Vec<&str> = text.split_whitespace().collect();

    let mut tokens = Vec::new();
    for t in candidate_tokens(text) {
        if t.len() >= MIN_TOKEN_LEN {
            tokens.push(fnv1a(t.as_bytes()));
        }
    }
    tokens.sort_unstable();
    tokens.dedup();

    let mut ngrams = Vec::new();
    if words.len() >= SHINGLE_WORDS {
        for window in words.windows(SHINGLE_WORDS) {
            ngrams.push(fnv1a(window.join(" ").as_bytes()));
        }
    }
    ngrams.sort_unstable();
    ngrams.dedup();

    Fingerprint { ngrams, tokens }
}

/// Where a tainted fingerprint came from, to be able to say so to the user.
#[derive(Debug, Clone)]
pub struct Origin {
    /// What was read — a path, a tool name. Shown in the prompt and journalled.
    pub label: String,
    pub at: Instant,
}

/// An overlap found between an outbound argument and an earlier read.
#[derive(Debug, Clone)]
pub struct Match {
    pub origin: String,
    /// How many pieces of evidence coincided. Reported so a user facing a
    /// refusal can judge how firm it is.
    pub strength: usize,
}

/// Fingerprints of recent local reads.
#[derive(Debug, Default)]
pub struct TaintStore {
    ngrams: HashMap<u64, Origin>,
    tokens: HashMap<u64, Origin>,
}

impl TaintStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what a local read returned.
    pub fn record(&mut self, fp: &Fingerprint, label: &str, now: Instant) {
        self.prune(now);
        for h in &fp.ngrams {
            self.ngrams.insert(
                *h,
                Origin {
                    label: label.to_owned(),
                    at: now,
                },
            );
        }
        for h in &fp.tokens {
            self.tokens.insert(
                *h,
                Origin {
                    label: label.to_owned(),
                    at: now,
                },
            );
        }
    }

    /// Looks for local data in what is about to leave.
    ///
    /// A single long token is enough; ordinary shingles need
    /// [`MIN_NGRAM_OVERLAP`] of them.
    pub fn overlap(&self, fp: &Fingerprint, now: Instant) -> Option<Match> {
        let fresh = |o: &Origin| now.duration_since(o.at) < TTL;

        for h in &fp.tokens {
            if let Some(o) = self.tokens.get(h).filter(|o| fresh(o)) {
                return Some(Match {
                    origin: o.label.clone(),
                    strength: usize::MAX,
                });
            }
        }

        let mut hits = 0usize;
        let mut origin = None;
        for h in &fp.ngrams {
            if let Some(o) = self.ngrams.get(h).filter(|o| fresh(o)) {
                hits += 1;
                origin.get_or_insert_with(|| o.label.clone());
            }
        }

        if hits >= MIN_NGRAM_OVERLAP {
            return Some(Match {
                origin: origin.unwrap_or_default(),
                strength: hits,
            });
        }
        None
    }

    /// Drops what has aged out. Called on write so the store cannot grow
    /// without bound in a long session.
    pub fn prune(&mut self, now: Instant) {
        self.ngrams.retain(|_, o| now.duration_since(o.at) < TTL);
        self.tokens.retain(|_, o| now.duration_since(o.at) < TTL);
    }

    pub fn len(&self) -> usize {
        self.ngrams.len() + self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Does this tool name look like a local read whose result must be tracked?
///
/// Spec §6: `resources/read`, or a tool whose name matches `*read*`, `*file*`
/// or `*exec*`.
pub fn is_local_read(method: &str, tool: Option<&str>) -> bool {
    if method == "resources/read" {
        return true;
    }
    let Some(t) = tool else {
        return false;
    };
    let t = t.to_ascii_lowercase();
    t.contains("read") || t.contains("file") || t.contains("exec")
}

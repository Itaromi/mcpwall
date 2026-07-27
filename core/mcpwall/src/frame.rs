//! Découpage de frames MCP stdio.
//!
//! La spec MCP (révision 2025-11-25, `basic/transports`) impose : « Messages are
//! delimited by newlines, and MUST NOT contain embedded newlines ». Ce module ne
//! fait que ça — trouver les `0x0A` et rendre les octets entre deux. Il ne parse
//! pas de JSON, ne convertit jamais en `String`, et ne valide pas l'UTF-8 : une
//! frame coupée au milieu d'une séquence multi-octets est un non-événement par
//! construction, puisqu'on ne raisonne que sur des octets.
//!
//! Volontairement synchrone et sans I/O : `wrap.rs` lui pousse ce que `read()` a
//! rendu. Ça rend le découpage testable et fuzzable sans runtime async, et ça
//! garde la partie critique du chemin de relais libre de toute allocation
//! superflue.

use std::fmt;

/// Plafond par défaut sur une frame unique.
///
/// Un serveur amont malformé ou hostile qui n'émet jamais de `\n` ferait croître
/// le tampon jusqu'à l'OOM. Au-delà de ce seuil on rend [`FrameError::Oversize`].
pub const DEFAULT_MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;

/// Seuil de compactage du tampon. En dessous, on laisse le préfixe consommé en
/// place plutôt que de payer un `memmove` par frame.
const COMPACT_THRESHOLD: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Aucun `\n` rencontré avant `max_frame_bytes` octets.
    ///
    /// Le découpeur passe alors en mode rejet : il jette les octets jusqu'au
    /// prochain `\n` puis reprend normalement. C'est la couche transport qui
    /// décide si l'incident est fatal pour la connexion — le découpeur, lui,
    /// sait toujours se resynchroniser.
    Oversize { limit: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversize { limit } => {
                write!(
                    f,
                    "frame dépassant la limite de {limit} octets sans retour ligne"
                )
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Compteurs d'anomalies. Alimentent `mcpwall log --stats`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SplitterStats {
    /// Frames rendues à l'appelant.
    pub frames: u64,
    /// Octets consommés en entrée, terminateurs compris.
    pub bytes_in: u64,
    /// Lignes vides ignorées. Un `\n` seul n'est pas un message.
    pub empty_skipped: u64,
    /// Incidents [`FrameError::Oversize`].
    pub oversize: u64,
    /// Octets jetés en mode rejet, après un `Oversize`.
    pub bytes_discarded: u64,
    /// Frames terminées par la fin du flux plutôt que par un `\n`.
    pub unterminated: u64,
    /// Terminateurs `\r\n` rencontrés. La spec dit `\n` ; on tolère et on compte.
    pub crlf: u64,
}

/// Une frame extraite du flux.
///
/// Porte deux vues des mêmes octets, et la distinction n'est pas cosmétique :
///
/// - [`content`](Self::content) sert à l'**inspection** — sans terminateur, sans
///   `\r` final. C'est ce qu'on scanne et qu'on journalise.
/// - [`raw`](Self::raw) sert au **relais** — les octets exacts reçus, terminateur
///   compris. Écrire `content` suivi d'un `\n` reviendrait à normaliser un
///   `\r\n` en `\n`, c'est-à-dire à modifier le flux d'un amont qu'on ne
///   comprend pas. Le relais ne réécrit rien.
///
/// `content` est un préfixe de `raw`, donc une seule allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    raw: Vec<u8>,
    content_len: usize,
}

impl Frame {
    /// Octets du message, sans délimiteur. À inspecter et journaliser.
    pub fn content(&self) -> &[u8] {
        &self.raw[..self.content_len]
    }

    /// Octets exacts reçus, délimiteur compris. À réémettre tels quels.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// La frame était-elle close par un délimiteur ?
    ///
    /// Faux uniquement pour une dernière frame rendue par [`FrameSplitter::finish`].
    /// Le relais doit alors décider s'il ajoute un `\n` — le pair, lui, attend
    /// un message délimité.
    pub fn is_terminated(&self) -> bool {
        self.raw.len() > self.content_len
    }

    pub fn len(&self) -> usize {
        self.content_len
    }

    pub fn is_empty(&self) -> bool {
        self.content_len == 0
    }

    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }
}

/// Découpeur de flux en frames délimitées par `\n`.
///
/// Usage : [`push`](Self::push) ce que le `read()` a rendu, puis boucler sur
/// [`next_frame`](Self::next_frame) jusqu'à `None`. En fin de flux, appeler
/// [`finish`](Self::finish) pour récupérer une éventuelle dernière frame non
/// terminée.
#[derive(Debug)]
pub struct FrameSplitter {
    buf: Vec<u8>,
    /// Début de la frame en cours dans `buf`.
    start: usize,
    /// Index jusqu'auquel `buf` a déjà été fouillé pour un `\n`. Évite de
    /// rescanner le même préfixe à chaque `push`, ce qui rendrait le découpage
    /// quadratique sur une frame de plusieurs mégaoctets arrivant en petits
    /// morceaux.
    scanned: usize,
    /// Mode rejet : on jette jusqu'au prochain `\n`.
    discarding: bool,
    max_frame_bytes: usize,
    stats: SplitterStats,
}

impl Default for FrameSplitter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_BYTES)
    }
}

impl FrameSplitter {
    pub fn new(max_frame_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            scanned: 0,
            discarding: false,
            max_frame_bytes,
            stats: SplitterStats::default(),
        }
    }

    pub fn stats(&self) -> SplitterStats {
        self.stats
    }

    /// Octets actuellement retenus dans le tampon, en attente d'un `\n`.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Pousse un morceau brut sortant de `read()`.
    pub fn push(&mut self, chunk: &[u8]) {
        self.stats.bytes_in += chunk.len() as u64;
        self.buf.extend_from_slice(chunk);
    }

    /// Rend la frame complète suivante, s'il y en a une.
    ///
    /// `None` signifie « il me faut plus d'octets », pas « fin de flux ».
    pub fn next_frame(&mut self) -> Option<Result<Frame, FrameError>> {
        loop {
            match memchr::memchr(b'\n', &self.buf[self.scanned..]) {
                Some(offset) => {
                    let newline = self.scanned + offset;

                    if self.discarding {
                        // On sort du mode rejet : la frame surdimensionnée
                        // s'arrête ici, la suivante repart proprement.
                        // Le `\n` est un délimiteur consommé, pas de la charge
                        // utile jetée : il ne compte pas.
                        self.stats.bytes_discarded += (newline - self.start) as u64;
                        self.discarding = false;
                        self.consume_to(newline + 1);
                        continue;
                    }

                    // Plafond à vérifier ici aussi, pas seulement quand aucun
                    // `\n` n'a été trouvé : une frame surdimensionnée arrivant
                    // d'un seul `read()`, terminateur compris, passerait sinon.
                    // Le plafond ne doit pas dépendre du découpage des lectures.
                    if newline - self.start > self.max_frame_bytes {
                        self.stats.oversize += 1;
                        self.stats.bytes_discarded += (newline - self.start) as u64;
                        self.consume_to(newline + 1);
                        return Some(Err(FrameError::Oversize {
                            limit: self.max_frame_bytes,
                        }));
                    }

                    let mut end = newline;
                    if end > self.start && self.buf[end - 1] == b'\r' {
                        self.stats.crlf += 1;
                        end -= 1;
                    }
                    // `raw` va jusqu'au `\n` inclus, `content` s'arrête avant le
                    // délimiteur : content est un préfixe de raw.
                    let frame = Frame {
                        raw: self.buf[self.start..=newline].to_vec(),
                        content_len: end - self.start,
                    };
                    self.consume_to(newline + 1);

                    if frame.is_empty() {
                        // Ligne vide : pas un message MCP. On l'ignore sans la
                        // remonter, mais on la compte — un serveur qui en émet
                        // viole le « MUST NOT write anything to stdout that is
                        // not a valid MCP message ».
                        self.stats.empty_skipped += 1;
                        continue;
                    }

                    self.stats.frames += 1;
                    return Some(Ok(frame));
                }
                None => {
                    self.scanned = self.buf.len();

                    if self.discarding {
                        self.stats.bytes_discarded += (self.buf.len() - self.start) as u64;
                        self.consume_to(self.buf.len());
                        return None;
                    }

                    if self.buffered() > self.max_frame_bytes {
                        self.stats.oversize += 1;
                        self.discarding = true;
                        self.stats.bytes_discarded += self.buffered() as u64;
                        self.consume_to(self.buf.len());
                        return Some(Err(FrameError::Oversize {
                            limit: self.max_frame_bytes,
                        }));
                    }

                    return None;
                }
            }
        }
    }

    /// Fin de flux : rend les octets résiduels comme une dernière frame.
    ///
    /// La spec exige un `\n` terminal, mais un serveur tué en cours d'écriture
    /// ou simplement négligent laisse une ligne nue. On la remonte quand même —
    /// perdre le dernier message d'une session serait pire — en l'ayant comptée
    /// dans [`SplitterStats::unterminated`].
    pub fn finish(&mut self) -> Option<Frame> {
        if self.discarding {
            self.stats.bytes_discarded += self.buffered() as u64;
            self.consume_to(self.buf.len());
            return None;
        }

        // Même plafond en fin de flux qu'ailleurs.
        if self.buffered() > self.max_frame_bytes {
            self.stats.oversize += 1;
            self.stats.bytes_discarded += self.buffered() as u64;
            self.consume_to(self.buf.len());
            return None;
        }

        let mut end = self.buf.len();
        if end > self.start && self.buf[end - 1] == b'\r' {
            end -= 1;
        }
        // Pas de délimiteur ici : `raw` s'arrête où s'arrête le flux. Le `\r`
        // final éventuel reste dans `raw` — on ne réécrit pas ce qu'on relaie.
        let frame = Frame {
            raw: self.buf[self.start..].to_vec(),
            content_len: end - self.start,
        };
        self.consume_to(self.buf.len());

        if frame.is_empty() {
            return None;
        }

        self.stats.frames += 1;
        self.stats.unterminated += 1;
        Some(frame)
    }

    /// Avance `start` et compacte le tampon quand le préfixe consommé devient
    /// coûteux à traîner.
    fn consume_to(&mut self, pos: usize) {
        self.start = pos;
        self.scanned = pos;

        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
            self.scanned = 0;
        } else if self.start >= COMPACT_THRESHOLD {
            self.buf.drain(..self.start);
            self.scanned -= self.start;
            self.start = 0;
        }
    }
}

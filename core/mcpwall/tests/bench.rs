//! Budget de latence en passthrough.
//!
//! La spec fixe **< 5 ms p99**. Ce fichier le mesure au lieu de le supposer, et
//! échoue si le seuil est dépassé — c'est la référence contre laquelle le
//! daemon de M1 sera jugé quand il s'ajoutera au chemin.
//!
//! Les assertions ne s'appliquent qu'en `--release` : un binaire de debug mesure
//! le coût des vérifications de débordement, pas celui du produit. En debug le
//! test se contente de tourner, ce qui garantit au moins qu'il compile et ne
//! régresse pas fonctionnellement.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mcpwall::mcp::AllowAll;
use mcpwall::wrap::{Direction, NullObserver, Pump};

/// Budget par frame en passthrough.
#[cfg_attr(debug_assertions, allow(dead_code))]
const P99_BUDGET: Duration = Duration::from_millis(5);

/// Frames mesurées.
const N: usize = 20_000;

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Mesure le chemin complet : découpage, scan de méthode, classement, point de
/// décision, écriture.
async fn measure(frame: &str) -> Vec<Duration> {
    let pump = Pump {
        direction: Direction::ToServer,
        max_frame_bytes: 32 * 1024 * 1024,
        observer: Arc::new(NullObserver),
        decision: Arc::new(AllowAll),
        denied_tx: None,
    };

    let mut samples = Vec::with_capacity(N);
    let mut sink = Vec::with_capacity(frame.len() * 2);

    for _ in 0..N {
        sink.clear();
        let start = Instant::now();
        // Une frame par appel : on mesure la latence d'un message, pas le débit
        // d'un lot, parce que c'est la latence qu'un agent ressent.
        pump.run(frame.as_bytes(), &mut sink, None)
            .await
            .expect("relais");
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    samples
}

fn report(nom: &str, samples: &[Duration]) {
    let p50 = percentile(samples, 0.50);
    let p99 = percentile(samples, 0.99);
    let max = samples.last().copied().unwrap_or_default();
    println!("{nom:<22} p50 {p50:>10.2?}  p99 {p99:>10.2?}  max {max:>10.2?}");
}

#[tokio::test]
async fn latence_passthrough_frame_courte() {
    // Le cas dominant : un appel d'outil ordinaire.
    let frame = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
         \"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/x\"}}}\n";

    let samples = measure(frame).await;
    report("frame courte", &samples);

    #[cfg(not(debug_assertions))]
    {
        let p99 = percentile(&samples, 0.99);
        assert!(
            p99 < P99_BUDGET,
            "budget de latence dépassé : p99 = {p99:?} (budget {P99_BUDGET:?})"
        );
    }
}

#[tokio::test]
async fn latence_passthrough_methode_hors_fenetre() {
    // Le pire cas du scan : `method` repoussée au-delà de la fenêtre, donc
    // seconde passe sur toute la frame.
    let blob = "a".repeat(4096);
    let frame = format!(
        "{{\"jsonrpc\":\"2.0\",\"params\":{{\"text\":\"{blob}\"}},\"method\":\"ping\",\"id\":1}}\n"
    );

    let samples = measure(&frame).await;
    report("méthode hors fenêtre", &samples);

    #[cfg(not(debug_assertions))]
    {
        let p99 = percentile(&samples, 0.99);
        assert!(
            p99 < P99_BUDGET,
            "budget de latence dépassé : p99 = {p99:?} (budget {P99_BUDGET:?})"
        );
    }
}

#[tokio::test]
async fn latence_passthrough_frame_de_cent_kilooctets() {
    let blob = "z".repeat(100 * 1024);
    let frame = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"t\":\"{blob}\"}}}}\n");

    // Moins d'échantillons : on mesure ici le coût de la copie, pas celui de
    // l'inspection.
    let pump = Pump {
        direction: Direction::ToClient,
        max_frame_bytes: 32 * 1024 * 1024,
        observer: Arc::new(NullObserver),
        decision: Arc::new(AllowAll),
        denied_tx: None,
    };
    let mut samples = Vec::with_capacity(2000);
    let mut sink = Vec::with_capacity(frame.len() * 2);
    for _ in 0..2000 {
        sink.clear();
        let start = Instant::now();
        pump.run(frame.as_bytes(), &mut sink, None)
            .await
            .expect("relais");
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    report("frame de 100 Ko", &samples);

    #[cfg(not(debug_assertions))]
    {
        let p99 = percentile(&samples, 0.99);
        assert!(
            p99 < P99_BUDGET,
            "budget de latence dépassé : p99 = {p99:?} (budget {P99_BUDGET:?})"
        );
    }
}

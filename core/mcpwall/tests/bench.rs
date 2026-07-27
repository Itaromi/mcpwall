//! Passthrough latency budget.
//!
//! The spec sets **< 5 ms p99**. This file measures it instead of assuming it,
//! and fails if the threshold is exceeded — it is the baseline the M1 daemon
//! will be judged against once it joins the path.
//!
//! The assertions only apply under `--release`: a debug binary measures the
//! cost of overflow checks, not the cost of the product. In debug the test just
//! runs, which at least guarantees it compiles and has not regressed
//! functionally.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mcpwall::mcp::AllowAll;
use mcpwall::wrap::{Direction, NullObserver, Pump};

/// Per-frame budget in passthrough.
#[cfg_attr(debug_assertions, allow(dead_code))]
const P99_BUDGET: Duration = Duration::from_millis(5);

/// Frames measured.
const N: usize = 20_000;

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Measures the complete path: splitting, method scan, classification,
/// decision point, write.
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
        // One frame per call: we measure the latency of a message, not the
        // throughput of a batch, because latency is what an agent feels.
        pump.run(frame.as_bytes(), &mut sink, None)
            .await
            .expect("relay");
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    samples
}

fn report(name: &str, samples: &[Duration]) {
    let p50 = percentile(samples, 0.50);
    let p99 = percentile(samples, 0.99);
    let max = samples.last().copied().unwrap_or_default();
    println!("{name:<22} p50 {p50:>10.2?}  p99 {p99:>10.2?}  max {max:>10.2?}");
}

#[tokio::test]
async fn passthrough_latency_short_frame() {
    // The dominant case: an ordinary tool call.
    let frame = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
         \"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/x\"}}}\n";

    let samples = measure(frame).await;
    report("short frame", &samples);

    #[cfg(not(debug_assertions))]
    {
        let p99 = percentile(&samples, 0.99);
        assert!(
            p99 < P99_BUDGET,
            "latency budget exceeded: p99 = {p99:?} (budget {P99_BUDGET:?})"
        );
    }
}

#[tokio::test]
async fn passthrough_latency_method_outside_window() {
    // The scan's worst case: `method` pushed beyond the window, so a second
    // pass over the whole frame.
    let blob = "a".repeat(4096);
    let frame = format!(
        "{{\"jsonrpc\":\"2.0\",\"params\":{{\"text\":\"{blob}\"}},\"method\":\"ping\",\"id\":1}}\n"
    );

    let samples = measure(&frame).await;
    report("method outside window", &samples);

    #[cfg(not(debug_assertions))]
    {
        let p99 = percentile(&samples, 0.99);
        assert!(
            p99 < P99_BUDGET,
            "latency budget exceeded: p99 = {p99:?} (budget {P99_BUDGET:?})"
        );
    }
}

#[tokio::test]
async fn passthrough_latency_hundred_kilobyte_frame() {
    let blob = "z".repeat(100 * 1024);
    let frame = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"t\":\"{blob}\"}}}}\n");

    // Fewer samples: here we measure the cost of copying, not of inspection.
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
            .expect("relay");
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    report("100 KB frame", &samples);

    #[cfg(not(debug_assertions))]
    {
        let p99 = percentile(&samples, 0.99);
        assert!(
            p99 < P99_BUDGET,
            "latency budget exceeded: p99 = {p99:?} (budget {P99_BUDGET:?})"
        );
    }
}

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Instant, SystemTime};

use aten_attribution::{AttributionEngine, EngineConfig};

fn prompt(index: usize) -> String {
    format!(
        "{{\"type\":\"user\",\"sessionId\":\"bench-session\",\"uuid\":\"{index}\",\"timestamp\":\"2026-05-27T19:08:02.110Z\",\"cwd\":\"/tmp/aten-bench\",\"message\":{{\"content\":\"inspect /tmp/file-{index}\"}}}}\n"
    )
}

fn main() {
    const INITIAL_RECORDS: usize = 20_000;
    const APPENDS: usize = 1_000;

    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aten-tail-bench-{unique}"));
    std::fs::create_dir_all(&dir).expect("create benchmark directory");
    let transcript = dir.join("session.jsonl");
    let mut writer = std::io::BufWriter::new(
        std::fs::File::create(&transcript).expect("create benchmark transcript"),
    );
    for index in 0..INITIAL_RECORDS {
        writer
            .write_all(prompt(index).as_bytes())
            .expect("write initial transcript");
    }
    writer.flush().expect("flush initial transcript");

    let mut engine = AttributionEngine::new(EngineConfig {
        transcript_paths: vec![transcript.clone()],
        ..EngineConfig::default()
    });
    let initial_start = Instant::now();
    engine.refresh().expect("initial refresh");
    let initial_elapsed = initial_start.elapsed();

    let mut writer = OpenOptions::new()
        .append(true)
        .open(&transcript)
        .expect("open transcript for append");
    let tail_start = Instant::now();
    for index in INITIAL_RECORDS..INITIAL_RECORDS + APPENDS {
        writer
            .write_all(prompt(index).as_bytes())
            .expect("append transcript");
        writer.flush().expect("flush append");
        let emitted = engine.refresh().expect("tail refresh");
        assert_eq!(emitted.len(), 1);
    }
    let tail_elapsed = tail_start.elapsed();
    let stats = engine.stats();

    println!(
        "initial_records={INITIAL_RECORDS} initial_ms={:.2} appends={APPENDS} tail_total_ms={:.2} tail_us_per_append={:.2} bytes_read={} discovery_passes={}",
        initial_elapsed.as_secs_f64() * 1_000.0,
        tail_elapsed.as_secs_f64() * 1_000.0,
        tail_elapsed.as_secs_f64() * 1_000_000.0 / APPENDS as f64,
        stats.bytes_read,
        stats.discovery_passes,
    );

    std::fs::remove_dir_all(dir).expect("remove benchmark directory");
}

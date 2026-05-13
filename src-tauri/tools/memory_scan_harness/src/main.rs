// Standalone harness that runs prism's memory_scanner and prints findings.
// Used to verify that the runtime-registry walk catches Lorno-style writes
// that the string-scan exporter cannot see.

use prism_lib::scanners::memory_scanner;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    eprintln!("memory_scan_harness: starting full memory scan via prism_lib...");
    let findings = memory_scanner::scan().await;

    eprintln!("memory_scan_harness: {} findings", findings.len());
    for (i, f) in findings.iter().enumerate() {
        eprintln!(
            "  [{i:02}] {:?} {} - {}",
            f.verdict, f.module, f.description
        );
        if let Some(d) = &f.details {
            for line in d.lines() {
                eprintln!("       {line}");
            }
        }
    }

    let json = serde_json::to_string_pretty(&findings).expect("serialize");
    println!("{json}");
}

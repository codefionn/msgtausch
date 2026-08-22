use std::{sync::LazyLock, time::Duration};

use divan::{AllocProfiler, black_box};
use msgtausch_throughput::{Protocol, Summary};

#[global_allocator]
static ALLOCATOR: AllocProfiler = AllocProfiler::system();

static HTTP_SUMMARY: LazyLock<Summary> = LazyLock::new(|| Summary {
    protocol: Protocol::Http,
    duration: Duration::from_secs_f64(12.345),
    attempted: 10_000,
    succeeded: 9_998,
    failed: 2,
    bytes: 1_073_741_824,
    requests_per_second: 810.04,
    bytes_per_second: 87_058_760.0,
    latency_p50: Duration::from_micros(825),
    latency_p95: Duration::from_millis(12),
    latency_p99: Duration::from_millis(41),
    deadline_expired: false,
});

static CONNECT_SUMMARY: LazyLock<Summary> = LazyLock::new(|| Summary {
    protocol: Protocol::Connect,
    duration: Duration::from_secs_f64(60.0),
    attempted: 1_000_000,
    succeeded: 999_000,
    failed: 1_000,
    bytes: 4_398_046_511_104,
    requests_per_second: 16_650.0,
    bytes_per_second: 73_300_775_185.07,
    latency_p50: Duration::from_micros(64),
    latency_p95: Duration::from_millis(5),
    latency_p99: Duration::from_millis(125),
    deadline_expired: true,
});

fn main() {
    LazyLock::force(&HTTP_SUMMARY);
    LazyLock::force(&CONNECT_SUMMARY);
    divan::main();
}

#[divan::bench]
fn format_http_report() -> String {
    black_box(&*HTTP_SUMMARY).format_report()
}

#[divan::bench]
fn format_connect_report_with_failures() -> String {
    black_box(&*CONNECT_SUMMARY).format_report()
}

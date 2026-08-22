use std::{sync::LazyLock, time::Duration};

use divan::{AllocProfiler, Bencher, black_box};
use hyper::{Method, StatusCode};
use msgtausch_observability::Observability;
use msgtausch_proxy::ProxyMetrics;

#[global_allocator]
static ALLOCATOR: AllocProfiler = AllocProfiler::system();

static WARM_METRICS: LazyLock<std::sync::Arc<Observability>> = LazyLock::new(|| {
    let metrics = Observability::new();
    record_proxy_metrics(&metrics);
    metrics
});

fn main() {
    LazyLock::force(&WARM_METRICS);
    divan::main();
}

#[divan::bench]
fn observability_new() -> std::sync::Arc<Observability> {
    Observability::new()
}

#[divan::bench]
fn proxy_metrics_cold(bencher: Bencher) {
    bencher
        .with_inputs(Observability::new)
        .bench_values(|metrics| record_proxy_metrics(black_box(&metrics)));
}

#[divan::bench]
fn proxy_metrics_warm() {
    record_proxy_metrics(black_box(&WARM_METRICS));
}

fn record_proxy_metrics(metrics: &Observability) {
    metrics.connection_opened();
    metrics.connection_closed();
    metrics.access_decision(true);
    metrics.access_decision(false);
    metrics.request_finished(&Method::GET, StatusCode::OK, Duration::from_millis(12));
    metrics.proxy_error("connect");
    metrics.route_selected("direct");
    metrics.route_error("socks5");
    metrics.tunnel_finished(1_024, 2_048, Duration::from_millis(34));
}

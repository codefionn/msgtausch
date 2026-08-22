use std::{collections::BTreeMap, sync::LazyLock};

use divan::{AllocProfiler, black_box};
use msgtausch_config::{Classifier, Config, DomainOp, Forward, ForwardKind};
use msgtausch_proxy::ProxyRuntime;

#[global_allocator]
static ALLOCATOR: AllocProfiler = AllocProfiler::system();

static DEFAULT_CONFIG: LazyLock<Config> = LazyLock::new(Config::default);
static ROUTED_CONFIG: LazyLock<Config> = LazyLock::new(|| routed_config(128));
static ROUTED_RUNTIME: LazyLock<ProxyRuntime> = LazyLock::new(|| {
    ProxyRuntime::with_noop_metrics(&ROUTED_CONFIG).expect("routed proxy runtime should be valid")
});

fn main() {
    LazyLock::force(&DEFAULT_CONFIG);
    LazyLock::force(&ROUTED_CONFIG);
    LazyLock::force(&ROUTED_RUNTIME);
    divan::main();
}

#[divan::bench]
fn construct_default_runtime() -> ProxyRuntime {
    ProxyRuntime::with_noop_metrics(black_box(&DEFAULT_CONFIG))
        .expect("default proxy runtime should be valid")
}

#[divan::bench]
fn construct_runtime_with_128_routes() -> ProxyRuntime {
    ProxyRuntime::with_noop_metrics(black_box(&ROUTED_CONFIG))
        .expect("routed proxy runtime should be valid")
}

#[divan::bench]
fn clone_runtime() -> ProxyRuntime {
    black_box(&*ROUTED_RUNTIME).clone()
}

fn routed_config(route_count: usize) -> Config {
    let mut config = Config {
        classifiers: BTreeMap::new(),
        forwards: Vec::with_capacity(route_count),
        ..Config::default()
    };
    for index in 0..route_count {
        let name = format!("route-{index}");
        config.classifiers.insert(
            name.clone(),
            Classifier::Domain {
                op: DomainOp::Is,
                domain: format!("service-{index}.example"),
            },
        );
        config.forwards.push(Forward {
            kind: ForwardKind::Direct,
            classifier: Classifier::Ref(name),
            force_ipv4: index % 2 == 0,
            log: false,
        });
    }
    config
}

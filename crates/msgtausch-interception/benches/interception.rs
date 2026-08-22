use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use divan::{AllocProfiler, Bencher, black_box};
use msgtausch_config::{Classifier, Config, DomainOp, InterceptionConfig};
use msgtausch_interception::InterceptionRuntime;
use msgtausch_policy::{ClassifierEngine, Target};

#[global_allocator]
static ALLOCATOR: AllocProfiler = AllocProfiler::system();

static HOST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static CONFIG: LazyLock<InterceptionConfig> = LazyLock::new(interception_config);
static RUNTIME: LazyLock<InterceptionRuntime> = LazyLock::new(|| {
    let engine = ClassifierEngine::from_config(&Config::default()).expect("policy should compile");
    InterceptionRuntime::from_config_with_classifiers(&CONFIG, &engine)
        .expect("test CA should load")
        .expect("HTTPS interception should be enabled")
});
static POLICY: LazyLock<(InterceptionRuntime, ClassifierEngine, Target, Target)> =
    LazyLock::new(|| {
        let mut config = Config {
            classifiers: BTreeMap::new(),
            interception: interception_config(),
            ..Config::default()
        };
        config.classifiers.insert(
            "excluded".into(),
            Classifier::Domain {
                op: DomainOp::Is,
                domain: "internal.example".into(),
            },
        );
        config.interception.exclude_classifier = Some(Classifier::Ref("excluded".into()));
        let engine = ClassifierEngine::from_config(&config).expect("policy should compile");
        let runtime =
            InterceptionRuntime::from_config_with_classifiers(&config.interception, &engine)
                .expect("test CA should load")
                .expect("HTTPS interception should be enabled");
        (
            runtime,
            engine,
            Target::new("www.example.com", 443, None),
            Target::new("api.internal.example", 443, None),
        )
    });

fn main() {
    LazyLock::force(&CONFIG);
    LazyLock::force(&RUNTIME);
    LazyLock::force(&POLICY);
    RUNTIME
        .downstream_config("cached.bench.example")
        .expect("cached leaf should be primed");
    divan::main();
}

#[divan::bench(sample_count = 20, sample_size = 5)]
fn load_interception_runtime() -> InterceptionRuntime {
    let engine = ClassifierEngine::from_config(&Config::default()).expect("policy should compile");
    InterceptionRuntime::from_config_with_classifiers(black_box(&CONFIG), &engine)
        .expect("test CA should load")
        .expect("HTTPS interception should be enabled")
}

#[divan::bench]
fn cached_leaf_config() {
    RUNTIME
        .downstream_config(black_box("cached.bench.example"))
        .expect("cached leaf should be returned");
}

#[divan::bench(sample_count = 20, sample_size = 5)]
fn issue_leaf_config(bencher: Bencher) {
    bencher
        .with_inputs(|| {
            let id = HOST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            format!("host-{id}.bench.example")
        })
        .bench_values(|host| {
            RUNTIME
                .downstream_config(&host)
                .expect("leaf should be issued")
        });
}

#[divan::bench(args = [false, true])]
fn interception_policy(excluded: bool) -> bool {
    let (runtime, engine, allowed, denied) = &*POLICY;
    runtime
        .should_intercept(if excluded { denied } else { allowed }, engine)
        .expect("interception policy should evaluate")
}

fn interception_config() -> InterceptionConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    InterceptionConfig {
        enabled: true,
        https: true,
        ca_file: Some(root.join("tests/compose-intercept/ca/test_ca.crt")),
        ca_key_file: Some(root.join("tests/compose-intercept/ca/test_ca.key")),
        insecure_skip_verify: true,
        ..InterceptionConfig::default()
    }
}

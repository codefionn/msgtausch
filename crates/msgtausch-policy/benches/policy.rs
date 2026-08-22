use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, LazyLock},
};

use divan::AllocProfiler;
use msgtausch_config::{Classifier, Config, DomainOp as ConfigDomainOp, Forward, ForwardKind};
use msgtausch_policy::{
    ClassifierEngine, CompiledClassifier, DomainOp, Target, domain_list::DomainMatcher,
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

static ENGINE_CONFIG: LazyLock<Config> = LazyLock::new(|| Config {
    classifiers: BTreeMap::from([
        (
            "corp-network".into(),
            Classifier::Network("10.0.0.0/8".into()),
        ),
        (
            "service-domain".into(),
            Classifier::Domain {
                op: ConfigDomainOp::Is,
                domain: "service.example.com".into(),
            },
        ),
        (
            "trusted-service".into(),
            Classifier::And(vec![
                Classifier::Ref("corp-network".into()),
                Classifier::Ref("service-domain".into()),
                Classifier::Port(443),
            ]),
        ),
    ]),
    allowlist: Some(Classifier::Ref("trusted-service".into())),
    blocklist: Some(Classifier::Domain {
        op: ConfigDomainOp::Is,
        domain: "ads.service.example.com".into(),
    }),
    forwards: vec![
        Forward {
            kind: ForwardKind::HttpProxy {
                address: "127.0.0.1:3128".into(),
                username: Some("bench".into()),
                password: Some("bench".into()),
            },
            classifier: Classifier::Ref("trusted-service".into()),
            force_ipv4: true,
            log: true,
        },
        Forward {
            kind: ForwardKind::Direct,
            classifier: Classifier::True,
            force_ipv4: false,
            log: false,
        },
    ],
    ..Config::default()
});

static ENGINE: LazyLock<ClassifierEngine> = LazyLock::new(|| {
    ClassifierEngine::from_config(&ENGINE_CONFIG).expect("valid benchmark engine")
});

static TARGET: LazyLock<Target> = LazyLock::new(|| {
    Target::new(
        "api.service.example.com",
        443,
        Some("10.23.45.67".parse().expect("valid benchmark IP")),
    )
});

static DOMAIN_LIST_TARGET: LazyLock<Target> =
    LazyLock::new(|| Target::new("api.service-999.bench.example.com", 443, None));

static NAMED: LazyLock<HashMap<String, CompiledClassifier>> = LazyLock::new(|| {
    HashMap::from([(
        "corp-network".into(),
        CompiledClassifier::ClientNetwork("10.0.0.0/8".parse().expect("valid benchmark network")),
    )])
});

static COMPILED_DOMAIN: LazyLock<CompiledClassifier> =
    LazyLock::new(|| CompiledClassifier::Domain {
        op: DomainOp::Is,
        value: "service.example.com".into(),
    });

static COMPILED_COMPOSITE: LazyLock<CompiledClassifier> = LazyLock::new(|| {
    CompiledClassifier::And(vec![
        CompiledClassifier::Ref("corp-network".into()),
        CompiledClassifier::Domain {
            op: DomainOp::Is,
            value: "service.example.com".into(),
        },
        CompiledClassifier::Port(443),
    ])
});

static COMPILED_DOMAINS: LazyLock<CompiledClassifier> = LazyLock::new(|| {
    CompiledClassifier::Domains(Arc::new(DomainMatcher::from_local_tokens(
        domain_names(1_000).iter().cloned(),
    )))
});

fn domain_names(size: usize) -> &'static [String] {
    static SMALL: LazyLock<Vec<String>> = LazyLock::new(|| make_domains(10));
    static MEDIUM: LazyLock<Vec<String>> = LazyLock::new(|| make_domains(1_000));
    static LARGE: LazyLock<Vec<String>> = LazyLock::new(|| make_domains(100_000));
    match size {
        10 => &SMALL,
        1_000 => &MEDIUM,
        100_000 => &LARGE,
        _ => panic!("unsupported benchmark domain count: {size}"),
    }
}

fn domain_matcher(size: usize) -> &'static DomainMatcher {
    static SMALL: LazyLock<DomainMatcher> =
        LazyLock::new(|| DomainMatcher::new(domain_names(10).iter().cloned()));
    static MEDIUM: LazyLock<DomainMatcher> =
        LazyLock::new(|| DomainMatcher::new(domain_names(1_000).iter().cloned()));
    static LARGE: LazyLock<DomainMatcher> =
        LazyLock::new(|| DomainMatcher::new(domain_names(100_000).iter().cloned()));
    match size {
        10 => &SMALL,
        1_000 => &MEDIUM,
        100_000 => &LARGE,
        _ => panic!("unsupported benchmark domain count: {size}"),
    }
}

fn make_domains(size: usize) -> Vec<String> {
    (0..size)
        .map(|index| format!("service-{index}.bench.example.com"))
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum CompiledCase {
    Domain,
    Composite,
    Domains,
}

#[divan::bench]
fn construct_classifier_engine(bencher: divan::Bencher) {
    bencher
        .bench(|| ClassifierEngine::from_config(&ENGINE_CONFIG).expect("valid benchmark engine"));
}

#[divan::bench]
fn engine_allows(bencher: divan::Bencher) {
    bencher.bench(|| ENGINE.allows(&TARGET).expect("valid benchmark match"));
}

#[divan::bench]
fn engine_select_forward(bencher: divan::Bencher) {
    bencher.bench(|| {
        ENGINE
            .select_forward(&TARGET)
            .expect("valid benchmark match")
    });
}

#[divan::bench(args = [CompiledCase::Domain, CompiledCase::Composite, CompiledCase::Domains])]
fn compiled_classifier_matches(bencher: divan::Bencher, case: CompiledCase) {
    let classifier = match case {
        CompiledCase::Domain => &*COMPILED_DOMAIN,
        CompiledCase::Composite => &*COMPILED_COMPOSITE,
        CompiledCase::Domains => &*COMPILED_DOMAINS,
    };
    let target = match case {
        CompiledCase::Domains => &*DOMAIN_LIST_TARGET,
        CompiledCase::Domain | CompiledCase::Composite => &*TARGET,
    };
    bencher.bench(|| {
        classifier
            .matches(target, &NAMED)
            .expect("valid benchmark match")
    });
}

#[divan::bench(args = [10usize, 1_000, 100_000])]
fn construct_domain_matcher(bencher: divan::Bencher, size: usize) {
    let domains = domain_names(size);
    bencher.bench(|| DomainMatcher::new(domains.iter().cloned()));
}

#[divan::bench(args = [10usize, 1_000, 100_000])]
fn query_domain_matcher(bencher: divan::Bencher, size: usize) {
    let matcher = domain_matcher(size);
    let host = format!("api.service-{}.bench.example.com", size - 1);
    bencher.bench(|| matcher.matches(&host));
}

fn main() {
    LazyLock::force(&ENGINE_CONFIG);
    LazyLock::force(&ENGINE);
    LazyLock::force(&TARGET);
    LazyLock::force(&DOMAIN_LIST_TARGET);
    LazyLock::force(&NAMED);
    LazyLock::force(&COMPILED_DOMAIN);
    LazyLock::force(&COMPILED_COMPOSITE);
    LazyLock::force(&COMPILED_DOMAINS);
    for size in [10, 1_000, 100_000] {
        let _ = domain_names(size);
        let _ = domain_matcher(size);
    }
    divan::main();
}

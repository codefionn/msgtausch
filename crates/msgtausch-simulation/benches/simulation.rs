use std::sync::LazyLock;

use divan::{AllocProfiler, black_box};
use msgtausch_simulation::{Scenario, generate};

#[global_allocator]
static ALLOCATOR: AllocProfiler = AllocProfiler::system();

static SCENARIO: LazyLock<Scenario> = LazyLock::new(|| generate(790));
static ENCODED_SCENARIO: LazyLock<Vec<u8>> =
    LazyLock::new(|| serde_json::to_vec(&*SCENARIO).expect("generated scenario should serialize"));

fn main() {
    LazyLock::force(&SCENARIO);
    LazyLock::force(&ENCODED_SCENARIO);
    divan::main();
}

#[divan::bench]
fn generate_scenario() -> Scenario {
    generate(black_box(790))
}

#[divan::bench]
fn serialize_scenario() -> Vec<u8> {
    serde_json::to_vec(black_box(&*SCENARIO)).expect("generated scenario should serialize")
}

#[divan::bench]
fn deserialize_scenario() -> Scenario {
    serde_json::from_slice(black_box(&*ENCODED_SCENARIO))
        .expect("generated scenario JSON should deserialize")
}

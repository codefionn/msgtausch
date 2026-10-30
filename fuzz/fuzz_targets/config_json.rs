#![no_main]
//! Fuzz the JSON config parser + classifier engine: first line is a fuzzed
//! target host, the rest is the config document.
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

fn split_once_byte(data: &[u8], b: u8) -> Option<(&[u8], &[u8])> {
    data.iter()
        .position(|&x| x == b)
        .map(|i| (&data[..i], &data[i + 1..]))
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let Some((host_line, cfg)) = split_once_byte(data, b'\n') else {
        return;
    };
    let host = String::from_utf8_lossy(host_line).into_owned();
    let Ok(text) = std::str::from_utf8(cfg) else {
        return;
    };
    let env = BTreeMap::new();
    // Parse errors are expected; panics are crashes.
    if let Ok(config) = msgtausch_config::Config::from_text_for_fuzz(text, "json", &env)
        && let Ok(engine) = msgtausch_policy::ClassifierEngine::from_config(&config)
    {
        let target = msgtausch_policy::Target::new(host, 443, None);
        let _ = engine.allows(&target);
        let _ = engine.select_forward(&target);
    }
});

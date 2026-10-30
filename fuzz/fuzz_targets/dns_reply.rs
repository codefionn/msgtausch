#![no_main]
//! Fuzz the hand-rolled DNS reply parser. Input layout:
//! bytes [0..2) = transaction id, [2..4) = qtype, rest = packet body
//! (the parser is called with a fixed host "example.com").
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > 64 * 1024 {
        return;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let qtype = u16::from_be_bytes([data[2], data[3]]);
    // Expected errors are fine; panics/hangs/OOM are crashes.
    let _ = msgtausch_resolver::parse_dns_reply_for_fuzz(&data[4..], "example.com", qtype, id);
});

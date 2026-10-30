#![no_main]
//! Fuzz the remote domain-list parsers (rpz/wildcard/adblock/plain) and the
//! matcher: line 1 = format, line 2 = host to match, rest = list content.
use libfuzzer_sys::fuzz_target;
use msgtausch_config::DomainsUrlFormat;
use msgtausch_policy::domain_list::{DomainMatcher, parse_domains_for_fuzz};

fn split_once_byte(data: &[u8], b: u8) -> Option<(&[u8], &[u8])> {
    data.iter()
        .position(|&x| x == b)
        .map(|i| (&data[..i], &data[i + 1..]))
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    let Some((format_line, rest)) = split_once_byte(data, b'\n') else {
        return;
    };
    let Some((host_line, content)) = split_once_byte(rest, b'\n') else {
        return;
    };
    let format = match String::from_utf8_lossy(format_line).trim() {
        "rpz" => DomainsUrlFormat::Rpz,
        "wildcard" => DomainsUrlFormat::Wildcard,
        "adblock" => DomainsUrlFormat::Adblock,
        _ => DomainsUrlFormat::Plain,
    };
    let Ok(content) = std::str::from_utf8(content) else {
        return;
    };
    let host = String::from_utf8_lossy(host_line).into_owned();
    let domains = parse_domains_for_fuzz(content, format);
    let matcher = DomainMatcher::new(domains);
    let _ = matcher.matches(&host);
});

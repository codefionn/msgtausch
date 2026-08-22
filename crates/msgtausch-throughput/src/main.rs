use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Result, ensure};
use clap::{Parser, ValueEnum};
use msgtausch_throughput::{Protocol, RunOptions, run};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProtocolArg {
    Http,
    Connect,
    Both,
}

#[derive(Debug, Parser)]
#[command(
    name = "msgtausch-throughput",
    about = "Measure real loopback HTTP or CONNECT proxy throughput"
)]
struct Cli {
    /// Existing proxy address. When omitted, starts --binary with a temporary config.
    #[arg(long)]
    proxy: Option<SocketAddr>,
    #[arg(long, default_value = "target/debug/msgtausch")]
    binary: PathBuf,
    #[arg(long, value_enum, default_value_t = ProtocolArg::Both)]
    protocol: ProtocolArg,
    /// Total measured requests. Set to 0 to run solely for --duration.
    #[arg(long, alias = "numRequests", default_value_t = 100)]
    requests: usize,
    #[arg(long, default_value_t = 10)]
    concurrency: usize,
    #[arg(long, alias = "dataSize", default_value_t = 1024 * 1024)]
    body_size: usize,
    #[arg(long, default_value_t = 10)]
    warmup: usize,
    /// Stop a duration-mode run after this duration, for example 30s or 2m.
    #[arg(long, value_parser = parse_duration)]
    duration: Option<Duration>,
    /// Deadline for each measured protocol run.
    #[arg(long, alias = "timeout", default_value = "30s", value_parser = parse_duration)]
    deadline: Duration,
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    request_timeout: Duration,
    #[arg(long, default_value_t = 0)]
    max_errors: usize,
    #[arg(long, default_value_t = 0.0)]
    max_error_rate: f64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(
        cli.duration.is_none() || cli.duration <= Some(cli.deadline),
        "duration must not exceed deadline"
    );
    let protocols = match cli.protocol {
        ProtocolArg::Http => &[Protocol::Http][..],
        ProtocolArg::Connect => &[Protocol::Connect][..],
        ProtocolArg::Both => &[Protocol::Http, Protocol::Connect][..],
    };
    for (index, protocol) in protocols.iter().enumerate() {
        if index > 0 {
            println!();
        }
        let summary = run(&RunOptions {
            proxy: cli.proxy,
            binary: cli.binary.clone(),
            protocol: *protocol,
            requests: cli.requests,
            concurrency: cli.concurrency,
            body_size: cli.body_size,
            warmup: cli.warmup,
            duration: cli.duration,
            deadline: cli.deadline,
            request_timeout: cli.request_timeout,
            max_errors: cli.max_errors,
            max_error_rate: cli.max_error_rate,
        })?;
        println!("{}", summary.format_report());
    }
    Ok(())
}

fn parse_duration(input: &str) -> Result<Duration, String> {
    let (number, unit) = input
        .trim()
        .chars()
        .position(|character| !character.is_ascii_digit())
        .map(|index| input.trim().split_at(index))
        .unwrap_or((input.trim(), "s"));
    let value = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration {input:?}"))?;
    match unit {
        "ms" => Ok(Duration::from_millis(value)),
        "s" => Ok(Duration::from_secs(value)),
        "m" => Ok(Duration::from_secs(value.saturating_mul(60))),
        _ => Err(format!(
            "invalid duration unit in {input:?}; use ms, s, or m"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration_units() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
    }
}

use std::{
    path::PathBuf,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::Parser;
use msgtausch_simulation::{
    RunOptions, generate, replay, run,
    tls_interception::{TlsInterceptionOptions, run as run_tls_interception},
};

#[derive(Debug, Parser)]
#[command(name = "msgtausch-simulation")]
struct Cli {
    #[arg(value_name = "SEED")]
    seed: Option<u64>,
    #[arg(long, default_value_t = 0)]
    minutes: u64,
    #[arg(long)]
    verbose: bool,
    #[arg(long)]
    stats: bool,
    #[arg(long)]
    enable_forwards: bool,
    #[arg(long)]
    enable_policy_fixtures: bool,
    #[arg(long)]
    tls_interception: bool,
    #[arg(long, default_value_t = 1)]
    runs: usize,
    #[arg(long, default_value_t = 1)]
    jobs: usize,
    #[arg(long, default_value = "simulation-artifacts")]
    artifact_dir: PathBuf,
    #[arg(long)]
    replay: Option<PathBuf>,
    #[arg(long)]
    scenario: Option<PathBuf>,
    #[arg(long, default_value = "target/debug/msgtausch")]
    binary: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.tls_interception {
        run_tls_interception(&TlsInterceptionOptions {
            binary: cli.binary,
            timeout: Duration::from_secs(20),
            shutdown_timeout: Duration::from_secs(3),
        })?;
        println!("TLS interception simulation completed successfully.");
        return Ok(());
    }
    let options = RunOptions {
        binary: cli.binary,
        artifact_dir: cli.artifact_dir,
        timeout: Duration::from_secs(20),
        shutdown_timeout: Duration::from_secs(3),
        enable_forwards: cli.enable_forwards,
        enable_policy_fixtures: cli.enable_policy_fixtures,
    };
    if let Some(path) = cli.replay {
        let report = replay(&path, &options)?;
        print_report(&report, cli.stats || cli.verbose);
        return Ok(());
    }
    if let Some(path) = cli.scenario {
        let scenario = serde_json::from_slice(
            &std::fs::read(&path)
                .with_context(|| format!("reading scenario {}", path.display()))?,
        )?;
        let report = run(scenario, &options)?;
        print_report(&report, cli.stats || cli.verbose);
        return Ok(());
    }
    let initial_seed = cli.seed.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos() as u64
    });
    let deadline =
        (cli.minutes > 0).then(|| Instant::now() + Duration::from_secs(cli.minutes * 60));
    let mut next_seed = initial_seed;
    let mut completed = 0;
    loop {
        let count = cli.jobs.min(cli.runs.saturating_sub(completed).max(1));
        let handles = (0..count)
            .map(|offset| {
                let seed = next_seed + offset as u64;
                let options = options.clone();
                thread::spawn(move || run(generate(seed), &options))
            })
            .collect::<Vec<_>>();
        for handle in handles {
            let report = handle
                .join()
                .map_err(|_| anyhow::anyhow!("simulation worker panicked"))??;
            print_report(&report, cli.stats || cli.verbose);
            completed += 1;
        }
        next_seed += count as u64;
        if deadline.is_none() && completed >= cli.runs {
            break;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
    }
    println!("Simulation completed successfully. runs={completed} first-seed={initial_seed}");
    Ok(())
}

fn print_report(report: &msgtausch_simulation::SimulationReport, detailed: bool) {
    if detailed {
        println!(
            "seed={} completed={}/{} metric-comparisons={} events={}",
            report.seed,
            report.completed,
            report.operations,
            report.comparisons.len(),
            report.events.len()
        );
    }
}

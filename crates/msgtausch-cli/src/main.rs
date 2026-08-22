use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use compio::{
    net::TcpListener,
    runtime::{JoinHandle, spawn},
};
use msgtausch_config::{Config, ServerKind};
use msgtausch_observability::{Observability, init_tracing, spawn_prometheus};
use msgtausch_proxy::ProxyRuntime;
use msgtausch_quic::H3Listener;

use crate::cli::{Cli, version_string};

mod cli;

#[compio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse_compatible();
    if cli.version {
        println!("{}", version_string());
        return Ok(());
    }

    let config_paths = cli.config_paths();
    let environment = Config::current_environment(cli.envfile.as_deref())?;
    let mut config = Config::load_paths(&config_paths, &environment)?;
    let _telemetry = init_tracing(&config.observability, cli.debug, cli.trace)?;

    tracing::info!(driver = ?compio::runtime::Runtime::current().driver_type(), "Compio runtime initialized");
    tracing::info!(paths = ?config_paths, "starting msgtausch");
    let mut service = ServiceGroup::start(&config).await?;

    #[cfg(unix)]
    {
        loop {
            match wait_for_unix_signal().await? {
                UnixSignal::Interrupt | UnixSignal::Terminate => break,
                UnixSignal::Hangup => {
                    match reload(&config_paths, cli.envfile.as_deref(), &config).await {
                        Ok(Some(next)) => {
                            tracing::info!("configuration changed, restarting listeners");
                            service.shutdown().await;
                            service = ServiceGroup::start(&next).await?;
                            config = next;
                        }
                        Ok(None) => tracing::info!("configuration unchanged"),
                        Err(error) => {
                            tracing::error!(%error, "configuration reload failed; keeping current runtime")
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    compio::signal::ctrl_c()
        .await
        .context("waiting for shutdown signal")?;

    tracing::info!("shutting down msgtausch");
    service.shutdown().await;
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum UnixSignal {
    Interrupt,
    Terminate,
    Hangup,
}

#[cfg(unix)]
async fn wait_for_unix_signal() -> Result<UnixSignal> {
    use futures_util::{FutureExt, select};

    let interrupt = compio::signal::unix::signal(libc::SIGINT).fuse();
    let terminate = compio::signal::unix::signal(libc::SIGTERM).fuse();
    let hangup = compio::signal::unix::signal(libc::SIGHUP).fuse();
    futures_util::pin_mut!(interrupt, terminate, hangup);

    select! {
        result = interrupt => result.context("waiting for SIGINT").map(|()| UnixSignal::Interrupt),
        result = terminate => result.context("waiting for SIGTERM").map(|()| UnixSignal::Terminate),
        result = hangup => result.context("waiting for SIGHUP").map(|()| UnixSignal::Hangup),
    }
}

async fn reload(
    paths: &[PathBuf],
    envfile: Option<&std::path::Path>,
    current: &Config,
) -> Result<Option<Config>> {
    let environment = Config::current_environment(envfile)?;
    let next = Config::load_paths(paths, &environment)?;
    Ok((next != *current).then_some(next))
}

struct ServiceGroup {
    tasks: Vec<JoinHandle<Result<()>>>,
    prometheus: Option<JoinHandle<Result<()>>>,
    quic: Vec<H3Listener>,
}

impl ServiceGroup {
    async fn start(config: &Config) -> Result<Self> {
        let metrics = Observability::new();
        let runtime = Arc::new(ProxyRuntime::from_config(config, metrics.clone())?);
        let prometheus = spawn_prometheus(metrics, &config.observability)?;
        let mut tasks = Vec::new();
        let mut quic = Vec::new();

        for server in config.servers.iter().filter(|server| server.enabled) {
            if matches!(server.kind, ServerKind::Quic) {
                let address = server.listen_address.parse().with_context(|| {
                    format!("parsing QUIC listener address {}", server.listen_address)
                })?;
                let listener =
                    H3Listener::bind_with_tls_config(address, runtime.quic_server_config()?, None)
                        .await?;
                let bound = listener.local_addr()?;
                let task_listener = listener.clone();
                let runtime = runtime.clone();
                tracing::info!(%bound, "HTTP/3 proxy listener started");
                tasks.push(spawn(async move {
                    loop {
                        let connection = match task_listener.accept().await {
                            Ok(connection) => connection,
                            Err(error) if error.to_string().contains("listener is closed") => {
                                return Ok(())
                            }
                            Err(error) => {
                                tracing::debug!(%error, "rejecting HTTP/3 connection during handshake");
                                continue;
                            }
                        };
                        let runtime = runtime.clone();
                        spawn(async move {
                            if let Err(error) = runtime.serve_h3_connection(connection).await {
                                tracing::debug!(%error, "HTTP/3 proxy connection closed with an error");
                            }
                        }).detach();
                    }
                }));
                quic.push(listener);
                continue;
            }
            let listener = TcpListener::bind(&server.listen_address)
                .await
                .with_context(|| format!("binding proxy listener {}", server.listen_address))?;
            let address = listener.local_addr()?;
            let runtime = runtime.clone();
            let kind = server.kind;
            tracing::info!(%address, kind = ?server.kind, "proxy listener started");
            tasks.push(spawn(async move {
                loop {
                    let (stream, peer) = listener
                        .accept()
                        .await
                        .context("accepting proxy connection")?;
                    let runtime = runtime.clone();
                    spawn(async move {
                        let result = match kind {
                            ServerKind::Standard | ServerKind::Http => {
                                runtime.serve_connection(stream, peer).await
                            }
                            ServerKind::Https => runtime.serve_https_connection(stream, peer).await,
                            ServerKind::Quic => {
                                unreachable!("QUIC listeners are started separately")
                            }
                        };
                        if let Err(error) = result {
                            tracing::debug!(%peer, %error, "proxy connection closed with an error");
                        }
                    })
                    .detach();
                }
            }));
        }

        if tasks.is_empty() {
            bail!("configuration has no enabled proxy listeners");
        }
        let classifiers = runtime.classifiers_shared();
        let refresh_interval = Duration::from_secs(config.cache.refresh_interval_seconds.max(1));
        tasks.push(spawn(async move {
            loop {
                compio::time::sleep(refresh_interval).await;
                let classifiers = classifiers.clone();
                match compio::runtime::spawn_blocking(move || classifiers.refresh_remote_domains())
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "remote domain-list refresh failed")
                    }
                    Err(error) => {
                        tracing::error!(%error, "remote domain-list refresh task failed")
                    }
                }
            }
        }));
        Ok(Self {
            tasks,
            prometheus,
            quic,
        })
    }

    async fn shutdown(&mut self) {
        for listener in &self.quic {
            listener.close();
        }
        self.quic.clear();
        for task in self.tasks.drain(..) {
            if let Some(Err(error)) = task.cancel().await {
                tracing::error!(%error, "proxy listener task failed");
            }
        }
        if let Some(task) = self.prometheus.take()
            && let Some(Err(error)) = task.cancel().await
        {
            tracing::error!(%error, "Prometheus listener failed");
        }
    }
}

use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use compio::{
    net::TcpListener,
    runtime::{JoinHandle, spawn},
};
use futures_channel::{mpsc, oneshot};
use futures_util::StreamExt;
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
    let (mut service, mut failures) = ServiceGroup::start(&config).await?;

    #[cfg(unix)]
    {
        loop {
            let event =
                futures_util::future::select(Box::pin(wait_for_unix_signal()), failures.next())
                    .await;
            let signal = match event {
                futures_util::future::Either::Left((signal, _)) => signal?,
                futures_util::future::Either::Right((message, _)) => {
                    let message = message.unwrap_or_else(|| "worker channel closed".into());
                    tracing::error!(%message, "worker failed; exiting");
                    service.shutdown().await;
                    bail!("worker failed: {message}");
                }
            };
            match signal {
                UnixSignal::Interrupt | UnixSignal::Terminate => break,
                UnixSignal::Hangup => {
                    match reload(&config_paths, cli.envfile.as_deref(), &config).await {
                        Ok(Some(next)) => {
                            tracing::info!("configuration changed, restarting listeners");
                            service.shutdown().await;
                            (service, failures) = ServiceGroup::start(&next).await?;
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
    {
        let interrupt = Box::pin(compio::signal::ctrl_c());
        match futures_util::future::select(interrupt, failures.next()).await {
            futures_util::future::Either::Left((result, _)) => {
                result.context("waiting for shutdown signal")?
            }
            futures_util::future::Either::Right((message, _)) => {
                let message = message.unwrap_or_else(|| "worker channel closed".into());
                tracing::error!(%message, "worker failed; exiting");
                service.shutdown().await;
                bail!("worker failed: {message}");
            }
        }
    }

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

type FailureSender = mpsc::UnboundedSender<String>;
type BoundListener = (ServerKind, std::net::TcpListener);

struct Worker {
    shutdown: Option<oneshot::Sender<()>>,
    thread: thread::JoinHandle<()>,
}

struct ServiceGroup {
    tasks: Vec<JoinHandle<Result<()>>>,
    prometheus: Option<JoinHandle<Result<()>>>,
    quic: Vec<H3Listener>,
    workers: Vec<Worker>,
}

/// Reports a worker thread that unwinds. A normal exit disarms it.
struct ExitGuard {
    index: usize,
    failures: FailureSender,
    armed: bool,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self
                .failures
                .unbounded_send(format!("worker {} exited unexpectedly", self.index));
        }
    }
}

/// Bind one TCP listener. `reuse_port` lets several workers share a port, and
/// it only exists on unix targets.
fn bind_tcp(address: SocketAddr, reuse_port: bool) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    #[cfg(not(unix))]
    let _ = reuse_port;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

/// Bind `workers` listeners for one configured address. A port of 0 is
/// resolved by the first bind so every worker shares the same port.
fn bind_worker_listeners(
    listen_address: &str,
    workers: usize,
) -> Result<Vec<std::net::TcpListener>> {
    let reuse_port = workers > 1;
    let candidates: Vec<SocketAddr> = listen_address
        .to_socket_addrs()
        .with_context(|| format!("resolving proxy listener {listen_address}"))?
        .collect();
    let mut last_error = None;
    let mut first = None;
    for candidate in candidates {
        match bind_tcp(candidate, reuse_port) {
            Ok(listener) => {
                first = Some(listener);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some(first) = first else {
        let error = last_error.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "no socket addresses")
        });
        return Err(error).with_context(|| format!("binding proxy listener {listen_address}"));
    };
    let bound = first.local_addr()?;
    let mut listeners = vec![first];
    for _ in 1..workers {
        listeners.push(
            bind_tcp(bound, true)
                .with_context(|| format!("binding proxy listener {listen_address}"))?,
        );
    }
    Ok(listeners)
}

fn spawn_accept_loop(
    listener: TcpListener,
    runtime: Arc<ProxyRuntime>,
    kind: ServerKind,
    failures: FailureSender,
) -> JoinHandle<Result<()>> {
    spawn(async move {
        if let Err(error) = accept_loop(listener, runtime, kind).await {
            let _ = failures.unbounded_send(format!("{error:#}"));
        }
        Ok(())
    })
}

async fn accept_loop(
    listener: TcpListener,
    runtime: Arc<ProxyRuntime>,
    kind: ServerKind,
) -> Result<()> {
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
                ServerKind::Quic => unreachable!("QUIC listeners are started separately"),
            };
            if let Err(error) = result {
                tracing::debug!(%peer, %error, "proxy connection closed with an error");
            }
        })
        .detach();
    }
}

/// Start an extra worker thread with its own compio runtime. The returned
/// receiver resolves once its listeners are registered.
fn spawn_worker(
    index: usize,
    runtime: Arc<ProxyRuntime>,
    listeners: Vec<BoundListener>,
    failures: FailureSender,
) -> Result<(Worker, oneshot::Receiver<Result<(), String>>)> {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let thread = thread::Builder::new()
        .name(format!("msgtausch-worker-{index}"))
        .spawn(move || {
            let mut guard = ExitGuard {
                index,
                failures: failures.clone(),
                armed: true,
            };
            let compio_runtime = match compio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(error) => {
                    guard.armed = false;
                    let _ = ready_tx.send(Err(format!("creating runtime: {error}")));
                    return;
                }
            };
            compio_runtime.block_on(async move {
                let mut tasks = Vec::new();
                for (kind, listener) in listeners {
                    match TcpListener::from_std(listener) {
                        Ok(listener) => tasks.push(spawn_accept_loop(
                            listener,
                            runtime.clone(),
                            kind,
                            failures.clone(),
                        )),
                        Err(error) => {
                            let _ = ready_tx.send(Err(format!("registering listener: {error}")));
                            return;
                        }
                    }
                }
                let _ = ready_tx.send(Ok(()));
                let _ = shutdown_rx.await;
                for task in tasks {
                    task.cancel().await;
                }
            });
            // A startup error was already reported through `ready_tx`.
            guard.armed = false;
        })
        .context("spawning worker thread")?;
    Ok((
        Worker {
            shutdown: Some(shutdown_tx),
            thread,
        },
        ready_rx,
    ))
}

impl ServiceGroup {
    async fn start(config: &Config) -> Result<(Self, mpsc::UnboundedReceiver<String>)> {
        let (failure_tx, failure_rx) = mpsc::unbounded();
        let worker_count = if cfg!(unix) {
            config.resolved_worker_threads()
        } else {
            1
        };
        let metrics = Observability::new();
        let runtime = Arc::new(ProxyRuntime::from_config(config, metrics.clone())?);

        // Bind every TCP listener before anything runs, so a bind error exits
        // like it did with a single thread.
        let mut per_worker: Vec<Vec<BoundListener>> =
            (0..worker_count).map(|_| Vec::new()).collect();
        for server in config.servers.iter().filter(|server| server.enabled) {
            if matches!(server.kind, ServerKind::Quic) {
                continue;
            }
            let bound = bind_worker_listeners(&server.listen_address, worker_count)?;
            for (worker, listener) in per_worker.iter_mut().zip(bound) {
                worker.push((server.kind, listener));
            }
        }

        let prometheus = spawn_prometheus(metrics, &config.observability)?;
        let mut group = Self {
            tasks: Vec::new(),
            prometheus,
            quic: Vec::new(),
            workers: Vec::new(),
        };
        match group
            .start_services(config, runtime, per_worker, failure_tx)
            .await
        {
            Ok(()) => {
                tracing::info!(workers = worker_count, "msgtausch workers started");
                Ok((group, failure_rx))
            }
            Err(error) => {
                group.shutdown().await;
                Err(error)
            }
        }
    }

    async fn start_services(
        &mut self,
        config: &Config,
        runtime: Arc<ProxyRuntime>,
        mut per_worker: Vec<Vec<BoundListener>>,
        failures: FailureSender,
    ) -> Result<()> {
        let extra: Vec<Vec<BoundListener>> = per_worker.drain(1..).collect();
        let first = per_worker.pop().unwrap_or_default();

        for server in config.servers.iter().filter(|server| server.enabled) {
            if !matches!(server.kind, ServerKind::Quic) {
                continue;
            }
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
            self.tasks.push(spawn(async move {
                loop {
                    let connection = match task_listener.accept().await {
                        Ok(connection) => connection,
                        Err(error) if error.to_string().contains("listener is closed") => {
                            return Ok(());
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
                    })
                    .detach();
                }
            }));
            self.quic.push(listener);
        }

        let mut has_listener = !self.quic.is_empty();
        for (kind, listener) in first {
            let listener = TcpListener::from_std(listener)?;
            let address = listener.local_addr()?;
            tracing::info!(%address, kind = ?kind, "proxy listener started");
            self.tasks.push(spawn_accept_loop(
                listener,
                runtime.clone(),
                kind,
                failures.clone(),
            ));
            has_listener = true;
        }
        if !has_listener {
            bail!("configuration has no enabled proxy listeners");
        }

        let classifiers = runtime.classifiers_shared();
        let refresh_interval = Duration::from_secs(config.cache.refresh_interval_seconds.max(1));
        self.tasks.push(spawn(async move {
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

        let mut ready = Vec::new();
        for (offset, listeners) in extra.into_iter().enumerate() {
            let (worker, receiver) = spawn_worker(
                offset + 1,
                Arc::new(runtime.for_worker()),
                listeners,
                failures.clone(),
            )?;
            self.workers.push(worker);
            ready.push(receiver);
        }
        for receiver in ready {
            match receiver.await {
                Ok(Ok(())) => {}
                Ok(Err(message)) => bail!("worker failed to start: {message}"),
                Err(_) => bail!("worker exited during startup"),
            }
        }
        Ok(())
    }

    /// Stop every listener and join the worker threads.
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
        for worker in &mut self.workers {
            if let Some(shutdown) = worker.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
        for worker in self.workers.drain(..) {
            let name = worker.thread.thread().name().unwrap_or("worker").to_owned();
            match compio::runtime::spawn_blocking(move || worker.thread.join()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => tracing::error!(worker = %name, "worker thread panicked"),
                Err(error) => tracing::error!(%error, "joining worker thread failed"),
            }
        }
    }
}

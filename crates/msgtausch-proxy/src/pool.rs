//! Reusable HTTP/1 upstream connections.
//!
//! HTTP/1 permits only one outstanding response on a connection. A sender is
//! therefore checked out exclusively and is returned only after its response
//! body reaches EOF. Dropping a response early deliberately drops its sender:
//! the remaining bytes would otherwise corrupt the next request.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use compio::runtime;
use compio::time::{sleep, timeout};
use cyper_core::HyperStream;
use hyper::{
    Request, Response,
    body::{Body, Frame, Incoming, SizeHint},
    client::conn::http1::{Connection, SendRequest},
    header::CONNECTION,
};

use msgtausch_policy::Target;

type Sender = SendRequest<Incoming>;
type Stream = HyperStream<compio::net::TcpStream>;

/// Identity of an upstream connection. `route` distinguishes the selected
/// forward route so a changed policy cannot reuse a connection created for a
/// different route.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Key {
    host: String,
    port: u16,
    tls: bool,
    route: usize,
}

impl Key {
    pub(crate) fn new(target: &Target, tls: bool, route: usize) -> Self {
        Self {
            host: target.host.clone(),
            port: target.port,
            tls,
            route,
        }
    }
}

struct IdleSender {
    sender: Sender,
    returned_at: Instant,
}

struct Inner {
    idle: Mutex<HashMap<Key, Vec<IdleSender>>>,
    idle_timeout: Duration,
    max_idle_per_key: usize,
    max_idle: usize,
    ready_timeout: Duration,
    sweeper_running: AtomicBool,
}

/// A bounded collection of idle upstream HTTP/1 connections.
#[derive(Clone)]
pub(crate) struct UpstreamPool(Arc<Inner>);

impl UpstreamPool {
    pub(crate) fn new(idle_timeout: Duration, max_idle_per_key: usize) -> Self {
        Self(Arc::new(Inner {
            idle: Mutex::new(HashMap::new()),
            idle_timeout,
            max_idle_per_key,
            max_idle: max_idle_per_key.saturating_mul(8).max(1),
            // A stale peer must not tie up a new request for the whole tunnel
            // idle timeout. This only covers readiness, not request transfer.
            ready_timeout: idle_timeout.min(Duration::from_secs(5)),
            sweeper_running: AtomicBool::new(false),
        }))
    }

    /// Send one request. `connect` is invoked only when no usable idle sender
    /// exists. Once `send_request` starts, errors are returned to the caller
    /// without retrying, which prevents replaying a non-idempotent request.
    pub(crate) async fn send<F, Fut>(
        &self,
        key: Key,
        request: Request<Incoming>,
        connect: F,
    ) -> Result<Response<PooledBody>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Stream>>,
    {
        let mut sender = match self.take_ready(&key).await {
            Some(sender) => sender,
            None => Self::connect(connect).await?,
        };

        // Do not retry this operation. Hyper may have written all or part of
        // the request before reporting an I/O error.
        let response = sender
            .send_request(request)
            .await
            .context("forwarding HTTP request")?;
        let reusable = !connection_closes(response.headers());
        Ok(response.map(|body| {
            PooledBody::new(
                body,
                Lease {
                    pool: self.0.clone(),
                    key,
                    sender: Some(sender),
                },
                reusable,
            )
        }))
    }

    async fn take_ready(&self, key: &Key) -> Option<Sender> {
        loop {
            let mut sender = self.take_idle(key)?;
            match timeout(self.0.ready_timeout, sender.ready()).await {
                Ok(Ok(())) => return Some(sender),
                // A stale or busy sender is unusable. Dropping it also lets
                // Hyper's connection driver wind down.
                Ok(Err(_)) | Err(_) => continue,
            }
        }
    }

    fn take_idle(&self, key: &Key) -> Option<Sender> {
        let mut idle = self.0.idle.lock().expect("upstream pool mutex poisoned");
        let now = Instant::now();
        loop {
            let (entry, empty) = {
                let senders = idle.get_mut(key)?;
                (senders.pop(), senders.is_empty())
            };
            if empty {
                idle.remove(key);
            }
            let entry = entry?;
            if now.duration_since(entry.returned_at) <= self.0.idle_timeout {
                return Some(entry.sender);
            }
        }
    }

    async fn connect<F, Fut>(connect: F) -> Result<Sender>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Stream>>,
    {
        let stream = connect().await?;
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(stream)
            .await
            .context("starting upstream HTTP connection")?;
        Self::drive(connection);
        Ok(sender)
    }

    fn drive(connection: Connection<Stream, Incoming>) {
        runtime::spawn(async move {
            let _ = connection.with_upgrades().await;
        })
        .detach();
    }
}

struct Lease {
    pool: Arc<Inner>,
    key: Key,
    sender: Option<Sender>,
}

impl Lease {
    fn return_to_pool(&mut self) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        let should_store = {
            let mut idle = self.pool.idle.lock().expect("upstream pool mutex poisoned");
            prune_expired(&mut idle, self.pool.idle_timeout);
            let has_capacity = idle_len(&idle) < self.pool.max_idle;
            let has_key_capacity = idle
                .get(&self.key)
                .is_none_or(|senders| senders.len() < self.pool.max_idle_per_key);
            if has_capacity && has_key_capacity {
                idle.entry(self.key.clone()).or_default().push(IdleSender {
                    sender,
                    returned_at: Instant::now(),
                });
                true
            } else {
                false
            }
        };
        if should_store
            && self
                .pool
                .sweeper_running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let pool = Arc::downgrade(&self.pool);
            runtime::spawn(async move {
                sweep(pool).await;
            })
            .detach();
        }
    }
}

fn idle_len(idle: &HashMap<Key, Vec<IdleSender>>) -> usize {
    idle.values().map(Vec::len).sum()
}

async fn sweep(pool: Weak<Inner>) {
    loop {
        let Some(pool) = pool.upgrade() else {
            return;
        };
        sleep(pool.idle_timeout.min(Duration::from_secs(1))).await;
        let is_empty = {
            let mut idle = pool.idle.lock().expect("upstream pool mutex poisoned");
            prune_expired(&mut idle, pool.idle_timeout);
            idle.is_empty()
        };
        if is_empty {
            pool.sweeper_running.store(false, Ordering::Release);
            // A sender may have arrived just before the store above. Claim a
            // new sweep in that case, otherwise the next return starts one.
            let has_idle = !pool
                .idle
                .lock()
                .expect("upstream pool mutex poisoned")
                .is_empty();
            if !has_idle
                || pool
                    .sweeper_running
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                return;
            }
        }
    }
}

fn prune_expired(idle: &mut HashMap<Key, Vec<IdleSender>>, idle_timeout: Duration) {
    let now = Instant::now();
    idle.retain(|_, senders| {
        senders.retain(|entry| now.duration_since(entry.returned_at) <= idle_timeout);
        !senders.is_empty()
    });
}

/// A streamed upstream response body that releases its exclusive sender at
/// EOF. If it is cancelled or has a body error, its lease is dropped instead.
pub struct PooledBody {
    body: Incoming,
    lease: Option<Lease>,
}

impl PooledBody {
    fn new(body: Incoming, lease: Lease, reusable: bool) -> Self {
        let mut result = Self {
            body,
            lease: reusable.then_some(lease),
        };
        if result.body.is_end_stream() {
            result.release();
        }
        result
    }

    fn release(&mut self) {
        if let Some(mut lease) = self.lease.take() {
            lease.return_to_pool();
        }
    }
}

fn connection_closes(headers: &hyper::HeaderMap) -> bool {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("close"))
}

impl Body for PooledBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Ready(None) => {
                self.release();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                // Hyper marks a fixed-length response complete when it yields
                // the last data frame. Consumers are allowed to stop polling
                // at that point, so waiting for a separate `None` would leak
                // the lease and prevent reuse.
                if self.body.is_end_stream() {
                    self.release();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                // Keep no lease on an errored response.
                self.lease.take();
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::Key;
    use crate::ProxyRuntime;
    use bytes::Bytes;
    use compio::{
        net::{TcpListener, TcpStream},
        runtime,
        time::timeout,
    };
    use cyper_core::HyperStream;
    use futures_util::StreamExt;
    use http_body_util::{BodyExt, Full, StreamBody};
    use hyper::{
        Request, Response, StatusCode,
        body::{Frame, Incoming},
        header::CONNECTION,
        service::service_fn,
    };
    use msgtausch_config::Config;
    use msgtausch_policy::Target;

    #[test]
    fn separates_tls_and_forward_routes_for_the_same_authority() {
        let target = Target::new("origin.example", 443, None);
        assert_ne!(Key::new(&target, false, 0), Key::new(&target, true, 0));
        assert_ne!(Key::new(&target, true, 1), Key::new(&target, true, 2));
    }

    #[test]
    fn normalizes_target_host_through_target_key() {
        let upper = Target::new("ORIGIN.EXAMPLE.", 80, None);
        let lower = Target::new("origin.example", 80, None);
        assert_eq!(Key::new(&upper, false, 0), Key::new(&lower, false, 0));
    }

    #[compio::test]
    async fn returns_a_completed_response_connection_to_the_origin_pool() {
        assert_eq!(request_origin(false).await, 1);
    }

    #[compio::test]
    async fn discards_a_connection_the_origin_explicitly_closes() {
        assert_eq!(request_origin(true).await, 2);
    }

    #[compio::test]
    async fn dropping_a_partial_body_never_returns_its_sender_to_the_pool() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let count = accepts.clone();
        runtime::spawn(async move {
            loop {
                let (stream, _) = origin.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                runtime::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            HyperStream::new_plain(stream),
                            service_fn(|request: Request<Incoming>| async move {
                                let body = if request.uri().path() == "/slow" {
                                    BodyExt::boxed(StreamBody::new(
                                        futures_util::stream::iter([Ok::<_, Infallible>(
                                            Frame::data(Bytes::from_static(b"x")),
                                        )])
                                        .chain(futures_util::stream::pending()),
                                    ))
                                } else {
                                    BodyExt::boxed(Full::new(Bytes::from_static(b"ok")))
                                };
                                Ok::<_, Infallible>(Response::new(body))
                            }),
                        )
                        .await;
                })
                .detach();
            }
        })
        .detach();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy = Arc::new(ProxyRuntime::with_noop_metrics(&Config::default()).unwrap());
        runtime::spawn(async move {
            loop {
                let (stream, peer) = listener.accept().await.unwrap();
                let proxy = proxy.clone();
                runtime::spawn(async move {
                    let _ = proxy.serve_connection(stream, peer).await;
                })
                .detach();
            }
        })
        .detach();

        timeout(Duration::from_secs(5), async {
            let stream = TcpStream::connect(proxy_address).await.unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(HyperStream::new_plain(stream))
                    .await
                    .unwrap();
            runtime::spawn(async move {
                let _ = connection.await;
            })
            .detach();
            let response = sender
                .send_request(
                    Request::builder()
                        .uri(format!("http://{origin_address}/slow"))
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let mut body = response.into_body();
            let _ = body.frame().await.unwrap().unwrap();
            drop(body);
            drop(sender);

            let stream = TcpStream::connect(proxy_address).await.unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(HyperStream::new_plain(stream))
                    .await
                    .unwrap();
            runtime::spawn(async move {
                let _ = connection.await;
            })
            .detach();
            let response = sender
                .send_request(
                    Request::builder()
                        .uri(format!("http://{origin_address}/ok"))
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                b"ok".as_slice()
            );
            assert_eq!(accepts.load(Ordering::SeqCst), 2);
        })
        .await
        .expect("cancelled response must not stall the next request");
    }

    async fn request_origin(close: bool) -> usize {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let count = accepts.clone();
        runtime::spawn(async move {
            loop {
                let (stream, _) = origin.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                runtime::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            HyperStream::new_plain(stream),
                            service_fn(move |_: Request<Incoming>| async move {
                                let mut response =
                                    Response::new(Full::new(Bytes::from_static(b"ok")));
                                if close {
                                    response
                                        .headers_mut()
                                        .insert(CONNECTION, "close".parse().unwrap());
                                }
                                Ok::<_, Infallible>(response)
                            }),
                        )
                        .await;
                })
                .detach();
            }
        })
        .detach();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy = Arc::new(ProxyRuntime::with_noop_metrics(&Config::default()).unwrap());
        runtime::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            proxy.serve_connection(stream, peer).await.unwrap();
        })
        .detach();

        timeout(Duration::from_secs(5), async {
            let stream = TcpStream::connect(proxy_address).await.unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(HyperStream::new_plain(stream))
                    .await
                    .unwrap();
            runtime::spawn(async move {
                let _ = connection.await;
            })
            .detach();
            for _ in 0..2 {
                sender.ready().await.unwrap();
                let response = sender
                    .send_request(
                        Request::builder()
                            .uri(format!("http://{origin_address}/"))
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    response.into_body().collect().await.unwrap().to_bytes(),
                    b"ok".as_slice()
                );
            }
            accepts.load(Ordering::SeqCst)
        })
        .await
        .expect("origin requests must complete")
    }
}

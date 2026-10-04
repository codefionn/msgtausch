//! Stream wrappers that connect Compio sockets to Hyper and the tunnel copier.
//!
//! `cyper_core::HyperStream` zero-fills the whole Hyper read cursor on every
//! poll. For a 16 KiB or larger cursor that memset showed up as 20 to 30
//! percent of CPU. [`ProxyIo`] never initialises the cursor:
//!
//! - Plain TCP reads straight into the uninitialised cursor memory through
//!   `AsyncStream::poll_read_uninit`.
//! - TLS streams only expose `poll_read(&mut [u8])`, so they read into a
//!   scratch buffer that is zeroed once at construction and copy the result
//!   into the cursor.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::{io::compat::AsyncStream, net::TcpStream, tls::TlsStream};
use futures_util::io::{AsyncRead, AsyncWrite};
use hyper::rt::ReadBufCursor;
use send_wrapper::SendWrapper;

/// Buffer size for plain TCP compat streams and for the tunnel copy buffers.
pub(crate) const IO_BUFFER: usize = 64 * 1024;

/// One TLS record holds at most 16 KiB of plaintext, so a larger scratch
/// buffer would never be filled by a single read.
const TLS_SCRATCH: usize = 16 * 1024;

/// Reads through an initialised scratch buffer and copies into the cursor.
fn poll_read_scratch<R: AsyncRead + Unpin>(
    reader: &mut R,
    scratch: &mut [u8],
    cx: &mut Context<'_>,
    mut cursor: ReadBufCursor<'_>,
) -> Poll<io::Result<()>> {
    // SAFETY: only the length is read, no byte is read or written.
    let capacity = unsafe { cursor.as_mut() }.len();
    let want = capacity.min(scratch.len());
    let count = ready!(Pin::new(reader).poll_read(cx, &mut scratch[..want]))?;
    cursor.put_slice(&scratch[..count]);
    Poll::Ready(Ok(()))
}

/// Adapts a futures-I/O stream for Hyper without zero-filling the cursor.
pub(crate) struct FuturesIo<T> {
    inner: T,
    scratch: Box<[u8]>,
}

impl<T> FuturesIo<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            scratch: vec![0; TLS_SCRATCH].into_boxed_slice(),
        }
    }
}

impl<T: AsyncRead + Unpin> hyper::rt::Read for FuturesIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        cursor: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_read_scratch(&mut this.inner, &mut this.scratch, cx, cursor)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FuturesIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> hyper::rt::Write for FuturesIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FuturesIo<T> {
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

enum Inner {
    /// `AsyncStream` is `!Unpin`, so it lives behind a pinned box.
    Plain(Pin<Box<AsyncStream<TcpStream>>>),
    Tls(Box<FuturesIo<TlsStream<TcpStream>>>),
}

/// The connection type for every Hyper and tunnel path in this crate.
///
/// Compio sockets are `!Send`, but Hyper's upgrade machinery requires `Send`.
/// The runtime is single threaded per connection, so `SendWrapper` is sound
/// and panics if a stream is ever touched from another thread.
pub(crate) struct ProxyIo(SendWrapper<Inner>);

impl ProxyIo {
    pub(crate) fn plain(stream: TcpStream) -> Self {
        Self(SendWrapper::new(Inner::Plain(Box::pin(
            AsyncStream::with_capacity(IO_BUFFER, stream),
        ))))
    }

    /// compio-tls builds its inner `AsyncStream` with the default buffer size
    /// and offers no way to configure it, so TLS keeps the default.
    pub(crate) fn tls(stream: TlsStream<TcpStream>) -> Self {
        Self(SendWrapper::new(Inner::Tls(Box::new(FuturesIo::new(
            stream,
        )))))
    }
}

impl hyper::rt::Read for ProxyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut cursor: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self.get_mut().0 {
            Inner::Plain(stream) => {
                // SAFETY: `poll_read_uninit` only writes into the slice and
                // returns how many leading bytes it initialised.
                let uninit = unsafe { cursor.as_mut() };
                let count = ready!(stream.as_mut().poll_read_uninit(cx, uninit))?;
                // SAFETY: the first `count` bytes were just initialised.
                unsafe { cursor.advance(count) };
                Poll::Ready(Ok(()))
            }
            Inner::Tls(stream) => hyper::rt::Read::poll_read(Pin::new(&mut **stream), cx, cursor),
        }
    }
}

impl AsyncRead for ProxyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self.get_mut().0 {
            Inner::Plain(stream) => stream.as_mut().poll_read(cx, buf),
            Inner::Tls(stream) => AsyncRead::poll_read(Pin::new(&mut **stream), cx, buf),
        }
    }
}

impl AsyncWrite for ProxyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self.get_mut().0 {
            Inner::Plain(stream) => stream.as_mut().poll_write(cx, buf),
            Inner::Tls(stream) => AsyncWrite::poll_write(Pin::new(&mut **stream), cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut *self.get_mut().0 {
            Inner::Plain(stream) => stream.as_mut().poll_write_vectored(cx, bufs),
            Inner::Tls(stream) => {
                AsyncWrite::poll_write_vectored(Pin::new(&mut **stream), cx, bufs)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self.get_mut().0 {
            Inner::Plain(stream) => stream.as_mut().poll_flush(cx),
            Inner::Tls(stream) => AsyncWrite::poll_flush(Pin::new(&mut **stream), cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self.get_mut().0 {
            Inner::Plain(stream) => stream.as_mut().poll_close(cx),
            Inner::Tls(stream) => AsyncWrite::poll_close(Pin::new(&mut **stream), cx),
        }
    }
}

impl hyper::rt::Write for ProxyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write_vectored(self, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_close(self, cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, mem::MaybeUninit, time::Duration};

    use bytes::Bytes;
    use compio::{
        io::{AsyncWrite as _, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        runtime,
        time::{sleep, timeout},
    };
    use futures_util::io::{AsyncReadExt, Cursor};
    use http_body_util::Empty;
    use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};

    use super::*;
    use crate::TunnelIo;

    const SENTINEL: u8 = 0xAA;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, server) =
            futures_util::future::join(TcpStream::connect(address), listener.accept()).await;
        (client.unwrap(), server.unwrap().0)
    }

    /// Polls `hyper::rt::Read` into a sentinel-filled buffer and returns the
    /// buffer plus the filled length.
    async fn read_into_sentinel<R: hyper::rt::Read + Unpin>(
        reader: &mut R,
        size: usize,
    ) -> (Vec<MaybeUninit<u8>>, usize) {
        let mut storage = vec![MaybeUninit::new(SENTINEL); size];
        let mut buf = hyper::rt::ReadBuf::uninit(&mut storage);
        std::future::poll_fn(|cx| {
            hyper::rt::Read::poll_read(Pin::new(&mut *reader), cx, buf.unfilled())
        })
        .await
        .unwrap();
        let filled = buf.filled().len();
        (storage, filled)
    }

    fn tail_untouched(storage: &[MaybeUninit<u8>], filled: usize) -> bool {
        storage[filled..]
            .iter()
            .all(|byte| unsafe { byte.assume_init() } == SENTINEL)
    }

    #[compio::test]
    async fn plain_read_into_large_buffer_does_not_initialise_it() {
        let (mut client, server) = pair().await;
        let mut io = ProxyIo::plain(server);
        client.write_all(b"hello").await.0.unwrap();

        let (storage, filled) = read_into_sentinel(&mut io, 1024 * 1024).await;

        assert_eq!(filled, 5);
        let data: Vec<u8> = storage[..filled]
            .iter()
            .map(|b| unsafe { b.assume_init() })
            .collect();
        assert_eq!(data, b"hello");
        assert!(
            tail_untouched(&storage, filled),
            "cursor tail was overwritten"
        );
    }

    #[compio::test]
    async fn tls_path_read_does_not_initialise_cursor() {
        let mut io = FuturesIo::new(Cursor::new(b"hello".to_vec()));

        let (storage, filled) = read_into_sentinel(&mut io, 1024 * 1024).await;

        assert_eq!(filled, 5);
        assert!(
            tail_untouched(&storage, filled),
            "cursor tail was overwritten"
        );
    }

    #[compio::test]
    async fn eof_is_reported_as_an_empty_read() {
        let (client, server) = pair().await;
        let mut io = ProxyIo::plain(server);
        drop(client);

        let (_, filled) = read_into_sentinel(&mut io, 64).await;
        assert_eq!(filled, 0);
        let mut bytes = Vec::new();
        assert_eq!(
            AsyncReadExt::read_to_end(&mut io, &mut bytes)
                .await
                .unwrap(),
            0
        );
    }

    /// Runs one upgrade request through a real Hyper server on `ProxyIo` and
    /// checks what the tunnel side of the upgrade reads and that the downcast
    /// took the direct path.
    #[compio::test]
    async fn upgrade_downcast_delivers_prefix_before_stream_bytes_and_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let result = std::rc::Rc::new(std::cell::RefCell::new(None));
        let sender = result.clone();
        runtime::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    ProxyIo::plain(stream),
                    service_fn(move |mut request: Request<Incoming>| {
                        let upgrade = hyper::upgrade::on(&mut request);
                        let sender = sender.clone();
                        runtime::spawn(async move {
                            let mut io = TunnelIo::from_upgraded(upgrade.await.unwrap());
                            let direct = matches!(io, TunnelIo::Direct { .. });
                            let mut bytes = Vec::new();
                            AsyncReadExt::read_to_end(&mut io, &mut bytes)
                                .await
                                .unwrap();
                            *sender.borrow_mut() = Some((direct, bytes));
                        })
                        .detach();
                        async {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::SWITCHING_PROTOCOLS)
                                    .header("connection", "upgrade")
                                    .header("upgrade", "test")
                                    .body(Empty::<Bytes>::new())
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .with_upgrades()
                .await;
        })
        .detach();

        let mut client = TcpStream::connect(address).await.unwrap();
        // Prefix bytes arrive in the same packet as the request head.
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\nPREFIX"
                    .to_vec(),
            )
            .await
            .0
            .unwrap();
        sleep(Duration::from_millis(50)).await;
        client.write_all(b"-STREAM".to_vec()).await.0.unwrap();
        client.shutdown().await.unwrap();

        let (direct, bytes) = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(done) = result.borrow_mut().take() {
                    break done;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(direct, "Upgraded must downcast to ProxyIo");
        assert_eq!(bytes, b"PREFIX-STREAM");
    }
}

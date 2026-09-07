use std::{
    io::{Read, Write},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use compio::{net::TcpStream, runtime, time::timeout};
use cyper_core::HyperStream;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use msgtausch_config::Config;

use crate::ProxyRuntime;

#[compio::test]
async fn rejects_conflicting_upstream_framing_and_recovers() {
    timeout(Duration::from_secs(5), async {
        let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = runtime::spawn_blocking(move || {
            // Cover header order and case on both pooled and upgrade paths.
            for index in 0..8 {
                let (mut stream, _) = origin.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 8192);
                }
                if index % 2 == 0 {
                    let framing = if index % 4 == 0 {
                        "Content-Length: 5\r\nTransfer-Encoding: chunked"
                    } else {
                        "tRaNsFeR-EnCoDiNg: chunked\r\ncOnTeNt-LeNgTh: 5"
                    };
                    write!(stream,
                        "HTTP/1.1 200 OK\r\n{framing}\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                    ).unwrap();
                } else {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                }
            }
        });

        let listener = compio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy = Arc::new(ProxyRuntime::with_noop_metrics(&Config::default()).unwrap());
        let proxy_task = runtime::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            proxy.serve_connection(stream, peer).await.unwrap();
        });
        let stream = TcpStream::connect(proxy_address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(
            HyperStream::new_plain(stream),
        ).await.unwrap();
        let client_task = runtime::spawn(async move { let _ = connection.with_upgrades().await; });
        for index in 0..8 {
            sender.ready().await.unwrap();
            let mut request = Request::builder().uri(format!("http://{origin_address}/{index}"));
            if index >= 4 && index % 2 == 0 {
                request = request.header("Connection", "upgrade").header("Upgrade", "test");
            }
            let response = sender.send_request(request.body(Full::new(Bytes::new())).unwrap()).await.unwrap();
            let expected = if index % 2 == 0 { StatusCode::BAD_GATEWAY } else { StatusCode::OK };
            assert_eq!(response.status(), expected, "response {index} must reject conflicting framing before forwarding");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            if index % 2 != 0 { assert_eq!(body, b"ok".as_slice()); }
        }
        drop(sender);
        client_task.await.unwrap();
        proxy_task.await.unwrap();
        origin_task.await.unwrap();
    }).await.expect("framing rejection and recovery must not stall");
}

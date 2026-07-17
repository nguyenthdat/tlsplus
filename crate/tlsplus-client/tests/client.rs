use std::{convert::Infallible, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tlsplus_client::{Client, StatusCode};
use tokio::{net::TcpListener, sync::mpsc};

#[derive(Debug)]
struct CapturedRequest {
    method: hyper::Method,
    path_and_query: String,
    headers: hyper::HeaderMap,
    body: Bytes,
}

async fn spawn_test_server() -> (String, mpsc::UnboundedReceiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local test server");
    let address = listener.local_addr().expect("local address");
    let (sender, receiver) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept client");
        let service = service_fn(move |request: Request<Incoming>| {
            let sender = sender.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = body
                    .collect()
                    .await
                    .expect("collect request body")
                    .to_bytes();
                sender
                    .send(CapturedRequest {
                        method: parts.method,
                        path_and_query: parts
                            .uri
                            .path_and_query()
                            .map_or_else(|| "/".to_owned(), ToString::to_string),
                        headers: parts.headers,
                        body,
                    })
                    .expect("capture request");

                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .header("content-type", "application/json")
                        .header("x-test-server", "tlsplus")
                        .body(Full::new(Bytes::from_static(br#"{"accepted":true}"#)))
                        .expect("build response"),
                )
            }
        });

        http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("serve local request");
    });

    (format!("http://{address}/submit"), receiver)
}

#[derive(Debug, Serialize)]
struct Payload<'a> {
    name: &'a str,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Reply {
    accepted: bool,
}

#[tokio::test]
async fn ergonomic_client_sends_json_through_core_without_external_network() {
    let (url, mut captured) = spawn_test_server().await;
    let client = Client::builder()
        .profile("pass-through")
        .timeout(Duration::from_secs(5))
        .default_header("x-client-default", "default")
        .build()
        .expect("valid client");

    let response = client
        .post(url)
        .query(&[("source", "tls plus")])
        .header("x-client-default", "request")
        .json(&Payload { name: "demo" })
        .send()
        .await
        .expect("request succeeds")
        .error_for_status()
        .expect("201 is successful");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.profile(), "pass-through");
    assert_eq!(response.headers()["x-test-server"], "tlsplus");
    let reply: Reply = response.json().await.expect("decode response JSON");
    assert_eq!(reply, Reply { accepted: true });

    let captured = captured.recv().await.expect("captured request");
    assert_eq!(captured.method, hyper::Method::POST);
    assert_eq!(captured.path_and_query, "/submit?source=tls+plus");
    assert_eq!(captured.headers["x-client-default"], "request");
    assert_eq!(captured.headers["content-type"], "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&captured.body).expect("request JSON"),
        serde_json::json!({"name": "demo"})
    );
}

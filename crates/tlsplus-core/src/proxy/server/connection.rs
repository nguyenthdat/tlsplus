use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;

use crate::proxy::{service::proxy_service, websocket};

pub(super) async fn run(
    stream: tokio::net::TcpStream,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let io = TokioIo::new(stream);
    let (bridge_tx, mut bridge_rx) = mpsc::channel(1);
    let service = service_fn(move |request| proxy_service(request, bridge_tx.clone()));
    let connection = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades();
    tokio::pin!(connection);

    tokio::select! {
        biased;
        _ = shutdown.changed() => {}
        bridge = bridge_rx.recv() => {
            if let Some(job) = bridge {
                let tunnel = async {
                    let bridge = websocket::run_bridge(job);
                    tokio::join!(&mut connection, bridge)
                };
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => {}
                    (connection_result, bridge_result) = tunnel => {
                        log_result(connection_result);
                        if let Err(error) = bridge_result {
                            eprintln!("tlsplus proxy: {error}");
                        }
                    }
                }
            }
        }
        result = &mut connection => {
            log_result(result);
            if let Ok(job) = bridge_rx.try_recv() {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => {}
                    bridge_result = websocket::run_bridge(job) => {
                        if let Err(error) = bridge_result {
                            eprintln!("tlsplus proxy: {error}");
                        }
                    }
                }
            }
        },
    }
}

fn log_result(result: Result<(), hyper::Error>) {
    if let Err(error) = result
        && !error.to_string().contains("connection closed")
        && !error.to_string().contains("broken pipe")
        && !error.to_string().contains("protocol error")
    {
        eprintln!("tlsplus proxy: connection error: {error}");
    }
}

use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::{sync::mpsc, task::JoinSet};

use crate::proxy::{service::proxy_service, websocket};

pub(super) async fn run(
    stream: tokio::net::TcpStream,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let io = TokioIo::new(stream);
    let (bridge_tx, mut bridge_rx) = mpsc::channel(1);
    let service = service_fn(move |request| proxy_service(request, bridge_tx.clone()));
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .title_case_headers(true);
    builder.http2().enable_connect_protocol();
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);
    let mut bridges = JoinSet::new();
    let mut connection_finished = false;
    let mut bridge_channel_open = true;

    loop {
        if connection_finished && bridges.is_empty() {
            return;
        }

        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            bridge = bridge_rx.recv(), if bridge_channel_open => {
                match bridge {
                    Some(job) => {
                        bridges.spawn(websocket::run_bridge(job));
                    }
                    None => bridge_channel_open = false,
                }
            },
            result = &mut connection, if !connection_finished => {
                log_result(result);
                connection_finished = true;
                while let Ok(job) = bridge_rx.try_recv() {
                    bridges.spawn(websocket::run_bridge(job));
                }
            },
            Some(result) = bridges.join_next(), if !bridges.is_empty() => {
                log_bridge_result(result);
            },
        }
    }

    bridges.abort_all();
    while bridges.join_next().await.is_some() {}
}

fn log_bridge_result(result: Result<Result<(), String>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("tlsplus proxy: {error}"),
        Err(error) if error.is_cancelled() => {}
        Err(error) => eprintln!("tlsplus proxy: bridge task failed: {error}"),
    }
}

fn log_result<E>(result: Result<(), E>)
where
    E: std::fmt::Display,
{
    if let Err(error) = result {
        let message = error.to_string();
        if !message.contains("connection closed")
            && !message.contains("broken pipe")
            && !message.contains("protocol error")
        {
            eprintln!("tlsplus proxy: connection error: {error}");
        }
    }
}

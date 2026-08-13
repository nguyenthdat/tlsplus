use std::net::SocketAddr;

use tokio::{net::TcpListener, task::JoinSet};

use crate::{SERVER_STATE, ServerShutdown, ServerStatus};

use super::RUNTIME;

mod connection;

const CONNECTION_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);
const SERVER_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

pub fn start_local_server_impl(listen_addr: String) -> ServerStatus {
    let mut state = SERVER_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if state.running {
        return ServerStatus {
            running: true,
            listen_addr: state.listen_addr.clone(),
            message: "Server is already running".to_owned(),
        };
    }

    let addr: SocketAddr = match listen_addr.parse() {
        Ok(addr) => addr,
        Err(error) => {
            return ServerStatus {
                running: false,
                listen_addr: None,
                message: format!("Invalid listen address '{listen_addr}': {error}"),
            };
        }
    };

    let runtime = match &*RUNTIME {
        Ok(runtime) => runtime,
        Err(error) => {
            return ServerStatus {
                running: false,
                listen_addr: None,
                message: error.clone(),
            };
        }
    };
    let (listener, listen_addr) = match std::net::TcpListener::bind(addr).and_then(|listener| {
        let listen_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let _runtime_guard = runtime.enter();
        TcpListener::from_std(listener).map(|listener| (listener, listen_addr))
    }) {
        Ok(listener) => listener,
        Err(error) => {
            return ServerStatus {
                running: false,
                listen_addr: None,
                message: format!("failed to bind {addr}: {error}"),
            };
        }
    };
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let (completion_tx, completion_rx) = std::sync::mpsc::channel();
    runtime.spawn(async move {
        let (connection_shutdown_tx, connection_shutdown_rx) = tokio::sync::watch::channel(false);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    let _ = connection_shutdown_tx.send(true);
                    break;
                }
                accept = listener.accept() => match accept {
                    Ok((stream, _)) => {
                        connections.spawn(connection::run(stream, connection_shutdown_rx.clone()));
                    }
                    Err(error) => eprintln!("tlsplus proxy: accept error: {error}"),
                },
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        eprintln!("tlsplus proxy: connection task failed: {error}");
                    }
                }
            }
        }
        drop(listener);

        let drain = async {
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    eprintln!("tlsplus proxy: connection task failed: {error}");
                }
            }
        };
        if tokio::time::timeout(CONNECTION_SHUTDOWN_GRACE, drain)
            .await
            .is_err()
        {
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
        let _ = completion_tx.send(());
    });

    state.running = true;
    let listen_addr = listen_addr.to_string();
    state.listen_addr = Some(listen_addr.clone());
    state.shutdown = Some(ServerShutdown {
        sender: shutdown_tx,
        completion: completion_rx,
    });
    ServerStatus {
        running: true,
        listen_addr: Some(listen_addr),
        message: "Local HTTP forward proxy started".to_owned(),
    }
}

pub fn server_status_impl() -> ServerStatus {
    match SERVER_STATE.lock() {
        Ok(state) => ServerStatus {
            running: state.running,
            listen_addr: state.listen_addr.clone(),
            message: if state.running {
                format!(
                    "Server is running{}",
                    state
                        .listen_addr
                        .as_deref()
                        .map(|address| format!(" on {address}"))
                        .unwrap_or_default()
                )
            } else {
                "Server is stopped".to_owned()
            },
        },
        Err(_) => ServerStatus {
            running: false,
            listen_addr: None,
            message: "Server state lock poisoned — restart recommended".to_owned(),
        },
    }
}

pub fn stop_local_server_impl() -> ServerStatus {
    let mut state = SERVER_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous_addr = state.listen_addr.take();
    if let Some(shutdown) = state.shutdown.take() {
        let _ = shutdown.sender.send(());
        let completed = shutdown
            .completion
            .recv_timeout(SERVER_STOP_TIMEOUT)
            .is_ok();
        state.running = false;
        ServerStatus {
            running: false,
            listen_addr: previous_addr,
            message: if completed {
                "Local HTTP forward proxy stopped".to_owned()
            } else {
                "Local HTTP forward proxy stop timed out".to_owned()
            },
        }
    } else {
        state.running = false;
        ServerStatus {
            running: false,
            listen_addr: previous_addr,
            message: "Server was not running".to_owned(),
        }
    }
}

async fn send_request(request: crate::ProxyRequest) -> crate::ProxyResponse {
    let result = super::forward::forward_request(
        &request.url,
        &request.method,
        request.headers,
        request.body,
        &request.profile,
        request.timeout_secs,
    )
    .await;

    match result {
        Ok(mut response) => {
            response.id = request.id;
            response
        }
        Err(error) => crate::ProxyResponse {
            id: request.id,
            status_code: 0,
            headers: vec![],
            body: vec![],
            ja4: None,
            error: Some(error),
        },
    }
}

pub async fn proxy_send_request_async_impl(request: crate::ProxyRequest) -> crate::ProxyResponse {
    send_request(request).await
}

pub fn proxy_send_request_impl(request: crate::ProxyRequest) -> crate::ProxyResponse {
    match &*RUNTIME {
        Ok(runtime) => runtime.block_on(send_request(request)),
        Err(error) => crate::ProxyResponse {
            id: request.id,
            status_code: 0,
            headers: vec![],
            body: vec![],
            ja4: None,
            error: Some(error.clone()),
        },
    }
}

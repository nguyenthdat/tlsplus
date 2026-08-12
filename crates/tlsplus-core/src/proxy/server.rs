use std::{net::SocketAddr, sync::Arc};

use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::{SERVER_STATE, ServerStatus};

use super::{RUNTIME, service::proxy_service};

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

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let shutdown_notify_clone = Arc::clone(&shutdown_notify);
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
    runtime.spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("tlsplus proxy: failed to bind {addr}: {error}");
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown_notify_clone.notified() => break,
                accept = listener.accept() => match accept {
                    Ok((stream, _)) => {
                        let io = TokioIo::new(stream);
                        tokio::spawn(async move {
                            if let Err(error) = http1::Builder::new()
                                .preserve_header_case(true)
                                .title_case_headers(true)
                                .serve_connection(io, service_fn(proxy_service))
                                .await
                                && !error.to_string().contains("connection closed")
                                && !error.to_string().contains("broken pipe")
                                && !error.to_string().contains("protocol error")
                            {
                                eprintln!("tlsplus proxy: connection error: {error}");
                            }
                        });
                    }
                    Err(error) => eprintln!("tlsplus proxy: accept error: {error}"),
                },
            }
        }
    });

    state.running = true;
    state.listen_addr = Some(listen_addr.clone());
    state.shutdown_notify = Some(shutdown_notify);
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
    if let Some(notify) = state.shutdown_notify.take() {
        notify.notify_one();
        state.running = false;
        ServerStatus {
            running: false,
            listen_addr: previous_addr,
            message: "Local HTTP forward proxy stopped".to_owned(),
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

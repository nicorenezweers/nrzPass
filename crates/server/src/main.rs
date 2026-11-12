//! nrzPass-Server. `nrzpass` startet den Server, `nrzpass healthcheck` prueft ihn (Docker).

use nrzpass_server::Config;
use std::net::SocketAddr;

fn healthcheck(port: u16) -> i32 {
    use std::io::{Read, Write};
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3)) else { return 1 };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(3)));
    if s.write_all(b"GET /alive HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").is_err() {
        return 1;
    }
    let mut buf = [0u8; 16];
    match s.read(&mut buf) {
        Ok(n) if n >= 12 && &buf[9..12] == b"200" => 0,
        _ => 1,
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    eprintln!("nrzPass: wird beendet …");
}

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
    match std::env::args().nth(1).as_deref() {
        Some("healthcheck") => std::process::exit(healthcheck(cfg.port)),
        Some("--version") | Some("-V") => {
            println!("nrzpass {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some(other) => {
            eprintln!("Unbekannter Befehl: {other}. Aufruf: nrzpass [healthcheck|--version]");
            std::process::exit(2);
        }
        None => {}
    }
    let addr = format!("{}:{}", cfg.address, cfg.port);
    let app = match nrzpass_server::build(cfg).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("nrzPass: Start fehlgeschlagen: {e}");
            std::process::exit(1);
        }
    };
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("nrzPass: {addr} nicht verfuegbar: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("nrzPass {} laeuft auf http://{addr}", env!("CARGO_PKG_VERSION"));
    if let Err(e) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("nrzPass: Serverfehler: {e}");
        std::process::exit(1);
    }
}

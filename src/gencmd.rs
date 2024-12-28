use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper::{body, Request, Response};
use hyper_util::rt::tokio::TokioIo;
use log::{debug, info};
use tokio::net::{TcpListener, TcpStream};

use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;

use crate::assume_socket_addr_v4;
use crate::ssh::Server;

const GENCMD_SALT: &'static str = "not really random";

/// Get the hash of a tunnel. We use
///
///   - the destination of forwarding, and
///   - the SSH client IP
///
/// to uniquely identify a tunnel, or a forwarding session, so that the same SSH client is able to
/// create multiple forwarding, and multiple clients can forward to the same destination. A salt is
/// appended to prevent the client from accessing the tunnel with a forged hash without ever running
/// the `ssh -R` command.
pub fn hash_tunnel(dest_addr: SocketAddrV4, client_ip: Ipv4Addr) -> Result<u32, anyhow::Error> {
    let mut cursor = Cursor::new(Vec::new());

    Write::write(
        &mut cursor,
        dest_addr.ip().to_bits().to_le_bytes().as_slice(),
    )?;

    Write::write(&mut cursor, dest_addr.port().to_le_bytes().as_slice())?;
    Write::write(&mut cursor, client_ip.to_bits().to_le_bytes().as_slice())?;
    Write::write(&mut cursor, GENCMD_SALT.as_bytes())?;

    cursor.set_position(0);

    murmur3::murmur3_x64_128(&mut cursor, 0)
        .map(|x| x as u32)
        .map_err(|e| e.into())
}

async fn handle_unregister(
    dest_addr: &str,
    client_addr: SocketAddrV4,
    server: Arc<Server>,
) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let resp = Response::builder().header("Server", env!("CARGO_CRATE_NAME"));
    let dest_addr = match SocketAddrV4::from_str(dest_addr) {
        Ok(addr) => addr,
        Err(e) => {
            return resp
                .status(400)
                .body(Full::new(Bytes::from(format!(
                    "Invalid destination {dest_addr}: {e}"
                ))))
                .map_err(|e| e.into());
        }
    };

    let hash = match hash_tunnel(dest_addr, *client_addr.ip()) {
        Ok(h) => h,
        Err(_) => {
            return resp
                .status(500)
                .body(Full::new(Bytes::new()))
                .map_err(|e| e.into())
        }
    };

    if let Err(e) = server.unregister_tunnel(hash).await {
        return resp
            .status(500)
            .body(Full::new(Bytes::from(e.to_string())))
            .map_err(|e| e.into());
    }

    resp.status(200)
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.into())
}

// To eliminate the repetition we can implement custom axum extractors
// to convert `dest_addr` and `client_addr` to `SocketAddrV4`.
async fn handle_register(
    dest_addr: &str,
    server_addr: SocketAddrV4,
    client_addr: SocketAddrV4,
    ssh_port: u16,
    server: Arc<Server>,
) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let resp = Response::builder().header("Server", env!("CARGO_CRATE_NAME"));
    let dest_addr = match SocketAddrV4::from_str(dest_addr) {
        Ok(addr) => addr,
        Err(e) => {
            return resp
                .status(400)
                .body(Full::new(Bytes::from(format!(
                    "Invalid destination {dest_addr}: {e}"
                ))))
                .map_err(|e| e.into())
        }
    };

    let hash = match hash_tunnel(dest_addr, *client_addr.ip()) {
        Ok(h) => h,
        Err(_) => {
            return resp
                .status(500)
                .body(Full::new(Bytes::new()))
                .map_err(|e| e.into())
        }
    };
    if let Err(e) = server.register_tunnel(hash).await {
        return resp
            .status(500)
            .body(Full::new(Bytes::from(format!("{e}"))))
            .map_err(|e| e.into());
    }

    let mut cmd = format!(
        "ssh -R {}:{}:{}",
        crate::FORWARDED_PORT,
        dest_addr.ip(),
        dest_addr.port(),
    );
    if ssh_port != crate::DEFAULT_SSH_PORT {
        cmd.push_str(format!(" -p {}", ssh_port).as_str());
    }
    cmd.push_str(format!(" {:x}@{}\r\n", hash, server_addr.ip()).as_str());

    resp.status(200)
        .body(Full::new(Bytes::from(cmd)))
        .map_err(|e| e.into())
}

async fn handle_request(
    req: Request<body::Incoming>,
    server_addr: SocketAddrV4,
    client_addr: SocketAddrV4,
    ssh_port: u16,
    server: Arc<Server>,
) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let resp = Response::builder().header("Server", env!("CARGO_CRATE_NAME"));

    let path: Vec<&str> = req.uri().path().split('/').collect();
    if path.len() != 3 {
        return resp
            .status(400)
            .body(Full::new(Bytes::new()))
            .map_err(|e| e.into());
    }

    match path[1] {
        "register" => {
            handle_register(path[2], server_addr, client_addr, ssh_port, server.clone()).await
        }
        "unregister" => handle_unregister(path[2], client_addr, server.clone()).await,
        _ => unreachable!(),
    }
}

async fn handle_stream(
    stream: TcpStream,
    server_addr: SocketAddrV4,
    client_addr: SocketAddrV4,
    ssh_port: u16,
    server: Arc<Server>,
) -> Result<(), anyhow::Error> {
    let io = TokioIo::new(stream);
    Builder::new()
        .serve_connection(
            io,
            service_fn(|req| {
                handle_request(req, server_addr, client_addr, ssh_port, server.clone())
            }),
        )
        .await
        .map_err(|e| e.into())
}

pub async fn run(port: u16, ssh_port: u16, server: Arc<Server>) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;

    info!("listening on {port}");

    loop {
        let (stream, client_addr) = listener.accept().await?;
        let server_addr = assume_socket_addr_v4(stream.local_addr()?);
        let client_addr = assume_socket_addr_v4(client_addr);

        debug!("accept new connection from client {client_addr:?}");

        tokio::spawn(handle_stream(
            stream,
            server_addr,
            client_addr,
            ssh_port,
            server.clone(),
        ));
    }
}

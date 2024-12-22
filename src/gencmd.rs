use anyhow::anyhow;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path};
use axum::http::{Response, StatusCode};
use axum::routing::post;
use axum::Router;
use http_body_util::Full;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;

use crate::assume_socket_addr_v4;
use crate::ssh::Server;

const GENCMD_SALT: &'static str = "not really random";

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
    Path(dest_addr): Path<String>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    server: Arc<Server>,
) -> Response<Body> {
    let resp = Response::builder().header("Server", env!("CARGO_CRATE_NAME"));
    let client_addr = assume_socket_addr_v4(client_addr);
    let dest_addr = match SocketAddrV4::from_str(dest_addr.as_str()) {
        Ok(addr) => addr,
        Err(e) => {
            return resp
                .status(400)
                .body(Body::from(format!("Invalid destination {dest_addr}: {e}")))
                .unwrap()
        }
    };
    let hash = match hash_tunnel(dest_addr, *client_addr.ip()) {
        Ok(h) => h,
        Err(e) => return resp.status(500).body(Body::empty()).unwrap(),
    };

    server.unregister_tunnel(hash);

    return resp.status(200).body(Body::empty()).unwrap();
}

// XXX implement custom extractor to convert dest_addr and client_addr to SocketAddrV4
async fn handle_register(
    Path(dest_addr): Path<String>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    server_addr: SocketAddrV4,
    ssh_port: u16,
    server: Arc<Server>,
) -> Response<Body> {
    let resp = Response::builder().header("Server", env!("CARGO_CRATE_NAME"));
    let client_addr = assume_socket_addr_v4(client_addr);
    let dest_addr = match SocketAddrV4::from_str(dest_addr.as_str()) {
        Ok(addr) => addr,
        Err(e) => {
            return resp
                .status(400)
                .body(Body::from(format!("Invalid destination {dest_addr}: {e}")))
                .unwrap()
        }
    };
    let hash = match hash_tunnel(dest_addr, *client_addr.ip()) {
        Ok(h) => h,
        Err(e) => return resp.status(500).body(Body::empty()).unwrap(),
    };

    if let Err(e) = server.register_tunnel(hash, dest_addr).await {
        return resp.status(500).body(Body::from(format!("{e}"))).unwrap();
    }

    let mut cmd = format!(
        "ssh -R 1:{}:{} {:x}@{}",
        dest_addr.ip(),
        dest_addr.port(),
        hash,
        server_addr.ip(),
    );
    if ssh_port != crate::DEFAULT_SSH_PORT {
        cmd.push_str(format!(":{}", ssh_port).as_str());
    }
    return resp.status(200).body(Body::from(cmd)).unwrap();
}

pub async fn run(
    gencmd_port: u16,
    ssh_port: u16,
    server: Arc<Server>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", gencmd_port)).await?;
    let server_addr = assume_socket_addr_v4(listener.local_addr()?);
    let s = server.clone();
    let app = Router::new()
        .route(
            "/register/:dest_addr",
            post(move |dest_addr, client_addr| {
                handle_register(dest_addr, client_addr, server_addr, ssh_port, s)
            }),
        )
        .route(
            "/unregister/:dest_addr",
            post(move |dest_addr, client_addr| handle_unregister(dest_addr, client_addr, server)),
        );

    println!("gencmd on {} ...", gencmd_port);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| e.into())
}

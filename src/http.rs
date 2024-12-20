use anyhow::anyhow;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper::{body, Request, Response};
use hyper_util::rt::tokio::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::ssh::Server;

use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;

async fn serialize_request(req: Request<body::Incoming>) -> Result<Vec<u8>, anyhow::Error> {
    let mut bytes = Vec::new();

    Write::write(
        &mut bytes,
        format!(
            "{} {} {:?}\r\n",
            req.method().clone(),
            req.uri().to_string(),
            req.version()
        )
        .as_bytes(),
    )?;

    for (name, value) in req.headers() {
        Write::write(
            &mut bytes,
            format!("{}: {}\r\n", name, value.to_str()?).as_bytes(),
        )?;
    }

    Write::write(&mut bytes, b"\r\n")?;

    let body = req.into_body().collect().await?;
    Write::write(&mut bytes, body.to_bytes().as_ref())?;

    Ok(bytes)
}

async fn handle_request(
    req: Request<body::Incoming>,
    server: Arc<Server>,
) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let hash = match u32::from_str_radix(req.uri().path(), 16) {
        Ok(hash) => (),
        Err(_) => {
            return Response::builder()
                .status(400)
                .header("Server", env!("CARGO_CRATE_NAME"))
                .body(Full::new(Bytes::from("Invalid tunnel.\n")))
                .map_err(|e| e.into());
        }
    };

    let serialized = serialize_request(req).await;

    Err(anyhow!("shit"))
}

async fn handle_stream(stream: TcpStream, server: Arc<Server>) -> Result<(), anyhow::Error> {
    let io = TokioIo::new(stream);
    Builder::new()
        .serve_connection(io, service_fn(|req| handle_request(req, server.clone())))
        .await
        .map_err(|e| e.into())
}

pub async fn run_http(port: u16, server: Arc<Server>) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;

    loop {
        println!("http on {} ...", port);
        let (mut stream, client_addr) = listener.accept().await?;
        println!("http conn from {:?}", client_addr);
        tokio::spawn(handle_stream(stream, server.clone()));
    }
}

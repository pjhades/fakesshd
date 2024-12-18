use http_body_util::Full;

use hyper::body::Bytes;
use hyper::rt::Executor;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper::{body, Request, Response};
use hyper_util::rt::tokio::TokioIo;

use tokio::net::TcpListener;

use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;

use anyhow::anyhow;

pub const GENCMD_SALT: &'static str = "not really random";

fn extract_ip_port(path: &str) -> Result<SocketAddrV4, anyhow::Error> {
    let path = path
        .strip_prefix('/')
        .ok_or(anyhow!("path doesn't start with /"))?;
    SocketAddrV4::from_str(path).map_err(|e| e.into())
}

async fn handle_request(
    req: Request<body::Incoming>,
    server_addr: SocketAddrV4,
) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let uri = req.uri();
    let dest_addr = match extract_ip_port(uri.path()) {
        Ok(a) => a,
        Err(e) => {
            return Response::builder()
                .status(400)
                .header("Server", env!("CARGO_CRATE_NAME"))
                .body(Full::new(Bytes::from("bad")))
                .map_err(|e| e.into());
        }
    };

    let mut cursor = Cursor::new(Vec::new());
    cursor.write(dest_addr.ip().to_bits().to_le_bytes().as_slice())?;
    cursor.write(dest_addr.port().to_le_bytes().as_slice())?;
    cursor.write(GENCMD_SALT.as_bytes())?;

    let hash = murmur3::murmur3_32(&mut cursor, 0)?;
    let mut message = format!(
        "ssh -R 1:{}:{} {}@{}",
        dest_addr.ip(),
        dest_addr.port(),
        hash,
        server_addr.ip(),
    );
    if server_addr.port() != crate::DEFAULT_SSH_PORT {
        message.push_str(format!(":{}", server_addr.port()).as_str());
    }

    Response::builder()
        .status(200)
        .header("Server", env!("CARGO_CRATE_NAME"))
        .body(Full::new(Bytes::from(message)))
        .map_err(|e| e.into())
}

pub async fn run(port: u16) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;

    loop {
        println!("gencmd on {} ...", port);
        let (mut stream, client_addr) = listener.accept().await?;
        println!("conn from {:?}", client_addr);
        let io = TokioIo::new(stream);
        let server_addr = match listener.local_addr()? {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(addr) => return Err(anyhow!("IPv6 is not supported now")),
        };
        tokio::spawn(async move {
            if let Err(e) = Builder::new()
                .serve_connection(io, service_fn(|req| handle_request(req, server_addr)))
                .await
            {
                eprintln!("too bad {}", e);
            }
        });
    }

    unreachable!();
}

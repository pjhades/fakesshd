use http_body_util::Full;

use hyper::body::Bytes;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper::{body, Request, Response};
use hyper_util::rt::tokio::TokioIo;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;

use anyhow::anyhow;

const GENCMD_SALT: &'static str = "not really random";

fn extract_ip_port(path: &str) -> Result<SocketAddrV4, anyhow::Error> {
    let path = path
        .strip_prefix('/')
        .ok_or(anyhow!("path doesn't start with /"))?;
    SocketAddrV4::from_str(path).map_err(|e| e.into())
}

// XXX This only hashes the client IP, not the forward destination. So, if one client wants to
// forward to multiple destinations, the hash will be the same and thus the server won't be able
// to distinguish the different tunnels.
pub fn hash_client(client_ip: Ipv4Addr) -> Result<u32, anyhow::Error> {
    let mut cursor = Cursor::new(Vec::new());
    Write::write(&mut cursor, client_ip.to_bits().to_le_bytes().as_slice())?;
    Write::write(&mut cursor, GENCMD_SALT.as_bytes())?;
    cursor.set_position(0);
    murmur3::murmur3_x64_128(&mut cursor, 0)
        .map(|x| x as u32)
        .map_err(|e| e.into())
}

async fn handle_request(
    req: Request<body::Incoming>,
    client_addr: SocketAddrV4,
    server_addr: SocketAddrV4,
    ssh_port: u16,
) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let uri = req.uri();
    let local_addr = match extract_ip_port(uri.path()) {
        Ok(a) => a,
        Err(e) => {
            println!("{e}");
            return Response::builder()
                .status(400)
                .header("Server", env!("CARGO_CRATE_NAME"))
                .body(Full::new(Bytes::from("bad")))
                .map_err(|e| e.into());
        }
    };

    let hash = hash_client(*client_addr.ip())?;
    let mut message = format!(
        "ssh -R 1:{}:{} {:x}@{}\n",
        local_addr.ip(),
        local_addr.port(),
        hash,
        server_addr.ip(),
    );
    if ssh_port != crate::DEFAULT_SSH_PORT {
        message.push_str(format!(":{}", ssh_port).as_str());
    }

    Response::builder()
        .status(200)
        .header("Server", env!("CARGO_CRATE_NAME"))
        .body(Full::new(Bytes::from(message)))
        .map_err(|e| e.into())
}

pub async fn run(gencmd_port: u16, ssh_port: u16) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", gencmd_port)).await?;

    loop {
        println!("gencmd on {} ...", gencmd_port);
        let (mut stream, client_addr) = listener.accept().await?;
        println!("conn from {:?}", client_addr);
        let client_addr = match client_addr {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(addr) => {
                stream.shutdown().await?;
                return Err(anyhow!("unexpected IPv6 address {addr}"));
            }
        };
        let server_addr = match listener.local_addr()? {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(addr) => {
                stream.shutdown().await?;
                return Err(anyhow!("unexpected IPv6 address {addr}"));
            }
        };

        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            if let Err(e) = Builder::new()
                .serve_connection(
                    io,
                    service_fn(|req| handle_request(req, client_addr, server_addr, ssh_port)),
                )
                .await
            {
                eprintln!("too bad {}", e);
            }
        });
    }
}

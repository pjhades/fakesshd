use anyhow::anyhow;
use http::header::{HeaderName, HeaderValue};
use http::uri::PathAndQuery;
use http_body_util::{BodyExt, Full};
use httparse::{Response as ParsedResponse, Status, EMPTY_HEADER};
use hyper::body::Bytes;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper::{body, Request, Response, Uri};
use hyper_util::rt::tokio::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Receiver;

use crate::assume_socket_addr_v4;
use crate::ssh::Server;

use std::io::Write;
use std::net::SocketAddrV4;
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

fn deserialize_response(data: &[u8]) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let mut headers = [EMPTY_HEADER; 32];
    let mut resp = ParsedResponse::new(&mut headers);
    let body_start = match resp.parse(data) {
        Err(e) => return Err(anyhow!("response parse error: {e}")),
        Ok(Status::Complete(pos)) => pos,
        Ok(Status::Partial) => return Err(anyhow!("incomplete response")),
    };

    let body = Full::new(body::Bytes::copy_from_slice(&data[body_start..]));
    let status = resp.code.ok_or(anyhow!("no status code in response"))?;
    let mut builder = Response::builder().status(status);
    for h in resp.headers {
        let k = HeaderName::from_bytes(h.name.as_bytes()).map_err(|e| anyhow::Error::from(e))?;
        let v = HeaderValue::from_bytes(h.value).map_err(|e| anyhow::Error::from(e))?;
        builder = builder.header(k, v);
    }

    builder.body(body).map_err(|e| e.into())
}

async fn wait_for_response(
    mut rx: Receiver<Vec<u8>>,
) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let mut buf = Vec::new();
    while let Some(ref mut data) = rx.recv().await {
        buf.append(data);
    }
    deserialize_response(buf.as_slice())
}

async fn handle_request(
    mut req: Request<body::Incoming>,
    client_addr: SocketAddrV4,
    server: Arc<Server>,
) -> Result<Response<Full<body::Bytes>>, anyhow::Error> {
    let resp = Response::builder().header("Server", env!("CARGO_CRATE_NAME"));

    let mut parts = req.uri().clone().into_parts();
    let path = req.uri().path_and_query().unwrap();
    let split: Vec<&str> = path.as_str().split('/').collect();
    if split.len() < 3 {
        return resp
            .status(400)
            .body(Full::new(Bytes::from("Invalid tunnel")))
            .map_err(|e| e.into());
    }
    let hash = match u32::from_str_radix(split[1], 16) {
        Ok(h) => h,
        Err(_) => {
            return resp
                .status(400)
                .body(Full::new(Bytes::from("Invalid tunnel")))
                .map_err(|e| e.into());
        }
    };

    // Modify the query path since it begins with the hash, which is unknown to the destination.
    // For example, /<hash>/foo/bar?x=1&y=2 should be modified as /foo/bar?x=1&y=2.
    let mut modified_path = String::from("/");
    modified_path.push_str(&split[2..].join("/"));
    parts.path_and_query = Some(PathAndQuery::from_maybe_shared(modified_path).unwrap());
    *req.uri_mut() = Uri::from_parts(parts).unwrap();

    let tunnel = server.open_tunnel(hash, client_addr).await?;
    let serialized = serialize_request(req).await?;
    let rx = tunnel
        .forward(serialized.as_slice(), server.clone())
        .await?;
    let resp = wait_for_response(rx).await?;
    Ok(resp)
}

async fn handle_stream(
    stream: TcpStream,
    client_addr: SocketAddrV4,
    server: Arc<Server>,
) -> Result<(), anyhow::Error> {
    let io = TokioIo::new(stream);
    Builder::new()
        .serve_connection(
            io,
            service_fn(|req| handle_request(req, client_addr, server.clone())),
        )
        .await
        .map_err(|e| e.into())
}

pub async fn run_http(port: u16, server: Arc<Server>) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;

    loop {
        println!("http on {} ...", port);
        let (stream, client_addr) = listener.accept().await?;
        let client_addr = assume_socket_addr_v4(client_addr);
        println!("http conn from {:?}", client_addr);
        tokio::spawn(handle_stream(stream, client_addr, server.clone()));
    }
}

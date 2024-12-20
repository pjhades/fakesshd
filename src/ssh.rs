use async_trait::async_trait;
//use log::{info, warn};
use anyhow::anyhow;
use russh::server::{run_stream, Auth, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodSet};
use ssh_key::rand_core::OsRng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::gencmd;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub struct Server {
    tunnels: Mutex<BTreeMap<ChannelId, Channel<Msg>>>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            tunnels: Mutex::new(BTreeMap::new()),
        }
    }
}

struct SessionHandler {
    server: Arc<Server>,
    client_ip: Ipv4Addr,
    user: Option<String>,
}

#[async_trait]
impl Handler for SessionHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        println!("auth none");
        self.user = Some(String::from(user));
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        println!("auth succeeded");
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        println!("tcp/ip forward");
        Ok(true)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        println!("channel open session");
        let user = self.user.as_ref().map_or("", |s| s.as_str());
        let claimed_hash = u32::from_str_radix(user, 16).map_err(|e| anyhow::Error::from(e));
        let hash = gencmd::hash_client(self.client_ip).map_err(|e| anyhow::Error::from(e));
        match (&claimed_hash, &hash) {
            (Ok(claimed_hash), Ok(hash)) if claimed_hash == hash => return Ok(true),
            _ => (),
        }
        Ok(false)
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        println!("client sends channel eof");
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        println!("client closes channel");
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Handle Ctrl-C from clients
        if data == &[0x3] {
            return Err(anyhow::Error::from(russh::Error::Disconnect));
        }
        Ok(())
    }
}

pub async fn run(port: u16, server: Arc<Server>) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    let config = Arc::new(Config {
        methods: MethodSet::NONE,
        keys: vec![
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap(),
        ],
        ..Default::default()
    });

    loop {
        println!("accept ssh ...");
        let (mut stream, client_addr) = listener.accept().await?;
        println!("conn from {:?}", client_addr);
        let client_addr = match client_addr {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(addr) => {
                stream.shutdown().await?;
                return Err(anyhow!("unexpected IPv6 address {addr}"));
            }
        };
        let handler = SessionHandler {
            client_ip: *client_addr.ip(),
            server: server.clone(),
            user: None,
        };
        run_stream(config.clone(), stream, handler).await?;
    }
}

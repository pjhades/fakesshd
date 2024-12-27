use anyhow::anyhow;
use async_trait::async_trait;
use log::{error, info};
use russh::server::{run_stream, Auth, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet};
use russh_keys::{Algorithm, PrivateKey};
use ssh_key::rand_core::OsRng;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::sync::Arc;

#[derive(Debug)]
pub struct Tunnel {
    /// russh session handle.
    session: Handle,
    /// russh channel corresponding to this tunnel.
    channel: Channel<Msg>,
}

impl Tunnel {
    pub async fn forward(
        &self,
        req: &[u8],
        server: Arc<Server>,
    ) -> Result<Receiver<Vec<u8>>, anyhow::Error> {
        self.session
            .data(self.channel.id(), CryptoVec::from(req))
            .await
            .map_err(|_| anyhow!("failed to forward data"))?;

        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        let mut pipes = server.pipes.lock().await;
        match pipes.get(&self.channel.id()) {
            None => {
                pipes.insert(self.channel.id(), tx);
            }
            Some(_) => {
                return Err(anyhow!("channel {} exists", self.channel.id()));
            }
        }
        Ok(rx)
    }
}

pub struct Server {
    /// Map a tunnel hash to the tunnel information.
    tunnels: Mutex<BTreeMap<u32, Option<Handle>>>,

    /// Map a russh channel to its MPSC sender side, so that when we receive response data from the
    /// SSH client we know where to send to the HTTP/HTTPS client.
    pipes: Mutex<BTreeMap<ChannelId, Sender<Vec<u8>>>>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            tunnels: Mutex::new(BTreeMap::new()),
            pipes: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn register_tunnel(&self, hash: u32) -> Result<(), anyhow::Error> {
        let mut tunnels = self.tunnels.lock().await;
        if tunnels.get(&hash).is_some() {
            return Err(anyhow!("Tunnel exists"));
        }
        tunnels.insert(hash, None);
        info!("register tunnel hash {hash:x}");
        Ok(())
    }

    pub async fn unregister_tunnel(&self, hash: u32) {
        let mut tunnels = self.tunnels.lock().await;
        tunnels.remove(&hash);
        info!("unregister tunnel hash {hash:x}");
        // XXX close the channel and session, whatever
    }

    pub async fn open_tunnel(
        &self,
        hash: u32,
        client_addr: SocketAddrV4,
    ) -> Result<Tunnel, anyhow::Error> {
        let mut tunnels = self.tunnels.lock().await;
        match tunnels.get_mut(&hash) {
            None => Err(anyhow!("Invalid tunnel")),
            Some(None) => {
                error!(
                    "trying to open tunnel but session handle is missing, removing hash {hash:x}"
                );
                tunnels.remove(&hash);
                Err(anyhow!("missing session"))
            }
            Some(Some(sess)) => {
                let channel = sess
                    .channel_open_forwarded_tcpip(
                        "localhost",
                        1,
                        format!("{}", client_addr.ip()),
                        client_addr.port() as u32,
                    )
                    .await
                    .map_err(|e| anyhow::Error::from(e))?;
                println!("channel id {} opened", channel.id());
                Ok(Tunnel {
                    session: sess.clone(),
                    channel,
                })
            }
        }
    }
}

struct SessionHandler {
    server: Arc<Server>,
    hash: Option<u32>,
}

#[async_trait]
impl Handler for SessionHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        let hash = u32::from_str_radix(user, 16).map_err(|e| anyhow::Error::from(e))?;
        let tunnels = self.server.tunnels.lock().await;
        if tunnels.get(&hash).is_none() {
            // Returning an `Err` makes sure the connection will be closed as a result of
            // authentication failure. In theory we should return `Auth::Reject` but the client
            // will continue with other authentication options like password which isn't
            // acceptable.
            Err(anyhow!("Invalid user"))
        } else {
            self.hash = Some(hash);
            Ok(Auth::Accept)
        }
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let hash = match self.hash {
            None => return Ok(false),
            Some(h) => h,
        };

        info!("tcp/ip forward is requested for hash {hash:x}");

        let mut tunnels = self.server.tunnels.lock().await;
        match tunnels.get_mut(&hash) {
            None => return Ok(false),
            Some(Some(_)) => {
                error!(
                    "trying to forward tcp/ip but session already exists, removing hash {hash:x}"
                );
                tunnels.remove(&hash);
            }
            Some(sess) => {
                println!("XXX");
                *sess = Some(session.handle());
            }
        }
        Ok(true)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut pipes = self.server.pipes.lock().await;
        pipes.remove(&channel);
        println!("EOF, remove channel {channel}");
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
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data == &[0x3] {
            self.server.unregister_tunnel(self.hash.unwrap()).await;
            return Err(anyhow::Error::from(russh::Error::Disconnect));
        }

        let pipes = self.server.pipes.lock().await;
        match pipes.get(&channel) {
            None => {
                return Err(anyhow!("no pipe found for channel {}", channel));
            }
            Some(tx) => tx.send(Vec::from(data)).await?,
        }

        Ok(())
    }
}

pub async fn run(port: u16, server: Arc<Server>) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    let config = Arc::new(Config {
        methods: MethodSet::NONE,
        keys: vec![PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });

    loop {
        info!("ssh listening on {port}");
        let (stream, client_addr) = listener.accept().await?;
        println!("conn from {:?}", client_addr);
        let handler = SessionHandler {
            server: server.clone(),
            hash: None,
        };
        let _session = run_stream(config.clone(), stream, handler).await?.handle();
    }
}

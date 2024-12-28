use anyhow::anyhow;
use async_trait::async_trait;
use log::{debug, error, info};
use russh::server::{run_stream, Auth, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, Disconnect, MethodSet};
use russh_keys::{Algorithm, PrivateKey};
use ssh_key::rand_core::OsRng;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::sync::Arc;

use crate::{assume_socket_addr_v4, DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT, FORWARDED_PORT};

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

struct SessionInfo {
    /// russh session handle.
    session: Option<Handle>,

    /// Forwarding channels opened in this session.
    channels: Vec<ChannelId>,
}

pub struct Server {
    /// Map a tunnel hash to the forwarding session.
    sessions: Mutex<BTreeMap<u32, SessionInfo>>,

    /// Map a russh channel to its MPSC sender side, so that when we receive response data from the
    /// SSH client we know where to send to the HTTP/HTTPS client.
    pipes: Mutex<BTreeMap<ChannelId, Sender<Vec<u8>>>>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
            pipes: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn register_tunnel(&self, hash: u32) -> Result<(), anyhow::Error> {
        let mut sessions = self.sessions.lock().await;
        if sessions.get(&hash).is_some() {
            return Err(anyhow!("Tunnel exists"));
        }
        sessions.insert(
            hash,
            SessionInfo {
                session: None,
                channels: Vec::new(),
            },
        );
        info!("register tunnel hash {hash:x}");
        Ok(())
    }

    pub async fn unregister_tunnel(&self, hash: u32) -> Result<(), anyhow::Error> {
        let mut sessions = self.sessions.lock().await;
        if let Some(info) = sessions.remove(&hash) {
            {
                let mut pipes = self.pipes.lock().await;
                for channel in &info.channels {
                    pipes.remove(channel);
                }
            }

            if let Some(sess) = info.session {
                sess.disconnect(Disconnect::ByApplication, String::new(), String::new())
                    .await
                    .map_err(|e| anyhow::Error::from(e))?
            }
        }
        info!("unregister tunnel hash {hash:x}");
        Ok(())
    }

    pub async fn open_tunnel(
        &self,
        hash: u32,
        client_addr: SocketAddrV4,
    ) -> Result<Tunnel, anyhow::Error> {
        let mut sessions = self.sessions.lock().await;
        match sessions.get_mut(&hash) {
            None => Err(anyhow!("Invalid tunnel")),
            Some(info) => match info.session.as_ref() {
                None => {
                    debug!("session is missing for hash {hash:x}");
                    Err(anyhow!("missing session"))
                }
                Some(sess) => {
                    let channel = sess
                        .channel_open_forwarded_tcpip(
                            "localhost",
                            FORWARDED_PORT as u32,
                            format!("{}", client_addr.ip()),
                            client_addr.port() as u32,
                        )
                        .await
                        .map_err(|e| anyhow::Error::from(e))?;

                    debug!("open forwarding channel {} for hash {hash:x}", channel.id());

                    info.channels.push(channel.id());

                    Ok(Tunnel {
                        session: sess.clone(),
                        channel,
                    })
                }
            },
        }
    }
}

struct SessionHandler {
    server: Arc<Server>,
    server_addr: SocketAddrV4,
    http_port: u16,
    https_port: u16,
    hash: Option<u32>,
    /// Channel ID of the session, i.e., the `ssh -R` command.
    channel: Option<ChannelId>,
}

impl SessionHandler {
    async fn check_channel_close(&self, channel: ChannelId) -> Result<(), anyhow::Error> {
        match (self.hash, self.channel) {
            (Some(h), Some(c)) => {
                if c == channel {
                    self.server.unregister_tunnel(h).await?;
                } else {
                    let mut pipes = self.server.pipes.lock().await;
                    pipes.remove(&channel);
                }
            }
            _ => (),
        }
        Ok(())
    }
}

#[async_trait]
impl Handler for SessionHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        let hash = u32::from_str_radix(user, 16).map_err(|e| anyhow::Error::from(e))?;
        let sessions = self.server.sessions.lock().await;
        if sessions.get(&hash).is_none() {
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

        info!("TCP/IP forwarding is requested for hash {hash:x}");

        let mut sessions = self.server.sessions.lock().await;
        match sessions.get_mut(&hash) {
            None => {
                debug!("session is missing for hash {hash:x}");
                Err(anyhow!("missing session"))
            }
            Some(info) => match info.session.as_ref() {
                Some(_) => {
                    debug!("session exists for hash {hash:x}");
                    Err(anyhow!("session exists"))
                }
                None => {
                    debug!("record session handle for hash {hash:x}");
                    info.session = Some(session.handle());
                    Ok(true)
                }
            },
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.channel.is_some() {
            error!("trying to open session but channel already exists, disconnect");
            return Err(anyhow!("failed to open session"));
        }

        self.channel = Some(channel.id());

        match self.hash {
            None => {
                error!("trying to open session but hash is missing, disconnect");
                return Err(anyhow!("failed to open session"));
            }
            Some(h) => {
                let mut http_url = format!("http://{:?}", self.server_addr.ip());
                let mut https_url = format!("https://{:?}", self.server_addr.ip());
                let path = format!("/{h:x}/");
                if self.http_port != DEFAULT_HTTP_PORT {
                    http_url.push_str(format!(":{}", self.http_port).as_str())
                }
                if self.https_port != DEFAULT_HTTPS_PORT {
                    https_url.push_str(format!(":{}", self.https_port).as_str())
                }
                let msg = format!("{http_url}{path}\r\n{https_url}{path}\r\n");
                session
                    .handle()
                    .data(channel.id(), CryptoVec::from(msg.as_bytes()))
                    .await
                    .map_err(|_| anyhow!("failed to send URL to client"))?;
            }
        }

        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("receive EOF from channel {channel}");
        self.check_channel_close(channel).await
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("client closes channel {channel}");
        self.check_channel_close(channel).await
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.channel {
            Some(c) if c == channel => {
                // Handle Ctrl-C from SSH client
                if data == &[0x3] {
                    self.server.unregister_tunnel(self.hash.unwrap()).await?;
                    return Err(anyhow::Error::from(russh::Error::Disconnect));
                } else {
                    return Ok(());
                }
            }
            None => {
                error!("received data from channel {channel} but session channel is missing, disconnect");
                self.server.unregister_tunnel(self.hash.unwrap()).await?;
                return Err(anyhow!("broken session"));
            }
            _ => (),
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

pub async fn run(
    port: u16,
    http_port: u16,
    https_port: u16,
    server: Arc<Server>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    let config = Arc::new(Config {
        methods: MethodSet::NONE,
        keys: vec![PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });

    loop {
        info!("listening on {port}");
        let (stream, client_addr) = listener.accept().await?;

        debug!("accept new connection from client {client_addr:?}");

        let server_addr = assume_socket_addr_v4(stream.local_addr()?);
        let handler = SessionHandler {
            server: server.clone(),
            server_addr,
            http_port,
            https_port,
            hash: None,
            channel: None,
        };
        let _session = run_stream(config.clone(), stream, handler).await?.handle();
    }
}

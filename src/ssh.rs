use async_trait::async_trait;
//use log::{info, warn};
use anyhow::anyhow;
use russh::server::{run_stream, Auth, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet};
use russh_keys::{Algorithm, PrivateKey};
use ssh_key::rand_core::OsRng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};

use crate::{assume_socket_addr_v4, gencmd};

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

/// Bookkeeping information of a tunnel belonging to a specific SSH client and destination.
struct TunnelInfo {
    // XXX we probably don't need this. this is currently only for logging
    // if it's removed, we can simplify the tunnels as btreemap: u32 -> session handle
    dest_addr: SocketAddrV4,
    session: Option<Handle>,
}

#[derive(Debug)]
pub struct Tunnel {
    hash: u32,
    dest_addr: SocketAddrV4,
    client_addr: SocketAddrV4,
    session: Handle,
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
            .map_err(|_| {
                anyhow!(
                    "failed to forward for {:?} to {:?} via tunnel {}",
                    self.client_addr,
                    self.dest_addr,
                    self.hash
                )
            })?;

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
    tunnels: Mutex<BTreeMap<u32, TunnelInfo>>,
    pipes: Mutex<BTreeMap<ChannelId, Sender<Vec<u8>>>>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            tunnels: Mutex::new(BTreeMap::new()),
            pipes: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn register_tunnel(
        &self,
        hash: u32,
        dest_addr: SocketAddrV4,
    ) -> Result<(), anyhow::Error> {
        // XXX if we don't hold the lock across await then we can replace this with
        // std::sync::Mutex, if our critical sections do not contain any await.
        let mut tunnels = self.tunnels.lock().await;
        if tunnels.get(&hash).is_some() {
            return Err(anyhow!("Tunnel exists"));
        }
        let info = TunnelInfo {
            dest_addr,
            session: None,
        };
        tunnels.insert(hash, info);
        Ok(())
    }

    pub async fn unregister_tunnel(&self, hash: u32) {
        let mut tunnels = self.tunnels.lock().await;
        tunnels.remove(&hash);
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
            Some(info) => {
                // XXX handle this error instead of assert
                assert!(info.session.is_some());
                let channel = info
                    .session
                    .as_ref()
                    .unwrap()
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
                    hash,
                    dest_addr: info.dest_addr,
                    client_addr,
                    session: info.session.as_ref().unwrap().clone(),
                    channel,
                })
            }
        }
    }
}

struct SessionHandler {
    server: Arc<Server>,
    client_ip: Ipv4Addr,
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
        println!("tcp/ip forward, hash={:x?}", self.hash);
        let hash = match self.hash {
            None => return Ok(false),
            Some(h) => h,
        };
        let mut tunnels = self.server.tunnels.lock().await;
        match tunnels.get_mut(&hash) {
            None => return Ok(false),
            Some(info) => {
                // XXX handle this error instead of assert
                // XXX this crashes, to reproduce:
                //   - register
                //   - ssh -R
                //   - ctrl-c
                //   - ssh -R same
                assert!(info.session.is_none());
                info.session = Some(session.handle());
            }
        }
        Ok(true)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        println!("channel open session, channel {}", channel.id());
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // XXX if we get Ctrl-C from the client ovre the channel of ssh -R,
        // we should remove the tunnel from the map, but at that time, the
        // channel might still be in use, so we should kill the session and
        // then I GUESS calling I/O functions on the corresponding channels on the same session will
        // error out
        if data == &[0x3] {
            self.server.unregister_tunnel(self.hash.unwrap());
            return Err(anyhow::Error::from(russh::Error::Disconnect));
        }

        let mut pipes = self.server.pipes.lock().await;
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
        println!("accept ssh ...");
        let (mut stream, client_addr) = listener.accept().await?;
        println!("conn from {:?}", client_addr);
        let client_addr = assume_socket_addr_v4(client_addr);
        let handler = SessionHandler {
            client_ip: *client_addr.ip(),
            server: server.clone(),
            hash: None,
        };
        let session = run_stream(config.clone(), stream, handler).await?.handle();
    }
}

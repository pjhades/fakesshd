use async_trait::async_trait;
use log::{info, warn};
use russh::server::{run_stream, Auth, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet, Sig, SshId};
use ssh_key::rand_core::OsRng;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

struct Server {
    tunnels: Mutex<BTreeMap<ChannelId, Channel<Msg>>>,
}

impl Server {
    fn new() -> Self {
        Self {
            tunnels: Mutex::new(BTreeMap::new()),
        }
    }
}

struct SessionHandler {
    server: Arc<Server>,
}

#[async_trait]
impl Handler for SessionHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        println!("auth none: {}", user);
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        println!("auth succeeds");
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        println!("tcp/ip forward");
        Ok(true)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        println!("open session");
        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        println!("client sends channel eof");
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
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
        println!("data: {:?}", data);
        if data == &[0x3] {
            let m = "bye bye!".into();
            session.data(channel, m)?;
            session.close(channel)?;
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        println!("signal {:?}", signal);
        Ok(())
    }
}

pub async fn run(port: u16) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    let config = Arc::new(Config {
        methods: MethodSet::NONE,
        keys: vec![
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap(),
        ],
        ..Default::default()
    });

    let server = Arc::new(Server::new());

    loop {
        println!("accept ...");
        let (mut stream, addr) = listener.accept().await?;
        println!("conn from {:?}", addr);
        let handler = SessionHandler {
            server: server.clone(),
        };
        let session = run_stream(config.clone(), stream, handler).await?;
    }
}

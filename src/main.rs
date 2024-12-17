use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use async_trait::async_trait;

use clap::Parser;

use russh::server::{run_stream, Auth, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodSet, SshId};

use std::sync::Arc;
use std::time::Duration;

use ssh_key::rand_core::OsRng;

const DEFAULT_SERVICE_PORT: u16 = 8080;
const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_HTTP_PORT: u16 = 80;
const DEFAULT_HTTPS_PORT: u16 = 443;

#[derive(Parser, Debug)]
#[command(version)]
struct CliArgs {
    #[arg(long, value_name = "PORT")]
    ssh_port: Option<u16>,
    #[arg(long, value_name = "PORT")]
    http_port: Option<u16>,
    #[arg(long, value_name = "PORT")]
    https_port: Option<u16>,
    #[arg(long, value_name = "PORT")]
    service_port: Option<u16>,
}

struct Server;

#[async_trait]
impl Handler for Server {
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
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = CliArgs::parse();
    let service_port = cli_args.service_port.unwrap_or(DEFAULT_SERVICE_PORT);
    let ssh_port = cli_args.ssh_port.unwrap_or(DEFAULT_SSH_PORT);
    let listener = TcpListener::bind(("0.0.0.0", ssh_port)).await?;
    let config = Arc::new(Config {
        methods: MethodSet::NONE,
        keys: vec![
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap(),
        ],
        ..Default::default()
    });

    loop {
        println!("accept ...");
        let (mut stream, addr) = listener.accept().await?;
        println!("conn from {:?}", addr);
        let session = run_stream(config.clone(), stream, Server).await?;
        session.await?;
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use clap::Parser;

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = CliArgs::parse();
    let ssh_port = cli_args.ssh_port.unwrap_or(DEFAULT_SSH_PORT);
    let listener = TcpListener::bind(("0.0.0.0", ssh_port)).await?;

    loop {
        let (mut stream, addr) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = [0; 1024];

            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(n) if n == 0 => return,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("failed to read from {:?}: {:?}", addr, e);
                        return;
                    }
                };

                if let Err(e) = stream.write_all(&buf[..n]).await {
                    eprintln!("failed to write to {:?}: {:?}", addr, e);
                    return;
                }
            }
        });
    }
}

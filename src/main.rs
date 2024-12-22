use clap::Parser;
use fakesshd::{gencmd, http, ssh};
use log::{error, info};
use tokio::task::JoinSet;

use std::sync::Arc;

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
    gencmd_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let cli_args = CliArgs::parse();
    let gencmd_port = cli_args
        .gencmd_port
        .unwrap_or(fakesshd::DEFAULT_GENCMD_PORT);
    let ssh_port = cli_args.ssh_port.unwrap_or(fakesshd::DEFAULT_SSH_PORT);
    let http_port = cli_args.http_port.unwrap_or(fakesshd::DEFAULT_HTTP_PORT);
    let https_port = cli_args.https_port.unwrap_or(fakesshd::DEFAULT_HTTPS_PORT);

    let server = Arc::new(ssh::Server::new());
    let mut services = JoinSet::new();
    services.spawn(gencmd::run(gencmd_port, ssh_port, server.clone()));
    services.spawn(ssh::run(ssh_port, server.clone()));
    services.spawn(http::run_http(http_port, server.clone()));

    // TODO tracing?
    while let Some(result) = services.join_next_with_id().await {
        match result {
            Ok((id, _)) => info!("task {} finished", id),
            Err(e) => error!("task {} error: {}", e.id(), e),
        }
    }

    Ok(())
}

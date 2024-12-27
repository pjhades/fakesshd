use clap::Parser;
use fakesshd::{gencmd, http, ssh};
use log::{error, info};
use tokio::task::JoinSet;

use std::future::Future;
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

    #[arg(long, value_name = "FILE")]
    cert_file: Option<String>,

    #[arg(long, value_name = "FILE")]
    private_key_file: Option<String>,
}

async fn named_task<F, T>(name: &str, task: F) -> (&str, <F as Future>::Output)
where
    F: Future<Output = T> + Send + 'static,
    T: Send,
{
    (name, task.await)
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
    let cert_file = cli_args
        .cert_file
        .unwrap_or(String::from(fakesshd::DEFAULT_CERT_FILE));
    let private_key_file = cli_args
        .private_key_file
        .unwrap_or(String::from(fakesshd::DEFAULT_PRIVATE_KEY_FILE));

    let server = Arc::new(ssh::Server::new());
    let mut services = JoinSet::new();
    services.spawn(named_task(
        "gencmd",
        gencmd::run(gencmd_port, ssh_port, server.clone()),
    ));
    services.spawn(named_task("ssh", ssh::run(ssh_port, server.clone())));
    services.spawn(named_task(
        "http",
        http::run_http(http_port, server.clone()),
    ));
    services.spawn(named_task(
        "https",
        http::run_https(https_port, cert_file, private_key_file, server.clone()),
    ));

    while let Some(result) = services.join_next().await {
        match result {
            Ok((name, Ok(_))) => info!("task {name} exited"),
            Ok((name, Err(e))) => error!("task {name} exited with error: {e}"),
            Err(e) => error!("join error {e}"),
        }
    }

    Ok(())
}

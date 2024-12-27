use std::net::{SocketAddr, SocketAddrV4};

pub mod gencmd;
pub mod http;
pub mod ssh;

pub const DEFAULT_GENCMD_PORT: u16 = 8080;
pub const DEFAULT_SSH_PORT: u16 = 22;
pub const DEFAULT_HTTP_PORT: u16 = 80;
pub const DEFAULT_HTTPS_PORT: u16 = 443;
pub const DEFAULT_CERT_FILE: &'static str = "cert.pem";
pub const DEFAULT_PRIVATE_KEY_FILE: &'static str = "key.pem";

pub const FORWARDED_PORT: u16 = 1;

pub fn assume_socket_addr_v4(addr: SocketAddr) -> SocketAddrV4 {
    match addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => panic!("Unexpected IPv6 address {addr:?}"),
    }
}

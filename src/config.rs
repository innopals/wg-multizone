use std::{
    fs::{File, read_to_string},
    io::Write,
    path::Path,
};

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub name: Option<String>,
    pub internal_cidr: String,
    pub ip: String,
    pub port: u32,
    pub pubkey: String,
    pub vpc_id: Option<String>,
    pub vpc_ip: Option<String>,
    pub persistent_keepalive_interval: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub mtu: u32,
    pub peers: Vec<ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub config_url: String,
    pub secret: Option<String>,
    pub fetch_interval: u64,
    pub interface_name: String,
}

pub const PRIVATE_KEY_PATH: &str = "secret.key";
pub const CONFIG_PATH: &str = "config.json";

pub fn load_key() -> (PublicKey, StaticSecret) {
    if !Path::new(PRIVATE_KEY_PATH).exists() {
        let secret_key = StaticSecret::random();
        let secret_key_bytes = secret_key.to_bytes();
        let secret_key_hex = hex::encode(secret_key_bytes);
        let mut file = File::create(PRIVATE_KEY_PATH).unwrap();
        file.write_all(secret_key_hex.as_bytes()).unwrap();
    }
    let secret_key = read_to_string(PRIVATE_KEY_PATH).unwrap();
    let secret_key = hex::decode(secret_key).unwrap();
    let secret_key: [u8; 32] = secret_key.try_into().unwrap();
    let secret_key = StaticSecret::from(secret_key);
    let pubkey = PublicKey::from(&secret_key);
    (pubkey, secret_key)
}

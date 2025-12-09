mod config;
mod crypto;
mod dns;
mod loader;

use base64::Engine;
use config::DaemonConfig;
use defguard_wireguard_rs::{InterfaceConfiguration, WGApi};
use std::{fs::read_to_string, time::Duration};
use tokio::time::sleep;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
use tikv_jemallocator::Jemalloc;

use crate::config::CONFIG_PATH;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() {
    let config = read_to_string(CONFIG_PATH).unwrap();
    let config: DaemonConfig = serde_json::from_str(&config).unwrap();
    let (pubkey, secret_key) = config::load_key();
    let pubkey = base64::engine::general_purpose::STANDARD.encode(pubkey.as_bytes());
    println!("Local public key: {}", &pubkey);

    #[cfg(not(target_os = "macos"))]
    let wgapi = WGApi::<defguard_wireguard_rs::Kernel>::new(config.interface_name.clone()).unwrap();
    #[cfg(target_os = "macos")]
    let wgapi =
        WGApi::<defguard_wireguard_rs::Userspace>::new(config.interface_name.clone()).unwrap();

    let mut interface_config = InterfaceConfiguration {
        name: config.interface_name.clone(),
        prvkey: base64::engine::general_purpose::STANDARD.encode(secret_key.as_bytes()),
        addresses: vec![],
        port: 0,
        peers: vec![],
        mtu: None,
    };

    loop {
        let r =
            loader::fetch_and_apply_config(&wgapi, &mut interface_config, &pubkey, &config).await;
        if r.is_err() {
            println!("Failed to apply config: {:?}", r.unwrap_err());
        }
        sleep(Duration::from_secs(config.fetch_interval)).await;
    }
}

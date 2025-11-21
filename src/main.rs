use std::{
    error::Error,
    fs::{File, read_to_string},
    io::Write,
    net::IpAddr,
    path::Path,
    str::FromStr,
    time::Duration,
};

use base64::Engine;
use defguard_wireguard_rs::{
    InterfaceConfiguration, WGApi, WireguardInterfaceApi, host::Peer, key::Key, net::IpAddrMask,
};
use hickory_resolver::Resolver;
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use url::Url;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerConfig {
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
struct NetworkConfig {
    pub mtu: u32,
    pub peers: Vec<ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonConfig {
    pub config_url: String,
    pub secret: Option<String>,
    pub fetch_interval: u64,
    pub interface_name: String,
}

const PRIVATE_KEY_PATH: &str = "secret.key";
const CONFIG_PATH: &str = "config.json";

fn load_key() -> (PublicKey, StaticSecret) {
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

async fn fetch_config_content(config_url: &str) -> Result<String, Box<dyn Error>> {
    // Try to parse as URL first
    if let Ok(url) = Url::parse(config_url) {
        match url.scheme() {
            "file" => {
                // Handle file:// URLs
                let path = url.to_file_path().map_err(|_| {
                    format!("Invalid file URL: {}", config_url)
                })?;
                Ok(read_to_string(path)?)
            }
            "http" | "https" => {
                // Handle HTTP(S) URLs with 30-second timeout
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()?;
                Ok(client.get(config_url).send().await?.text().await?)
            }
            scheme => {
                Err(format!("Unsupported URL scheme: {}", scheme).into())
            }
        }
    } else {
        // If URL parsing fails, treat it as a plain file path
        Ok(read_to_string(config_url)?)
    }
}

fn decrypt_config(encrypted: &str, secret: &str) -> Result<String, Box<dyn Error>> {
    // Step 1: Base64 decode
    let data = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .unwrap();

    // Step 2: Verify prefix
    assert!(&data[0..8] == b"Salted__");
    let salt = &data[8..16];
    let ciphertext = &data[16..];

    // Step 3: Derive key and iv using PBKDF2-HMAC-SHA256
    let mut key = [0u8; 32]; // AES-256 => 32-byte key
    let mut iv = [0u8; 16]; // CBC IV
    let mut derived = [0u8; 48]; // key + iv = 48 bytes total

    openssl::pkcs5::pbkdf2_hmac(
        secret.as_bytes(),
        salt,
        10_000,
        openssl::hash::MessageDigest::sha256(),
        &mut derived,
    )
    .unwrap();
    key.copy_from_slice(&derived[..32]);
    iv.copy_from_slice(&derived[32..48]);

    // Step 4: Decrypt
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv)).unwrap();
    crypter.pad(true);

    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(ciphertext, &mut plaintext).unwrap();
    count += crypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);

    Ok(String::from_utf8(plaintext)?)
}

async fn resolve_to_ip(host: &str) -> Option<String> {
    // Try to parse as IP address first
    if let Ok(_) = host.parse::<IpAddr>() {
        return Some(host.to_string());
    }

    // If not an IP, try to resolve as domain name
    let resolver = match Resolver::builder_tokio() {
        Ok(builder) => builder.build(),
        Err(e) => {
            println!("Failed to create DNS resolver: {}", e);
            return None;
        }
    };

    match resolver.lookup_ip(host).await {
        Ok(response) => {
            // Get the first IP address from the response
            response.iter().next().map(|ip| ip.to_string())
        }
        Err(e) => {
            println!("Failed to resolve domain {}: {}", host, e);
            None
        }
    }
}

async fn fetch_and_apply_config(
    wgapi: &WGApi,
    interface_config: &mut InterfaceConfiguration,
    pubkey: &str,
    config: &DaemonConfig,
) -> Result<(), Box<dyn Error>> {
    let mut r = fetch_config_content(&config.config_url).await?;
    if config.secret.is_some() {
        r = decrypt_config(
            &r.replace("\n", "").replace(" ", ""),
            &config.secret.as_ref().unwrap(),
        )?;
    }
    let r: NetworkConfig = serde_json::from_str(&r)?;
    let mut my_config: Option<ServerConfig> = None;
    for peer in r.peers.iter() {
        if peer.pubkey == pubkey {
            my_config = Some(peer.clone());
        }
    }
    if my_config.is_none() {
        println!("Current server is not configured in the network");
        return Ok(());
    }
    let my_config = my_config.unwrap();
    let current_address = if interface_config.addresses.len() > 0 {
        interface_config.addresses[0].to_string()
    } else {
        "".to_string()
    };
    if current_address != my_config.internal_cidr
        || my_config.port != interface_config.port
        || Some(r.mtu) != interface_config.mtu
    {
        if interface_config.port == 0 {
            wgapi.create_interface()?;
        }
        interface_config.addresses = vec![IpAddrMask::from_str(&my_config.internal_cidr)?];
        interface_config.port = my_config.port;
        interface_config.mtu = Some(r.mtu);
        wgapi.configure_interface(&interface_config)?;
    }
    let current_peers = wgapi.read_interface_data()?;
    let mut next_peers = std::collections::HashSet::new();
    for peer in r.peers.iter() {
        if peer.pubkey == pubkey {
            continue;
        }
        let pubkey = Key::from_str(&peer.pubkey)?;
        next_peers.insert(pubkey.clone());
        let current_peer = current_peers.peers.get(&pubkey);
        let mut should_reconfigure = false;
        let mut peer_cidr = IpAddrMask::from_str(&peer.internal_cidr)?;
        peer_cidr.cidr = 32;
        let peer_endpoint_host = if my_config.vpc_id.is_some()
            && my_config.vpc_id == peer.vpc_id
            && peer.vpc_ip.is_some()
        {
            peer.vpc_ip.as_ref().unwrap().clone()
        } else {
            peer.ip.clone()
        };

        // Resolve domain name to IP address
        let peer_endpoint_ip = resolve_to_ip(&peer_endpoint_host).await;

        // Calculate keepalive interval as minimum of both endpoints
        let keepalive_interval = match (my_config.persistent_keepalive_interval, peer.persistent_keepalive_interval) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        if let Some(p) = current_peer {
            if let Some(endpoint) = p.endpoint {
                if let Some(resolved_ip) = &peer_endpoint_ip {
                    if endpoint.ip().to_string() != *resolved_ip
                        || endpoint.port() as u32 != peer.port
                    {
                        should_reconfigure = true;
                    }
                } else {
                    // Resolution failed, need to reconfigure to clear endpoint
                    should_reconfigure = true;
                }
            } else {
                should_reconfigure = true;
            }
            if p.allowed_ips.len() != 1 {
                should_reconfigure = true;
            } else if p.allowed_ips[0] != peer_cidr {
                should_reconfigure = true;
            }
            if p.persistent_keepalive_interval != keepalive_interval {
                should_reconfigure = true;
            }
        } else {
            should_reconfigure = true;
        }
        if should_reconfigure {
            let endpoint = match &peer_endpoint_ip {
                Some(ip) => {
                    // Check if IP is IPv6 and needs brackets for SocketAddr parsing
                    let endpoint_str = match ip.parse::<IpAddr>() {
                        Ok(IpAddr::V6(_)) => format!("[{}]:{}", ip, peer.port),
                        _ => format!("{}:{}", ip, peer.port),
                    };
                    match endpoint_str.parse() {
                        Ok(addr) => Some(addr),
                        Err(e) => {
                            println!("Failed to parse endpoint {}: {}", endpoint_str, e);
                            None
                        }
                    }
                }
                None => None,
            };
            let wg_peer = Peer {
                public_key: pubkey,
                preshared_key: None,
                protocol_version: None,
                endpoint,
                last_handshake: None,
                tx_bytes: 0,
                rx_bytes: 0,
                persistent_keepalive_interval: keepalive_interval,
                allowed_ips: vec![peer_cidr],
            };
            let endpoint_display = peer_endpoint_ip
                .as_ref()
                .map(|ip| format!("{}:{}", ip, peer.port))
                .unwrap_or_else(|| "(no endpoint - resolution failed)".to_string());
            println!(
                "Configuring peer: {} {} {}",
                &peer.pubkey, endpoint_display, &peer.internal_cidr
            );
            wgapi.configure_peer(&wg_peer)?;
        }
    }
    for peer in current_peers.peers.iter() {
        if next_peers.contains(&peer.0) {
            continue;
        }
        wgapi.remove_peer(&peer.0)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let config = read_to_string(CONFIG_PATH).unwrap();
    let config: DaemonConfig = serde_json::from_str(&config).unwrap();
    let (pubkey, secret_key) = load_key();
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
        let r = fetch_and_apply_config(&wgapi, &mut interface_config, &pubkey, &config).await;
        if r.is_err() {
            println!("Failed to apply config: {:?}", r.unwrap_err());
        }
        sleep(Duration::from_secs(config.fetch_interval)).await;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_decrypt_config() {
        // cat servers.json | openssl enc -aes-256-cbc -a -salt -pbkdf2 -pass pass:mysecret
        let mut r = r#"
            U2FsdGVkX19nIrNUt9Wpcyw2qK2rEqJkHX6Wv7ot3sZGR5wIBtkHPvmBXkre46a4
            T+8hHiRtwvrZZithpFHi9Y1Tq+T7DrwT4A1auJ15ZZbRSEA5quEl/ywF/65FaDeA
            5uhj5lr+BcO8bvLbT7dQzmpAP7rCzY0l067fQh6pNuaiDhK31XnZ0WIK/E+o5k+1
            +JwiloAjeMGdP5jNFTws+XjFTPYPJAfhIVdpGqfmb5+hFZh9rZsRTsb+TaGC0tWS
            UtXcZz6A4RmXWLx+YgEGUg=="#
            .replace("\n", "")
            .replace(" ", "");
        r = decrypt_config(&r, "mysecret").unwrap();
        let r: NetworkConfig = serde_json::from_str(&r).unwrap();
        println!("{:?}", r);
    }
}

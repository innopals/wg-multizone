use std::{
    error::Error,
    fs::{File, read_to_string},
    io::Write,
    path::Path,
    str::FromStr,
    time::Duration,
};

use base64::Engine;
use defguard_wireguard_rs::{
    InterfaceConfiguration, WGApi, WireguardInterfaceApi, host::Peer, key::Key, net::IpAddrMask,
};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
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

async fn fetch_and_apply_config(
    wgapi: &WGApi,
    interface_config: &mut InterfaceConfiguration,
    pubkey: &str,
    config: &DaemonConfig,
) -> Result<(), Box<dyn Error>> {
    let mut r = reqwest::get(&config.config_url).await?.text().await?;
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
        let peer_endpoint_ip = if my_config.vpc_id.is_some()
            && my_config.vpc_id == peer.vpc_id
            && peer.vpc_ip.is_some()
        {
            peer.vpc_ip.as_ref().unwrap().clone()
        } else {
            peer.ip.clone()
        };
        if let Some(p) = current_peer {
            if let Some(endpoint) = p.endpoint {
                if endpoint.ip().to_string() != peer_endpoint_ip
                    || endpoint.port() as u32 != peer.port
                {
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
        } else {
            should_reconfigure = true;
        }
        if should_reconfigure {
            let wg_peer = Peer {
                public_key: pubkey,
                preshared_key: None,
                protocol_version: None,
                endpoint: Some(format!("{}:{}", peer_endpoint_ip, peer.port).parse()?),
                last_handshake: None,
                tx_bytes: 0,
                rx_bytes: 0,
                persistent_keepalive_interval: None,
                allowed_ips: vec![peer_cidr],
            };
            println!(
                "Configuring peer: {} {} {}",
                &peer.pubkey, &peer_endpoint_ip, &peer.internal_cidr
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

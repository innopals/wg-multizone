use crate::{
    config::{DaemonConfig, NetworkConfig, ServerConfig},
    crypto::decrypt_config,
    dns::resolve_to_ip,
};
use defguard_wireguard_rs::{
    InterfaceConfiguration, WGApi, WireguardInterfaceApi, host::Peer, key::Key, net::IpAddrMask,
};
use std::{error::Error, fs::read_to_string, net::IpAddr, str::FromStr, time::Duration};
use url::Url;

pub async fn fetch_config_content(config_url: &str) -> Result<String, Box<dyn Error>> {
    // Try to parse as URL first
    if let Ok(url) = Url::parse(config_url) {
        match url.scheme() {
            "file" => {
                // Handle file:// URLs
                let path = url
                    .to_file_path()
                    .map_err(|_| format!("Invalid file URL: {}", config_url))?;
                Ok(read_to_string(path)?)
            }
            "http" | "https" => {
                // Handle HTTP(S) URLs with 30-second timeout
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()?;
                Ok(client.get(config_url).send().await?.text().await?)
            }
            scheme => Err(format!("Unsupported URL scheme: {}", scheme).into()),
        }
    } else {
        // If URL parsing fails, treat it as a plain file path
        Ok(read_to_string(config_url)?)
    }
}

pub(crate) async fn fetch_and_apply_config(
    wgapi: &WGApi,
    interface_config: &mut InterfaceConfiguration,
    pubkey: &str,
    config: &DaemonConfig,
) -> Result<(), Box<dyn Error>> {
    let mut r = fetch_config_content(&config.config_url).await?;
    if config.secret.is_some() {
        r = decrypt_config(&r, &config.secret.as_ref().unwrap())?;
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
        let keepalive_interval = match (
            my_config.persistent_keepalive_interval,
            peer.persistent_keepalive_interval,
        ) {
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

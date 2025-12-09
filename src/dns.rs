use std::{net::IpAddr, time::Duration};

use hickory_resolver::Resolver;

pub async fn resolve_to_ip(host: &str) -> Option<String> {
    // Try to parse as IP address first
    if let Ok(_) = host.parse::<IpAddr>() {
        return Some(host.to_string());
    }

    // If not an IP, try to resolve as domain name
    let resolver = match Resolver::builder_tokio() {
        Ok(mut builder) => {
            builder.options_mut().timeout = Duration::from_secs(5);
            builder.build()
        }
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

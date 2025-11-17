use std::time::Duration;
use tonic::transport::{ClientTlsConfig, Endpoint, Error};

/// Configures the endpoint for the gRPC client.
///
/// Sets reasonable settings to handle timeouts and keep-alive.
pub fn configure_endpoint(addr: &str) -> Result<Endpoint, Error> {
    let mut endpoint = Endpoint::new(addr.to_string())?
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(15))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(15))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .tcp_nodelay(true);

    // Configure TLS if using HTTPS.
    if addr.starts_with("https://") {
        // Extract domain name from URL for SNI (Server Name Indication)
        // SNI is required for proper TLS certificate validation, even without Cloudflare
        // Format: https://domain:port/path -> extract "domain:port" -> extract "domain"
        let domain = addr
            .strip_prefix("https://")
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.split(':').next())
            .unwrap_or("rpc.mainnet.monero-chan.org");
        
        // Configure TLS with system root certificates and domain name for SNI
        // Domain name is required foar SNI which enables proper certificate validation
        let tls_config = ClientTlsConfig::new()
            .with_enabled_roots()
            .domain_name(domain);
        
        endpoint = endpoint.tls_config(tls_config)?;
    }

    Ok(endpoint)
}

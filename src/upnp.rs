use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use log::{debug, info, warn};
use tokio::net::UdpSocket;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use igd_next::PortMappingProtocol;
use crate::universal_listener::PrefixedStream;

const UPNP_MULTICAST_ADDR: &str = "239.255.255.250:1900";
const SSDP_ALIVE: &str = "ssdp:alive";
const SSDP_BYEBYE: &str = "ssdp:byebye";
const SSDP_DISCOVER: &str = "ssdp:discover";
const UPNP_LEASE_DURATION: u32 = 3600; // 1 hour

#[derive(Debug, Clone)]
pub struct PortMapping {
    pub external_port: u16,
    pub internal_port: u16,
    pub internal_client: Ipv4Addr,
    pub protocol: PortMappingProtocol,
    pub description: String,
    pub lease_duration: u32,
}

pub struct UpnpServer {
    local_ip: Ipv4Addr,
    mappings: Vec<PortMapping>,
}

impl UpnpServer {
    pub fn new(local_ip: Ipv4Addr) -> Self {
        Self {
            local_ip,
            mappings: Vec::new(),
        }
    }

    pub async fn add_port_mapping(&mut self, mapping: PortMapping) -> io::Result<()> {
        info!("Attempting to add UPnP port mapping: {:?}", mapping);
        let gateway = match tokio::task::spawn_blocking(move || igd_next::search_gateway(Default::default())).await {
            Ok(Ok(gw)) => gw,
            Ok(Err(e)) => {
                warn!("UPnP: Could not find gateway: {}. Manual port forwarding may be required.", e);
                return Err(io::Error::new(io::ErrorKind::Other, format!("No UPnP gateway: {}", e)));
            }
            Err(e) => {
                warn!("UPnP: Task failed: {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, format!("UPnP task error: {}", e)));
            }
        };

        let internal_addr = SocketAddr::new(IpAddr::V4(mapping.internal_client), mapping.internal_port);
        match gateway.add_port(mapping.protocol, mapping.external_port, internal_addr, mapping.lease_duration, &mapping.description) {
            Ok(_) => {
                info!("Successfully added UPnP port mapping: {:?}", mapping);
                self.mappings.push(mapping);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to add UPnP port mapping: {:?}, error: {}", mapping, e);
                Err(io::Error::new(io::ErrorKind::Other, format!("Failed to add UPnP mapping: {}", e)))
            }
        }
    }

    pub async fn remove_port_mapping(&mut self, external_port: u16, protocol: PortMappingProtocol) -> io::Result<()> {
        info!("Attempting to remove UPnP port mapping: {}/{:?}", external_port, protocol);
        let gateway = match tokio::task::spawn_blocking(move || igd_next::search_gateway(Default::default())).await {
            Ok(Ok(gw)) => gw,
            Ok(Err(e)) => {
                warn!("UPnP: Could not find gateway for removal: {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, format!("No UPnP gateway: {}", e)));
            }
            Err(e) => {
                warn!("UPnP: Task failed: {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, format!("UPnP task error: {}", e)));
            }
        };

        match gateway.remove_port(protocol, external_port) {
            Ok(_) => {
                info!("Successfully removed UPnP port mapping: {}/{:?}", external_port, protocol);
                self.mappings.retain(|m| !(m.external_port == external_port && m.protocol == protocol));
                Ok(())
            }
            Err(e) => {
                warn!("Failed to remove UPnP port mapping: {}/{:?}, error: {}", external_port, protocol, e);
                Err(io::Error::new(io::ErrorKind::Other, format!("Failed to remove UPnP mapping: {}", e)))
            }
        }
    }

    pub async fn start_ssdp_advertising(&self) -> io::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let multicast_addr: SocketAddr = UPNP_MULTICAST_ADDR.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid UPnP multicast address: {}", e)))?;

        info!("Starting SSDP advertising on {}", multicast_addr);

        let notify_message = format!(
            "NOTIFY * HTTP/1.1\r\n\
             HOST: {}\
             CACHE-CONTROL: max-age={}\
             NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\
             NTS: ssdp:alive\
             USN: uuid:{}:urn:schemas-upnp-org:device:InternetGatewayDevice:1\
             LOCATION: http://{}:49152/rootDesc.xml\
             SERVER: OS/version UPnP/1.0 LiteBike/1.0\
             \r\n",
            UPNP_MULTICAST_ADDR,
            UPNP_LEASE_DURATION,
            "12345678-1234-5678-9abc-123456789012",
            self.local_ip,
        );

        socket.send_to(notify_message.as_bytes(), multicast_addr).await?;
        info!("Sent SSDP alive notification");

        Ok(())
    }

    pub async fn handle_ssdp_request<S>(&self, mut stream: S, request: &str) -> io::Result<()> 
    where
        S: AsyncWrite + Unpin,
    {
        debug!("SSDP request received: {}", request);
        // For now, just send a generic OK. Full SSDP response is complex.
        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write_all(response.as_bytes()).await
    }
}

pub async fn is_upnp_request(request: &str) -> bool {
    request.contains("UPnP") ||
    request.contains("SSDP") ||
    request.contains("M-SEARCH") ||
    request.contains("NOTIFY") ||
    request.contains("urn:schemas-upnp-org")
}

/// Handler wrapper function for UPnP requests - called by universal listener
pub async fn handle_upnp_request(mut stream: PrefixedStream<tokio::net::TcpStream>) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    if n == 0 { return Ok(()); }

    let request = String::from_utf8_lossy(&buffer[..n]);
    debug!("UPnP request received: {}", request);

    // Extract local IP from stream or use default
    let local_ip = stream.inner.local_addr() 
        .map(|addr| match addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => std::net::Ipv4Addr::new(127, 0, 0, 1),
        })
        .unwrap_or_else(|_| std::net::Ipv4Addr::new(127, 0, 0, 1));

    let upnp_server = UpnpServer::new(local_ip);
    upnp_server.handle_ssdp_request(stream, &request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use crate::universal_listener::PrefixedStream;

    #[tokio::test]
    async fn test_is_upnp_request() {
        assert!(is_upnp_request("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").await);
        assert!(is_upnp_request("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nNTS: ssdp:alive\r\nUSN: uuid:some-uuid::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://192.168.1.1:49152/rootDesc.xml\r\nSERVER: OS/version UPnP/1.0 product/version\r\n\r\n").await);
        assert!(!is_upnp_request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await);
    }

    #[tokio::test]
    async fn test_upnp_server_handle_ssdp_request() {
        let local_ip = Ipv4Addr::new(127, 0, 0, 1);
        let upnp_server = UpnpServer::new(local_ip);
        
        let (client, server) = TcpStream::pair().unwrap();
        
        let server_handle = tokio::spawn(async move {
            let mut prefixed_stream = PrefixedStream::new(server, vec![]);
            upnp_server.handle_ssdp_request(prefixed_stream, "M-SEARCH * HTTP/1.1\r\n\r\n").await
        });
        
        let mut client_handle = tokio::spawn(async move {
            let mut response_buf = vec![0u8; 1024];
            client.write_all(b"M-SEARCH * HTTP/1.1\r\n\r\n").await.unwrap();
            client.read(&mut response_buf).await.unwrap();
            String::from_utf8_lossy(&response_buf).to_string()
        });
        
        let _ = server_handle.await.unwrap();
        let response = client_handle.await.unwrap();
        
        assert!(response.contains("HTTP/1.1 200 OK"));
    }
}

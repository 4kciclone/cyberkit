use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;


pub async fn scan_port(target: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = SocketAddr::new(target, port);
    
    
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true, 
        _ => false,        
    }
}
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;


pub async fn scan_port(target: IpAddr, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = SocketAddr::new(target, port);
    let timeout_duration = Duration::from_millis(timeout_ms);

    
    if let Ok(Ok(mut stream)) = timeout(timeout_duration, TcpStream::connect(&addr)).await {
        
        
        
        
        
        let _ = stream.write_all(b"\r\n").await;

        let mut buffer = [0; 1024];
        
        
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                
                let output = String::from_utf8_lossy(&buffer[..n]);
                
                let clean_output = output.replace(['\r', '\n'], " ").trim().to_string();
                return Some(clean_output);
            }
            _ => {
                
                return Some("Open (No Banner)".to_string());
            }
        }
    }
    
    
    None
}
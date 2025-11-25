use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;


pub async fn scan_port(target: IpAddr, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = SocketAddr::new(target, port);
    
    if let Ok(Ok(mut stream)) = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        let _ = stream.write_all(b"\r\n").await;
        let mut buffer = [0; 1024];
        
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let output = String::from_utf8_lossy(&buffer[..n]);
                let clean_output = output.replace(['\r', '\n'], " ").trim().to_string();
                return Some(clean_output);
            }
            _ => return Some("Open (No Banner)".to_string()),
        }
    }
    None
}


pub async fn scan_udp_port(target: IpAddr, port: u16, timeout_ms: u64) -> Option<String> {
    let target_addr = SocketAddr::new(target, port);
    
    
    
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return None,
    };

    
    if socket.connect(target_addr).await.is_err() {
        return None;
    }

    
    
    
    if socket.send(b"\r\nHelloUDP").await.is_err() {
        return None;
    }

    
    let mut buffer = [0; 1024];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let output = String::from_utf8_lossy(&buffer[..n]);
            let clean = output.replace(['\r', '\n'], " ").trim().to_string();
            return Some(clean);
        }
        _ => {
            
            
            None 
        }
    }
}
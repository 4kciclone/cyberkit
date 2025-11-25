pub mod port_scanner;
pub mod service_detection;

use colored::*;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use port_scanner::scan_port;
use service_detection::identify_service;

pub async fn run(target: String, ports_arg: Option<String>) {
    
    let ip = match IpAddr::from_str(&target) {
        Ok(i) => i,
        Err(_) => {
            println!("{} IP inválido: {}", "ERROR:".red(), target);
            return;
        }
    };

    
    let ports_to_scan = parse_ports(ports_arg);

    println!(
        "{} Iniciando scan em {} para {} portas...",
        "[*]".blue(),
        ip.to_string().bold(),
        ports_to_scan.len()
    );

    
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    
    for port in ports_to_scan {
        let results_clone = Arc::clone(&results);
        
        
        let handle = tokio::spawn(async move {
            
            if scan_port(ip, port, 1000).await {
                let service = identify_service(port);
                
                
                println!(
                    "{} Porta {} aberta ({})",
                    "[+]".green(),
                    port.to_string().bold(),
                    service.cyan()
                );

                let mut lock = results_clone.lock().await;
                lock.push((port, service));
            }
        });
        handles.push(handle);
    }

    
    for handle in handles {
        let _ = handle.await;
    }

    println!("{} Scan finalizado.", "[*]".blue());
}


fn parse_ports(ports_arg: Option<String>) -> Vec<u16> {
    if let Some(p_str) = ports_arg {
        p_str.split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    } else {
        
        vec![
            21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 
            1433, 3000, 3306, 3389, 5432, 6379, 8000, 8080, 8443
        ]
    }
}
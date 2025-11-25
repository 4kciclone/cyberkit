pub mod port_scanner;
pub mod service_detection;

use colored::*;
use ipnetwork::IpNetwork;
use serde::Serialize;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use port_scanner::{scan_port, scan_udp_port}; 
use service_detection::identify_service;


#[derive(Serialize)]
struct ScanReport {
    network_scan: String,
    protocol: String, 
    hosts: Vec<HostResult>,
}

#[derive(Serialize, Clone)]
struct HostResult {
    ip: String,
    ports: Vec<PortInfo>,
}

#[derive(Serialize, Clone)]
struct PortInfo {
    port: u16,
    service: String,
    banner: String,
}



pub async fn run(target: String, ports_arg: Option<String>, json_output: bool, is_udp: bool) {
    
    let targets: Vec<IpAddr> = if let Ok(ip) = IpAddr::from_str(&target) {
        vec![ip]
    } else if let Ok(net) = target.parse::<IpNetwork>() {
        net.iter().collect()
    } else {
        if !json_output { println!("{} Alvo inválido: {}", "ERROR:".red(), target); }
        return;
    };

    
    let ports_to_scan = parse_ports(ports_arg, is_udp);
    let proto_str = if is_udp { "UDP" } else { "TCP" };

    if !json_output {
        println!(
            "{} Alvo: {} | Protocolo: {} | Hosts: {}",
            "[*]".blue(),
            target.bold(),
            proto_str.yellow(),
            targets.len()
        );
        println!("{}", "------------------------------------------------------------".bright_black());
    }

    let final_report = Arc::new(Mutex::new(Vec::new()));

    
    for ip in targets {
        if !json_output { println!("{} Verificando Host: {}", "->".blue(), ip); }

        let mut handles = vec![];
        let host_ports = Arc::new(Mutex::new(Vec::new()));

        for &port in &ports_to_scan {
            let host_ports_clone = Arc::clone(&host_ports);
            let ip_clone = ip;
            let use_udp = is_udp; 

            let handle = tokio::spawn(async move {
                
                let scan_result = if use_udp {
                    scan_udp_port(ip_clone, port, 2000).await
                } else {
                    scan_port(ip_clone, port, 1500).await
                };

                if let Some(banner) = scan_result {
                    let service_name = identify_service(port);

                    if !json_output {
                        println!(
                            "    {} Porta {} \t| {} \t| {}",
                            "[+]".green(),
                            port.to_string().bold(),
                            service_name.cyan(),
                            banner.yellow().italic()
                        );
                    }

                    let mut lock = host_ports_clone.lock().await;
                    lock.push(PortInfo { port, service: service_name.to_string(), banner });
                }
            });
            handles.push(handle);
        }

        for handle in handles { let _ = handle.await; }

        let ports_found = host_ports.lock().await;
        if !ports_found.is_empty() {
            let mut report_lock = final_report.lock().await;
            report_lock.push(HostResult {
                ip: ip.to_string(),
                ports: ports_found.to_vec(),
            });
        }
    }

    
    if json_output {
        let report = ScanReport {
            network_scan: target,
            protocol: proto_str.to_string(),
            hosts: final_report.lock().await.to_vec(),
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("{}", "------------------------------------------------------------".bright_black());
        println!("{} Varredura completa.", "[*]".blue());
    }
}


fn parse_ports(ports_arg: Option<String>, is_udp: bool) -> Vec<u16> {
    if let Some(p_str) = ports_arg {
        p_str.split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    } else {
        if is_udp {
            
            vec![53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 623, 1900, 5353]
        } else {
            
            vec![21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
        }
    }
}
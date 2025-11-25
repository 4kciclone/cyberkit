pub mod rule_engine;
pub mod ui;

use colored::*;
use pcap::{Capture, Device, Activated};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::Packet;
use std::fs::OpenOptions; 
use std::io::Write;       
use std::path::Path;
use std::thread;
use std::sync::{mpsc, Arc};
use chrono::Local;        
use rule_engine::IdsEngine;


pub fn run(file: Option<String>, device: Option<String>, rules_file: Option<String>, log_file: Option<String>) {
    let rules_path = rules_file.unwrap_or("rules.json".to_string());
    
    let engine = rule_engine::load_rules(&rules_path);
    let engine_arc = Arc::new(engine);

    if let Some(fname) = file {
        
        println!("{} Modo: Análise de Arquivo ({})", "[*]".blue(), fname);
        if !Path::new(&fname).exists() {
            println!("{} Arquivo não encontrado!", "[-]".red());
            return;
        }

        match Capture::from_file(fname) {
            Ok(cap) => {
                
                process_capture_loop(cap, &engine_arc, None, log_file);
            },
            Err(e) => println!("{} Erro ao abrir pcap: {}", "[-]".red(), e),
        }

    } else if let Some(dev_name) = device {
        
        let (tx, rx) = mpsc::channel();
        
        let cap_result = Capture::from_device(dev_name.as_str())
            .and_then(|dev| dev.promisc(true).snaplen(5000).timeout(500).open());

        match cap_result {
            Ok(cap) => {
                let engine_ref = Arc::clone(&engine_arc);
                
                
                let log_path_clone = log_file.clone();

                thread::spawn(move || {
                    process_capture_loop(cap, &engine_ref, Some(tx), log_path_clone);
                });

                if let Err(e) = ui::run_tui(rx) {
                    println!("Erro na UI: {}", e);
                }
            },
            Err(e) => {
                println!("{} Erro ao abrir dispositivo: {}", "[-]".red(), e);
                if let Ok(devs) = Device::list() {
                    println!("Dispositivos disponíveis: {:?}", devs.iter().map(|d| &d.name).collect::<Vec<_>>());
                }
            }
        }

    } else {
        println!("{} Erro: Defina --file ou --device", "[-]".red());
    }
}

fn process_capture_loop<T: Activated>(
    mut cap: Capture<T>, 
    engine: &IdsEngine, 
    tx: Option<mpsc::Sender<ui::IdsMessage>>,
    log_path: Option<String> 
) {
    let mut alerts_count = 0;

    
    let mut log_writer = if let Some(path) = log_path {
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => {
                if tx.is_none() { println!("{} Logs serão salvos em: {}", "[+]".green(), path); }
                Some(f)
            },
            Err(e) => {
                println!("{} Falha ao criar arquivo de log: {}", "[-]".red(), e);
                None
            }
        }
    } else {
        None
    };

    if tx.is_none() {
        println!("{}", "----------------------------------------".bright_black());
        println!("{} Analisando pacotes...", "[*]".blue());
    }

    while let Ok(packet) = cap.next_packet() {
        if let Some(ref sender) = tx {
            let _ = sender.send(ui::IdsMessage::PacketProcessed);
        }

        if let Some(eth) = EthernetPacket::new(packet.data) {
            if eth.get_ethertype() == EtherTypes::Ipv4 {
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    
                    if let Some(alert) = engine.inspect(&ipv4) {
                        alerts_count += 1;
                        
                        let clean_payload = alert.payload_preview.replace(['\r', '\n'], " "); 
                        
                        
                        let now = Local::now().format("%Y-%m-%d %H:%M:%S");

                        
                        if let Some(ref mut file) = log_writer {
                            let log_line = format!(
                                "[{}] ALERT: {} | SRC: {} | PAYLOAD: {}\n",
                                now, alert.rule_name, alert.source_ip, clean_payload
                            );
                            
                            let _ = file.write_all(log_line.as_bytes());
                        }

                        
                        if let Some(ref sender) = tx {
                            let log_msg = format!("{} -> {} ({})", alert.source_ip, alert.rule_name, clean_payload);
                            let _ = sender.send(ui::IdsMessage::Alert(log_msg));
                        } else {
                            println!(
                                "{} ALERTA: {} | Src: {} | Payload: {}",
                                "🚨".red().bold(),
                                alert.rule_name,
                                alert.source_ip.yellow(),
                                clean_payload.dimmed()
                            );
                        }
                    }
                }
            }
        }
    }
    
    if tx.is_none() {
        println!("{}", "----------------------------------------".bright_black());
        println!("{} Análise finalizada. Alertas: {}", "[!]".yellow(), alerts_count);
    }
}
pub mod rule_engine;

use colored::*;
use pcap::{Capture, Device, Activated}; 
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::Packet;
use std::path::Path;
use rule_engine::IdsRule;

pub fn run(file: Option<String>, device: Option<String>, rules_file: Option<String>) {
    println!("{} Iniciando Engine IDS...", "🛡️".blue());

    
    let rules_path = rules_file.unwrap_or("rules.json".to_string());
    let rules = rule_engine::load_rules(&rules_path);
    println!("{} {} regras carregadas.", "[*]".blue(), rules.len());

    
    if let Some(fname) = file {
        println!("{} Modo: Análise de Arquivo ({})", "[*]".blue(), fname);
        if !Path::new(&fname).exists() {
            println!("{} Arquivo não encontrado!", "[-]".red());
            return;
        }
        
        
        match Capture::from_file(fname) {
            Ok(cap) => process_capture(cap, &rules),
            Err(e) => println!("{} Erro ao abrir pcap: {}", "[-]".red(), e),
        }

    } else if let Some(dev_name) = device {
        println!("{} Modo: Live Sniffing (Interface: {})", "[*]".blue(), dev_name.bold());
        println!("{} Dica: Live sniffing requer permissões de root/sudo.", "💡".yellow());

        
        match Capture::from_device(dev_name.as_str()) {
            Ok(dev) => {
                match dev
                    .promisc(true)
                    .snaplen(5000)
                    .timeout(1000)
                    .open() 
                {
                    Ok(cap) => process_capture(cap, &rules),
                    Err(e) => {
                        println!("{} Falha ao ativar interface: {}", "[-]".red(), e);
                        println!("Possível causa: Falta de permissão (sudo) ou interface inexistente.");
                    }
                }
            },
            Err(e) => {
                println!("{} Dispositivo inválido: {}", "[-]".red(), e);
                if let Ok(devs) = Device::list() {
                    println!("Dispositivos disponíveis: {:?}", devs.iter().map(|d| &d.name).collect::<Vec<_>>());
                }
            }
        }
    } else {
        println!("{} Erro: Você deve especificar --file ou --device", "[-]".red());
    }
}



fn process_capture<T: Activated>(mut cap: Capture<T>, rules: &[IdsRule]) {
    println!("{}", "----------------------------------------".bright_black());
    println!("{} Monitorando pacotes... (Pressione Ctrl+C para parar)", "[*]".green().blink());

    let mut alerts_count = 0;

    
    while let Ok(packet) = cap.next_packet() {
        if let Some(eth) = EthernetPacket::new(packet.data) {
            if eth.get_ethertype() == EtherTypes::Ipv4 {
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    
                    
                    if let Some(alert) = rule_engine::inspect_packet(&ipv4, rules) {
                        alerts_count += 1;
                        println!(
                            "{} ALERTA: {} | Src: {} | Payload: \"{}...\"",
                            "🚨".red().bold(),
                            alert.rule_name,
                            alert.source_ip.yellow(),
                            alert.payload_preview.replace('\n', " ")
                        );
                    }
                }
            }
        }
    }

    println!("\n{} Monitoramento encerrado. Total de alertas: {}", "[*]".blue(), alerts_count);
}
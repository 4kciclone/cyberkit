pub mod rule_engine;

use colored::*;
use pcap::Capture;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::Packet;
use std::path::Path;

pub fn run(file: String, rules_file: Option<String>) {
    println!("{} Iniciando Engine IDS...", "🛡️".blue());

    let rules_path = rules_file.unwrap_or("rules.json".to_string());
    let rules = rule_engine::load_rules(&rules_path);
    println!("{} {} regras carregadas.", "[*]".blue(), rules.len());

    if !Path::new(&file).exists() {
        println!("{} Arquivo PCAP não encontrado: {}", "[-]".red(), file);
        return;
    }

    let mut cap = match Capture::from_file(&file) {
        Ok(c) => c,
        Err(e) => {
            println!("{} Erro ao abrir PCAP: {}", "[-]".red(), e);
            return;
        }
    };

    let mut alerts_count = 0;
    let mut packet_count = 0;

    println!("{}", "----------------------------------------".bright_black());

    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;

        if let Some(eth) = EthernetPacket::new(packet.data) {
            
            if eth.get_ethertype() == EtherTypes::Ipv4 {
                
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    
                    if let Some(alert) = rule_engine::inspect_packet(&ipv4, &rules) {
                        alerts_count += 1;
                        
                        println!(
                            "{} ALERTA: {} | Src: {} | Payload: \"{}...\"",
                            "🚨".red().blink(),
                            alert.rule_name.bold(),
                            alert.source_ip.yellow(),
                            alert.payload_preview.replace('\n', " ") // Remove quebras de linha p/ não estragar o log
                        );
                    }
                }
            }
        }
    }

    println!("{}", "----------------------------------------".bright_black());
    
    println!("{} Pacotes analisados: {}", "[*]".blue(), packet_count);
    
    if alerts_count == 0 {
        println!("{} Nenhum pacote malicioso detectado.", "[+]".green());
        println!("{} Dica: Se estava testando localmente, lembre-se de usar 127.0.0.1 ao invés de localhost para forçar IPv4.", "💡".yellow());
    } else {
        println!("{} Análise concluída. Total de alertas críticos: {}", "[!]".red(), alerts_count);
    }
}
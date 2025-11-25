use pcap::Capture;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::Packet;
use std::collections::HashMap;
use colored::*;

pub struct PacketStats {
    pub total: u32,
    pub tcp: u32,
    pub udp: u32,
    pub icmp: u32,
    pub syn_flags: u32, 
    pub src_ips: HashMap<String, u32>,
}

impl PacketStats {
    pub fn new() -> Self {
        Self {
            total: 0,
            tcp: 0,
            udp: 0,
            icmp: 0,
            syn_flags: 0,
            src_ips: HashMap::new(),
        }
    }
}

pub fn analyze_pcap(file_path: &str) -> Result<PacketStats, Box<dyn std::error::Error>> {
    let mut cap = Capture::from_file(file_path)?;
    let mut stats = PacketStats::new();

    
    while let Ok(packet) = cap.next_packet() {
        stats.total += 1;

        
        if let Some(eth) = EthernetPacket::new(packet.data) {
            
            if eth.get_ethertype() == EtherTypes::Ipv4 {
                
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    let src = ipv4.get_source().to_string();
                    *stats.src_ips.entry(src).or_insert(0) += 1;

                    match ipv4.get_next_level_protocol() {
                        pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                            stats.tcp += 1;
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                if tcp.get_flags() & pnet_packet::tcp::TcpFlags::SYN != 0 
                                   && tcp.get_flags() & pnet_packet::tcp::TcpFlags::ACK == 0 {
                                    stats.syn_flags += 1;
                                }
                            }
                        },
                        pnet_packet::ip::IpNextHeaderProtocols::Udp => stats.udp += 1,
                        pnet_packet::ip::IpNextHeaderProtocols::Icmp => stats.icmp += 1,
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(stats)
}

pub fn print_report(stats: &PacketStats) {
    println!("{}", "📊 Relatório de Análise PCAP".bold().underline());
    println!("Total de Pacotes: {}", stats.total);
    println!("TCP: {} | UDP: {} | ICMP: {}", stats.tcp.to_string().cyan(), stats.udp.to_string().yellow(), stats.icmp);
    
    println!("{}", "\n🚩 Análise de Ameaças:".bold());
    if stats.syn_flags > 100 {
        println!("{} Detectado alto volume de SYNs ({}). Possível Port Scan ou SYN Flood!", "⚠️ ALERTA:".red(), stats.syn_flags);
    } else {
        println!("SYNs (Tentativas de conexão): {}", stats.syn_flags);
    }

    println!("{}", "\n🌍 Top 5 IPs de Origem:".bold());
    let mut ips: Vec<_> = stats.src_ips.iter().collect();
    ips.sort_by(|a, b| b.1.cmp(a.1)); 

    for (ip, count) in ips.iter().take(5) {
        println!("  - {}: {} pacotes", ip, count);
    }
}
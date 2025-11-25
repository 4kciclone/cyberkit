use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::Packet;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    pub name: String,
    pub protocol: String, 
    pub src_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub pattern: Option<String>, 
}

pub struct Alert {
    pub rule_name: String,
    pub source_ip: String,
    pub payload_preview: String,
}


pub fn load_rules(path: &str) -> Vec<IdsRule> {
    if let Ok(content) = fs::read_to_string(path) {
        if let Ok(rules) = serde_json::from_str(&content) {
            return rules;
        }
    }
    
    vec![
        IdsRule {
            name: "Tentativa de Acesso a Admin".to_string(),
            protocol: "tcp".to_string(),
            src_ip: None,
            dst_port: Some(80),
            pattern: Some("admin".to_string()),
        },
        IdsRule {
            name: "Tentativa de SQL Injection".to_string(),
            protocol: "tcp".to_string(),
            src_ip: None,
            dst_port: None,
            pattern: Some("UNION SELECT".to_string()),
        },
        IdsRule {
            name: "Shellcode Pattern".to_string(),
            protocol: "tcp".to_string(),
            src_ip: None,
            dst_port: None,
            pattern: Some("/bin/sh".to_string()),
        },
    ]
}


pub fn inspect_packet(ipv4: &Ipv4Packet, rules: &[IdsRule]) -> Option<Alert> {
    let src = ipv4.get_source().to_string();
    
    
    let payload = String::from_utf8_lossy(ipv4.payload());

    
    let mut dest_port = 0;
    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
        dest_port = tcp.get_destination();
    }

    for rule in rules {
        
        if rule.protocol == "tcp" && ipv4.get_next_level_protocol() != pnet_packet::ip::IpNextHeaderProtocols::Tcp {
            continue;
        }

        
        if let Some(port) = rule.dst_port {
            if port != dest_port {
                continue;
            }
        }

        
        if let Some(ref pattern) = rule.pattern {
            if payload.contains(pattern) {
                return Some(Alert {
                    rule_name: rule.name.clone(),
                    source_ip: src,
                    payload_preview: payload.chars().take(50).collect(),
                });
            }
        }
    }

    None
}
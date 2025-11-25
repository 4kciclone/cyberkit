use aho_corasick::AhoCorasick;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::Packet;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    pub name: String,
    pub protocol: String, // "tcp", "udp"
    pub src_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub pattern: Option<String>,
}

pub struct Alert {
    pub rule_name: String,
    pub source_ip: String,
    pub payload_preview: String,
}

// Estrutura Inteligente com Aho-Corasick
pub struct IdsEngine {
    rules: Vec<IdsRule>,
    ac: AhoCorasick,
    // Mapeia o ID do padrão no Aho-Corasick para o índice da regra no vetor 'rules'
    pattern_map: Vec<usize>, 
}

impl IdsEngine {
    pub fn new(rules: Vec<IdsRule>) -> Self {
        let mut patterns = Vec::new();
        let mut map = Vec::new();

        // Extrai apenas os padrões de texto das regras
        for (i, rule) in rules.iter().enumerate() {
            if let Some(p) = &rule.pattern {
                patterns.push(p.clone());
                map.push(i); // Guarda que o padrão X pertence à regra I
            }
        }

        // Compila o Autômato (A parte mágica da performance)
        let ac = AhoCorasick::new(&patterns).unwrap();

        IdsEngine {
            rules,
            ac,
            pattern_map: map,
        }
    }

    pub fn inspect(&self, ipv4: &Ipv4Packet) -> Option<Alert> {
        let src = ipv4.get_source().to_string();
        
        // Extrai porta (se for TCP) para validação cruzada
        let mut dest_port = 0;
        let is_tcp = ipv4.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp;
        
        if is_tcp {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                dest_port = tcp.get_destination();
            }
        }

        // Converte payload para busca
        let payload_bytes = ipv4.payload();
        let payload_str = String::from_utf8_lossy(payload_bytes);

        // BUSCA OTIMIZADA: Encontra TODOS os padrões em uma única passada
        // CORREÇÃO: Usamos .as_ref() para pegar o &str de dentro do Cow
        for mat in self.ac.find_iter(payload_str.as_ref()) {
            
            // mat.pattern() retorna o ID interno do Aho-Corasick
            // Usamos nosso mapa para descobrir qual é a Regra original
            let rule_index = self.pattern_map[mat.pattern().as_usize()];
            let rule = &self.rules[rule_index];

            // O padrão bateu, mas precisamos checar as outras condições (Porta, Protocolo)
            
            // 1. Checa Protocolo
            if rule.protocol == "tcp" && !is_tcp {
                continue;
            }

            // 2. Checa Porta (se a regra definir uma)
            if let Some(port) = rule.dst_port {
                if port != dest_port {
                    continue;
                }
            }

            // 3. Checa IP de Origem (se a regra definir)
            if let Some(ref ip) = rule.src_ip {
                if ip != &src {
                    continue;
                }
            }

            // SE PASSOU TUDO: TEMOS UM ALERTA!
            return Some(Alert {
                rule_name: rule.name.clone(),
                source_ip: src,
                payload_preview: payload_str.chars().take(100).collect(),
            });
        }

        None
    }
}

/// Carrega regras e inicializa a Engine
pub fn load_rules(path: &str) -> IdsEngine {
    let rules_vec = if let Ok(content) = fs::read_to_string(path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        // Regras padrão
        vec![
            IdsRule {
                name: "Tentativa de Acesso a Admin".to_string(),
                protocol: "tcp".to_string(),
                src_ip: None,
                dst_port: None,
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
                name: "Detectado Shellcode/Bin/Sh".to_string(),
                protocol: "tcp".to_string(),
                src_ip: None,
                dst_port: None,
                pattern: Some("/bin/sh".to_string()),
            },
        ]
    };

    IdsEngine::new(rules_vec)
}
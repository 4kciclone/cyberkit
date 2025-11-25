# 🔥 Cyberkit — Cybersecurity Toolkit em Rust

![Rust](https://img.shields.io/badge/built_with-Rust-dca282.svg?style=flat&logo=rust)
![Security](https://img.shields.io/badge/category-Security-red.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

**Cyberkit** é um toolkit de segurança ofensiva e defensiva modular, desenvolvido em **Rust**. Ele combina ferramentas essenciais de reconhecimento de rede, análise web e inspeção de pacotes em um único binário CLI de alta performance, utilizando concorrência assíncrona (`tokio`) para velocidade máxima.

---

## 🛠️ Módulos e Funcionalidades

O projeto é dividido em 4 engines principais:

### 1. 🚀 Port Scanner (`scan`)
Varredura de rede TCP assíncrona.
- **Alta Performance:** Escaneia centenas de portas simultaneamente usando *green threads*.
- **Service Fingerprinting:** Identifica serviços comuns (HTTP, SSH, Redis, SQL) baseados na porta.
- **Customizável:** Permite varredura de alvos específicos ou portas customizadas.

### 2. 🕸️ Web Recon & Crawler (`web`)
Ferramenta de enumeração web e spidering.
- **Crawler Profundo:** Extrai todos os links (`href`) de uma página alvo.
- **Fuzzing de Parâmetros:** Identifica automaticamente URLs com parâmetros GET (`?id=1`), apontando vetores potenciais para **SQL Injection** ou **XSS**.
- **User-Agent:** Simula navegação legítima.

### 3. 🛡️ IDS Engine (Intrusion Detection System) (`ids`)
Sistema de Detecção de Intrusão baseado em assinaturas.
- **Análise Forense:** Lê arquivos `.pcap` e inspeciona cada pacote.
- **Rule Engine:** Compara payloads contra regras JSON configuráveis.
- **Detecção:** Identifica padrões como tentativas de acesso administrativo, Shellcode e SQL Injection no tráfego de rede.

### 4. 📦 Packet Analyzer (`pcap`)
Analisador estatístico de tráfego de rede.
- **Protocol Breakdown:** Estatísticas de TCP, UDP e ICMP.
- **Threat Intelligence:** Detecta anomalias como excesso de flags SYN (sinal de port scanning ou DDoS).
- **Top Talkers:** Identifica os IPs de origem mais ativos na captura.

---

## 🏗️ Arquitetura Técnica

O projeto segue a arquitetura limpa do Rust (Idiomatic Rust):

```
cyberkit/
├── src/
│   ├── main.rs          # Entry Point & CLI Dispatcher
│   ├── scanner/         # Módulo de Rede (Tokio Async)
│   ├── web/             # Crawler HTTP (Reqwest + Scraper)
│   ├── pcap/            # Analisador de Pacotes (Libpcap wrapper)
│   ├── ids/             # Engine de Regras de Segurança
│   └── utils/           # Helpers e IO
```

**Principais Crates (Bibliotecas):**
- `tokio`: Runtime assíncrono para concorrência.
- `clap`: Parser de argumentos de linha de comando (CLI).
- `pcap` & `pnet`: Bindings para libpcap e manipulação de pacotes raw.
- `reqwest`: Cliente HTTP assíncrono.
- `serde`: Serialização/Deserialização de regras JSON.

---

## ⚙️ Instalação e Uso

### Pré-requisitos (Debian/Ubuntu/Kali)
Como o projeto interage com drivers de rede, é necessário instalar as dependências de sistema:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev libssl-dev pkg-config
```

### Compilação

Clone o repositório e compile em modo release (otimizado):

```bash
git clone https://github.com/4kciclone/cyberkit.git
cd cyberkit
cargo build --release
```

O binário estará disponível em `./target/release/cyberkit`.

---

## 📖 Exemplos de Comandos

### 1. Escanear um servidor
```bash
# Scan padrão (Top portas)
./cyberkit scan --target 192.168.1.10

# Scan específico
./cyberkit scan --target 8.8.8.8 --ports 53,80,443
```

### 2. Mapear um site (Crawler)
```bash
./cyberkit web --url http://scanme.nmap.org
```

### 3. Analisar tráfego de rede (PCAP)
```bash
./cyberkit pcap --file captura.pcap
```

### 4. Rodar o IDS contra um ataque
```bash
# Analisa o arquivo procurando assinaturas maliciosas
./cyberkit ids --file ataque.pcap
```

---

## 📝 Regras do IDS

As regras são definidas no arquivo `rules.json` (ou hardcoded como fallback). Exemplo de estrutura:

```json
[
  {
    "name": "SQL Injection Attempt",
    "protocol": "tcp",
    "pattern": "UNION SELECT"
  }
]
```

---

## ⚠️ Aviso Legal

Este software foi desenvolvido **exclusivamente para fins educacionais** e para testes em ambientes autorizados. O desenvolvedor não se responsabiliza pelo uso indevido desta ferramenta.

**Nunca escaneie redes ou sites sem permissão explícita.**

---

Desenvolvido com 🦀 e café.
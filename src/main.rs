mod cli;
mod scanner;
mod web;
mod pcap;
mod ids;
mod utils;

use clap::Parser;
use cli::{Cli, Commands};
use colored::*;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    
    
    let is_json_output = match &cli.command {
        Commands::Scan { json, .. } => *json,
        _ => false,
    };

    if !is_json_output {
        println!("{}", "\n🔥 Cyberkit v1.2 Iniciado...".bold().bright_red());
    }

    match cli.command {
        Commands::Scan { target, ports, json, udp } => {
            scanner::run(target, ports, json, udp).await;
        }
        
        Commands::Web { url, depth } => {
            web::run(url, depth).await;
        }
        Commands::Pcap { file } => {
            pcap::run(file);
        }
        Commands::Ids { file, device, rules, log } => {
            ids::run(file, device, rules, log);
        }
    }
}
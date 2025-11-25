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

    println!("{}", "\n🔥 Cyberkit v1.0 Iniciado...".bold().bright_red());

    match cli.command {
        Commands::Scan { target, ports } => {
            scanner::run(target, ports).await;
        }
        Commands::Web { url } => {
            web::run(url).await;
        }
        Commands::Pcap { file } => {
            
            
            pcap::run(file);
        }
        Commands::Ids { file, rules } => {
            ids::run(file, rules);
        }
    }
}
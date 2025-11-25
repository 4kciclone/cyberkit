use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cyberkit")]
#[command(about = "Cybersecurity Toolkit em Rust", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    
    Scan {
        
        #[arg(short, long)]
        target: String,

        
        #[arg(short, long)]
        ports: Option<String>,
    },

    
    Web {
        
        #[arg(short, long)]
        url: String,
    },

    
    Pcap {
        
        #[arg(short, long)]
        file: String,
    },

    
    Ids {
        
        #[arg(short, long)]
        file: String,
        
        
        #[arg(short, long)]
        rules: Option<String>,
    },
}
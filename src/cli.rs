use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cyberkit")]
#[command(about = "Cybersecurity Toolkit Profissional em Rust", long_about = None)]
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

        
        #[arg(long)]
        json: bool,

        
        #[arg(long)]
        udp: bool,
    },

    
    Web {
        
        #[arg(short, long)]
        url: String,

        
        #[arg(short, long, default_value_t = 2)]
        depth: usize,
    },

    
    Pcap {
        
        #[arg(short, long)]
        file: String,
    },

    
    Ids {
        
        #[arg(short, long)]
        file: Option<String>,

        
        #[arg(short, long)]
        device: Option<String>,
        
        
        #[arg(short, long)]
        rules: Option<String>,

        
        #[arg(long)]
        log: Option<String>,
    },
}
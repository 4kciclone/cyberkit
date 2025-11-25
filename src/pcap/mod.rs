pub mod analyzer;

use colored::*;
use std::path::Path;

pub fn run(file: String) {
    println!("{} Analisando arquivo: {}", "[*]".blue(), file);

    if !Path::new(&file).exists() {
        println!("{} Arquivo não encontrado!", "[-]".red());
        return;
    }

    match analyzer::analyze_pcap(&file) {
        Ok(stats) => {
            analyzer::print_report(&stats);
        }
        Err(e) => {
            println!("{} Erro ao ler PCAP: {}", "[-]".red(), e);
        }
    }
}
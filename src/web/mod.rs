pub mod crawler;
pub mod fuzz_params;

use colored::*;
use reqwest::Client;
use std::time::Duration;

pub async fn run(url: String) {
    println!("{} Iniciando Web Recon em: {}", "[*]".blue(), url);

    
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Cyberkit/1.0")
        .build()
        .unwrap();

    
    match crawler::crawl(&url, &client).await {
        Ok(links) => {
            println!("{} Links encontrados: {}", "[+]".green(), links.len());
            println!("{}", "----------------------------------------".bright_black());

            for link in links {
                
                if fuzz_params::check_for_params(&link) {
                    println!("{} [PARAM] {}", "⚠️".yellow(), link);
                } else {
                    println!("{} {}", "🔗".cyan(), link);
                }
            }
            println!("{}", "----------------------------------------".bright_black());
        }
        Err(e) => {
            println!("{} Falha ao acessar {}: {}", "[-]".red(), url, e);
        }
    }
}
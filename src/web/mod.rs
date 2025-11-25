pub mod crawler;
pub mod fuzz_params;

use colored::*;
use reqwest::Client;
use std::collections::{HashSet, VecDeque};
use std::time::Duration;

pub async fn run(start_url: String, max_depth: usize) {
    println!("{} Iniciando Spider em: {} (Profundidade: {})", "[*]".blue(), start_url, max_depth);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("Cyberkit/1.1 Spider")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .unwrap();

    
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new(); 

    
    queue.push_back((start_url.clone(), 0));
    visited.insert(start_url);

    let mut vulnerable_params = 0;
    let mut pages_crawled = 0;

    println!("{}", "------------------------------------------------------------".bright_black());

    
    while let Some((url, depth)) = queue.pop_front() {
        
        if depth > max_depth {
            continue;
        }

        pages_crawled += 1;
        println!("{} [D{}] Crawling: {}", "->".cyan(), depth, url);

        
        match crawler::fetch(&url, &client).await {
            Ok(body) => {
                
                let found_links = crawler::extract_links(&url, &body).await;
                
                
                if depth < max_depth {
                    for link in found_links {
                        if !visited.contains(&link) {
                            visited.insert(link.clone());
                            queue.push_back((link, depth + 1));
                        }
                    }
                }

                
                if fuzz_params::check_for_params(&url) {
                    println!("    {} Parâmetros detectados!", "⚠️".yellow());
                    vulnerable_params += 1;
                }
            }
            Err(_) => {
                
                
            }
        }
    }

    println!("{}", "------------------------------------------------------------".bright_black());
    println!(
        "{} Fim do Spider. Páginas: {} | URLs com Parâmetros: {}",
        "[*]".blue(),
        pages_crawled,
        vulnerable_params
    );
}
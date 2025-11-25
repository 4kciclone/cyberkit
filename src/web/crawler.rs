use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;


pub async fn crawl(url: &str, client: &Client) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    
    let resp = client.get(url).send().await?;
    
    
    if !resp.status().is_success() {
        return Err(format!("Erro HTTP: {}", resp.status()).into());
    }

    
    let body = resp.text().await?;
    
    
    let document = Html::parse_document(&body);
    let selector = Selector::parse("a").unwrap(); 
    
    let base_url = Url::parse(url)?;
    let mut links = HashSet::new();

    
    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            
            if let Ok(absolute_url) = base_url.join(href) {
                links.insert(absolute_url.to_string());
            }
        }
    }

    Ok(links)
}
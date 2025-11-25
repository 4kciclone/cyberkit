use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;


pub async fn extract_links(base_url: &str, html_body: &str) -> HashSet<String> {
    let mut links = HashSet::new();
    
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return links,
    };
    let base_domain = base.domain().unwrap_or("").to_string();

    let document = Html::parse_document(html_body);
    let selector = Selector::parse("a").unwrap();

    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            if let Ok(absolute_url) = base.join(href) {
                if let Some(domain) = absolute_url.domain() {
                    if domain == base_domain {
                        let mut clean_url = absolute_url.clone();
                        clean_url.set_fragment(None);
                        links.insert(clean_url.to_string());
                    }
                }
            }
        }
    }

    links
}


pub async fn fetch(url: &str, client: &Client) -> Result<String, reqwest::Error> {
    let resp = client.get(url).send().await?;
    
    
    
    
    if resp.status().is_client_error() || resp.status().is_server_error() {
        return Err(resp.error_for_status().unwrap_err());
    }

    
    
    resp.text().await
}
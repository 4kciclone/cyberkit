use url::Url;

pub fn check_for_params(url_str: &str) -> bool {
    if let Ok(parsed) = Url::parse(url_str) {
        return parsed.query().is_some();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_with_params() {
        let url = "http://site.com/index.php?id=1&admin=false";
        assert_eq!(check_for_params(url), true);
    }

    #[test]
    fn test_url_clean() {
        let url = "http://site.com/about";
        assert_eq!(check_for_params(url), false);
    }
}
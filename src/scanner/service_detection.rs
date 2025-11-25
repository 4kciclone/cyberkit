
pub fn identify_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_common_ports() {
        assert_eq!(identify_service(80), "HTTP");
        assert_eq!(identify_service(22), "SSH");
        assert_eq!(identify_service(6379), "Redis");
    }

    #[test]
    fn test_identify_unknown_port() {
        assert_eq!(identify_service(9999), "Unknown");
    }
}
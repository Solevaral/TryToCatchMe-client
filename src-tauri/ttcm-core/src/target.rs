//! Diagnostic targets, parsed without DNS or network access.

#[derive(Debug, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: Option<u16>,
    pub scheme: Option<String>,
    pub path: String,
}

impl Target {
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match self.port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }

    pub fn socket(&self) -> String {
        let port = self.port.unwrap_or(if self.scheme.as_deref() == Some("http") { 80 } else { 443 });
        format!("{}:{port}", if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() })
    }

    pub fn url(&self, fallback_scheme: &str) -> String {
        format!("{}://{}{}", self.scheme.as_deref().unwrap_or(fallback_scheme), self.authority(), self.path)
    }
}

pub fn parse(raw: &str) -> Result<Target, String> {
    let raw = raw.trim();
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, rest)) if s == "http" || s == "https" => (Some(s.to_string()), rest),
        Some(_) => return Err("Поддерживаются только http и https".into()),
        None => (None, raw),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let path = match &rest[end..] {
        "" => "/".into(),
        p if p.starts_with('/') => p.to_string(),
        p => format!("/{p}"),
    };
    let (host, port_text) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, tail) = v6.split_once(']').ok_or("Незакрытая скобка IPv6")?;
        host.parse::<std::net::Ipv6Addr>().map_err(|_| "Некорректный IPv6")?;
        let port = if tail.is_empty() { None } else { Some(tail.strip_prefix(':').ok_or("Некорректный порт")?) };
        (host, port)
    } else if authority.matches(':').count() > 1 {
        authority.parse::<std::net::Ipv6Addr>().map_err(|_| "Некорректный IPv6")?;
        (authority, None)
    } else {
        authority.split_once(':').map_or((authority, None), |(h, p)| (h, Some(p)))
    };
    if host.is_empty() || host.chars().any(|c| c.is_whitespace() || matches!(c, '@' | '[' | ']')) {
        return Err("Некорректный адрес цели".into());
    }
    let port = port_text.map(|p| p.parse::<u16>().ok().filter(|p| *p > 0).ok_or("Порт должен быть от 1 до 65535")).transpose()?;
    Ok(Target { host: host.into(), port, scheme, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_preserve_ipv6_ports_and_urls() {
        for raw in ["host", "host:8443", "[2001:db8::1]", "[2001:db8::1]:443", "2001:db8::1", "https://host:8443/path?q=a&b=c"] {
            let t = parse(raw).unwrap();
            assert!(t.socket().ends_with(&t.port.unwrap_or(443).to_string()));
            assert!(!t.host.contains('['));
            assert_eq!(parse(&t.url("https")).unwrap().host, t.host);
        }
        assert_eq!(parse("https://host:8443/path").unwrap().url("http"), "https://host:8443/path");
        assert_eq!(parse("2001:db8::1").unwrap().socket(), "[2001:db8::1]:443");
        assert_eq!(parse("http://host/path").unwrap().socket(), "host:80");
        for bad in ["", "[bad]", "host:0", "host:65536", "[::1]:", "user@host", "ftp://host"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}

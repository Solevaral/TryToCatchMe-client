//! Routing model + translation to sing-box `route` rules (pure, testable).
//!
//! Modes:
//!   global — everything through the proxy
//!   direct — everything direct (proxy off, tunnel still up)
//!   rule   — private IPs direct; then services + user rules + optional geo,
//!            unmatched traffic follows `final_action`.
//!
//! Services are additive & editable: each enabled service contributes its
//! domains/IPs with its own action (proxy/direct/block).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A user-defined routing rule.
#[derive(Serialize, Deserialize, Clone)]
pub struct Rule {
    /// "domain" | "domain_suffix" | "domain_keyword" | "ip_cidr"
    pub kind: String,
    pub value: String,
    /// "proxy" | "direct" | "block"
    pub action: String,
}

/// A predefined service (Cloudflare, Steam, …) — editable set of addresses.
#[derive(Serialize, Deserialize, Clone)]
pub struct Service {
    pub id: String,
    pub name: String,
    pub icon: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
}

/// An enabled service with its chosen action.
#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceSel {
    pub id: String,
    pub action: String,
}

fn default_mode() -> String {
    "rule".to_string()
}
fn default_final() -> String {
    "proxy".to_string()
}
fn default_geo_action() -> String {
    // RU region means "route Russian sites directly" (keep local traffic off the VPN).
    "direct".to_string()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RoutingConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub services: Vec<ServiceSel>,
    /// Region code for geosite/geoip rule-sets, e.g. "ru". None => off.
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default = "default_geo_action")]
    pub geo_action: String,
    /// Action for traffic that matches no rule (rule mode only).
    #[serde(default = "default_final")]
    pub final_action: String,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        RoutingConfig {
            mode: default_mode(),
            rules: Vec::new(),
            services: Vec::new(),
            region: None,
            geo_action: default_geo_action(),
            final_action: default_final(),
        }
    }
}

/// The materialized sing-box route pieces.
pub struct RouteSpec {
    pub rules: Vec<Value>,
    pub rule_sets: Vec<Value>,
    pub final_action: String,
}

/// Base URL for SagerNet's compiled rule-sets (.srs).
const GEOSITE_BASE: &str =
    "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set";
const GEOIP_BASE: &str = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set";

/// Build the sing-box route rules for a routing config + the service catalog.
pub fn build_route(cfg: &RoutingConfig, catalog: &[Service]) -> RouteSpec {
    match cfg.mode.as_str() {
        "global" => RouteSpec {
            rules: vec![],
            rule_sets: vec![],
            final_action: "proxy".to_string(),
        },
        "direct" => RouteSpec {
            rules: vec![],
            rule_sets: vec![],
            final_action: "direct".to_string(),
        },
        _ => build_rule_mode(cfg, catalog),
    }
}

fn build_rule_mode(cfg: &RoutingConfig, catalog: &[Service]) -> RouteSpec {
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_sets: Vec<Value> = Vec::new();

    // LAN / private IPs always direct.
    rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));

    // Services (additive): one rule per enabled service.
    for sel in &cfg.services {
        if let Some(svc) = catalog.iter().find(|s| s.id == sel.id) {
            let mut rule = serde_json::Map::new();
            if !svc.domains.is_empty() {
                rule.insert("domain_suffix".into(), json!(svc.domains));
            }
            if !svc.ip_cidrs.is_empty() {
                rule.insert("ip_cidr".into(), json!(svc.ip_cidrs));
            }
            if !rule.is_empty() {
                rule.insert("outbound".into(), json!(sanitize_action(&sel.action)));
                rules.push(Value::Object(rule));
            }
        }
    }

    // User rules grouped by (kind, action).
    for (key, values) in group_rules(&cfg.rules) {
        let (kind, action) = key;
        rules.push(json!({ &kind: values, "outbound": action }));
    }

    // Geo rule-sets by region.
    if let Some(region) = cfg.region.as_ref().filter(|r| !r.is_empty()) {
        let site_tag = format!("geosite-{region}");
        let ip_tag = format!("geoip-{region}");
        // NOTE: SagerNet publishes the per-country domain list as
        // "geosite-category-<code>.srs" (plain "geosite-ru.srs" returns 404 and
        // makes sing-box abort at startup).
        // Download the lists THROUGH the proxy: raw.githubusercontent.com is often
        // blocked/throttled by the local ISP (e.g. in Russia), so a direct download
        // silently fails. Going through the tunnel reaches GitHub reliably. The lists
        // are cached to disk (experimental.cache_file) and refreshed daily.
        rule_sets.push(json!({
            "type": "remote", "tag": site_tag,
            "format": "binary",
            "url": format!("{GEOSITE_BASE}/geosite-category-{region}.srs"),
            "download_detour": "proxy",
            "update_interval": "24h"
        }));
        rule_sets.push(json!({
            "type": "remote", "tag": ip_tag,
            "format": "binary",
            "url": format!("{GEOIP_BASE}/geoip-{region}.srs"),
            "download_detour": "proxy",
            "update_interval": "24h"
        }));
        rules.push(json!({
            "rule_set": [site_tag, ip_tag],
            "outbound": sanitize_action(&cfg.geo_action)
        }));
    }

    RouteSpec {
        rules,
        rule_sets,
        final_action: sanitize_action(&cfg.final_action),
    }
}

/// Group user rules into `{kind: [values...], outbound}` buckets, preserving order.
fn group_rules(rules: &[Rule]) -> Vec<((String, String), Vec<String>)> {
    let mut out: Vec<((String, String), Vec<String>)> = Vec::new();
    for r in rules {
        let kind = sanitize_kind(&r.kind);
        let action = sanitize_action(&r.action);
        let key = (kind, action);
        if let Some(entry) = out.iter_mut().find(|(k, _)| *k == key) {
            entry.1.push(r.value.clone());
        } else {
            out.push((key, vec![r.value.clone()]));
        }
    }
    out
}

fn sanitize_action(a: &str) -> String {
    match a {
        "direct" => "direct",
        "block" => "block",
        _ => "proxy",
    }
    .to_string()
}

fn sanitize_kind(k: &str) -> String {
    match k {
        "domain" => "domain",
        "domain_keyword" => "domain_keyword",
        "ip_cidr" => "ip_cidr",
        _ => "domain_suffix",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Vec<Service> {
        vec![Service {
            id: "cloudflare".into(),
            name: "Cloudflare".into(),
            icon: "☁".into(),
            domains: vec!["cloudflare.com".into()],
            ip_cidrs: vec!["1.1.1.1/32".into()],
        }]
    }

    #[test]
    fn global_mode() {
        let spec = build_route(
            &RoutingConfig {
                mode: "global".into(),
                ..Default::default()
            },
            &[],
        );
        assert_eq!(spec.final_action, "proxy");
        assert!(spec.rules.is_empty());
    }

    #[test]
    fn rule_mode_service_and_user() {
        let cfg = RoutingConfig {
            mode: "rule".into(),
            rules: vec![
                Rule { kind: "domain_suffix".into(), value: "example.com".into(), action: "direct".into() },
                Rule { kind: "domain_suffix".into(), value: "test.org".into(), action: "direct".into() },
            ],
            services: vec![ServiceSel { id: "cloudflare".into(), action: "proxy".into() }],
            region: Some("ru".into()),
            ..Default::default()
        };
        let spec = build_route(&cfg, &catalog());
        // private-ip + service + grouped user rule + geo = 4 rules
        assert_eq!(spec.rules.len(), 4);
        assert_eq!(spec.rule_sets.len(), 2);
        assert_eq!(spec.final_action, "proxy");
        // grouped user rule has both domains
        let user = &spec.rules[2];
        assert_eq!(user["domain_suffix"].as_array().unwrap().len(), 2);
    }
}

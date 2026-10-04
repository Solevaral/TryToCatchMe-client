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
    /// Optional community geosite list backing the service (e.g. "google-gemini"):
    /// complete and auto-updated, on top of the hand-maintained domains.
    #[serde(default)]
    pub geosite: Option<String>,
}

/// An enabled service with its chosen action.
#[derive(Serialize, Deserialize, Clone)]
pub struct ServiceSel {
    pub id: String,
    pub action: String,
    /// Route this service through a specific profile instead of the active one
    /// (e.g. Gemini through a server Google doesn't geolocate as a blocked country).
    #[serde(default)]
    pub profile: Option<String>,
}

/// Outbound tag for traffic pinned to a specific profile.
pub fn profile_tag(profile_id: &str) -> String {
    format!("via-{profile_id}")
}

fn default_mode() -> String {
    "rule".to_string()
}
fn default_final() -> String {
    "proxy".to_string()
}
fn default_true() -> bool {
    true
}
fn default_antifilter_final() -> String {
    "direct".to_string()
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
    /// Rule mode: the antifilter.download lists (blocked in Russia) go through the VPN.
    #[serde(default = "default_true")]
    pub antifilter: bool,
    /// 1.3.0 had a separate Antifilter mode with its own services and unmatched-traffic
    /// action. Read only to move them into Rule mode (see `migrate_antifilter_mode`).
    #[serde(default, skip_serializing)]
    pub antifilter_services: Vec<ServiceSel>,
    #[serde(default = "default_antifilter_final", skip_serializing)]
    pub antifilter_final: String,
}

impl RoutingConfig {
    /// 1.3.0's Antifilter mode → Rule mode with the lists on, its services merged in and
    /// its unmatched-traffic action kept. Returns true if anything changed.
    pub fn migrate_antifilter_mode(&mut self) -> bool {
        if self.mode != "antifilter" {
            return false;
        }
        self.mode = "rule".into();
        self.antifilter = true;
        self.final_action = sanitize_action(&self.antifilter_final);
        for sel in std::mem::take(&mut self.antifilter_services) {
            if !self.services.iter().any(|s| s.id == sel.id) {
                self.services.push(sel);
            }
        }
        true
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        // A fresh install: Rule mode, antifilter lists through the VPN, the rest directly.
        // Configs saved by older versions keep their values (serde defaults above).
        RoutingConfig {
            mode: default_mode(),
            rules: Vec::new(),
            services: Vec::new(),
            region: None,
            geo_action: default_geo_action(),
            final_action: "direct".to_string(),
            antifilter: true,
            antifilter_services: Vec::new(),
            antifilter_final: default_antifilter_final(),
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

/// What a downloaded list file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoKind {
    /// Compiled sing-box rule-set (.srs), used as is.
    Srs,
    /// Plain text, one domain per line → JSON rule-set with `domain_suffix`.
    DomainList,
    /// Plain text, one IP or CIDR per line → JSON rule-set with `ip_cidr`.
    IpList,
}

/// A geo rule-set file the app downloads for a region.
#[derive(Clone, Debug)]
pub struct GeoFile {
    pub tag: String,
    pub file_name: String,
    pub url: String,
    pub kind: GeoKind,
}

impl GeoFile {
    /// sing-box `format` of the stored file.
    pub fn format(&self) -> &'static str {
        if self.kind == GeoKind::Srs { "binary" } else { "source" }
    }
}

/// antifilter.download lists: the community-curated blocked domains and the
/// summarized blocked IP subnets (ipsum + subnet).
pub const ANTIFILTER_DOMAINS_URL: &str = "https://community.antifilter.download/list/domains.lst";
pub const ANTIFILTER_IP_URL: &str = "https://antifilter.download/list/allyouneed.lst";

pub fn antifilter_files() -> [GeoFile; 2] {
    [
        GeoFile {
            tag: "antifilter-domains".into(),
            file_name: "antifilter-domains.json".into(),
            url: ANTIFILTER_DOMAINS_URL.into(),
            kind: GeoKind::DomainList,
        },
        GeoFile {
            tag: "antifilter-ip".into(),
            file_name: "antifilter-ip.json".into(),
            url: ANTIFILTER_IP_URL.into(),
            kind: GeoKind::IpList,
        },
    ]
}

/// Turn a plain-text list into a sing-box source rule-set (JSON). Garbage lines are
/// skipped; a list that is too short is rejected (a block page or a cut-off download).
pub fn list_to_rule_set(kind: GeoKind, text: &str) -> Result<String, String> {
    let lines = text.lines().map(|l| l.trim().trim_matches('"')).filter(|l| !l.is_empty() && !l.starts_with('#'));
    let (key, values, min): (&str, Vec<String>, usize) = match kind {
        GeoKind::DomainList => (
            "domain_suffix",
            lines
                .map(|l| l.trim_start_matches("*.").trim_start_matches('.').to_ascii_lowercase())
                .filter(|d| d.contains('.') && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
                .collect(),
            50,
        ),
        GeoKind::IpList => (
            "ip_cidr",
            lines
                .filter(|l| l.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '/'))
                .filter(|l| l.split('/').next().is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok()))
                .map(str::to_string)
                .collect(),
            100,
        ),
        GeoKind::Srs => return Err("не текстовый список".into()),
    };
    if values.len() < min {
        return Err(format!("в списке только {} записей — это не список блокировок", values.len()));
    }
    Ok(json!({ "version": 2, "rules": [{ key: values }] }).to_string())
}

/// The downloaded geo lists that are available to the core.
#[derive(Clone, Copy)]
pub struct GeoInput<'a> {
    /// Folder holding the downloaded `.srs` files.
    pub dir: &'a str,
    /// Region files (geosite + geoip) are present.
    pub region_ready: bool,
    /// Service geosite names whose files are present (e.g. "google-gemini").
    pub geosites: &'a [String],
    /// antifilter lists are present.
    pub antifilter_ready: bool,
}

/// File for a service-backing geosite list.
pub fn service_geo_file(name: &str) -> GeoFile {
    let file = format!("geosite-{name}.srs");
    GeoFile {
        tag: format!("svc-geosite-{name}"),
        url: format!("{GEOSITE_BASE}/{file}"),
        file_name: file,
        kind: GeoKind::Srs,
    }
}

/// The files needed for a region. NOTE: SagerNet names the per-country domain list
/// "geosite-category-<code>.srs" (plain "geosite-<code>.srs" is a 404).
pub fn geo_files(region: &str) -> [GeoFile; 2] {
    let site = format!("geosite-category-{region}.srs");
    let ip = format!("geoip-{region}.srs");
    [
        GeoFile {
            tag: format!("geosite-{region}"),
            url: format!("{GEOSITE_BASE}/{site}"),
            file_name: site,
            kind: GeoKind::Srs,
        },
        GeoFile {
            tag: format!("geoip-{region}"),
            url: format!("{GEOIP_BASE}/{ip}"),
            file_name: ip,
            kind: GeoKind::Srs,
        },
    ]
}

/// Build the sing-box route rules for a routing config + the service catalog.
/// `geo` describes which downloaded lists exist; missing lists are simply left out.
pub fn build_route(cfg: &RoutingConfig, catalog: &[Service], geo: Option<&GeoInput>) -> RouteSpec {
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
        _ => build_rule_mode(cfg, catalog, geo),
    }
}

fn norm_domain(d: &str) -> String {
    d.trim().trim_start_matches('.').to_ascii_lowercase()
}

/// `a` is a narrower service than `b`: one of its domains lies strictly inside one of
/// b's (gemini.google.com in google.com), or its list is a sub-list (google-gemini of google).
fn narrower(a: &Service, b: &Service) -> bool {
    if let (Some(ga), Some(gb)) = (&a.geosite, &b.geosite) {
        if ga.starts_with(&format!("{gb}-")) {
            return true;
        }
    }
    a.domains.iter().map(|d| norm_domain(d)).any(|da| {
        b.domains
            .iter()
            .map(|d| norm_domain(d))
            .any(|db| !db.is_empty() && da.len() > db.len() && da.ends_with(&format!(".{db}")))
    })
}

/// Rank 0 = nothing narrower overlaps it; a service always ranks above every service
/// narrower than it. Bounded passes, so overlapping cycles can't loop forever.
fn service_ranks(services: &[&Service]) -> Vec<usize> {
    let n = services.len();
    let mut ranks = vec![0usize; n];
    for _ in 0..n {
        let mut changed = false;
        for a in 0..n {
            for b in 0..n {
                if a != b && narrower(services[a], services[b]) && ranks[b] <= ranks[a] && ranks[a] + 1 < n {
                    ranks[b] = ranks[a] + 1;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    ranks
}

fn build_rule_mode(cfg: &RoutingConfig, catalog: &[Service], geo: Option<&GeoInput>) -> RouteSpec {
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_sets: Vec<Value> = Vec::new();

    // LAN / private IPs always direct.
    rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));

    push_service_rules(&cfg.services, catalog, geo, &mut rules, &mut rule_sets);

    // User rules grouped by (kind, action).
    for (key, values) in group_rules(&cfg.rules) {
        let (kind, action) = key;
        rules.push(json!({ &kind: values, "outbound": action }));
    }

    // Blocked in Russia (antifilter.download) → VPN. Before the Russian-sites rule:
    // a blocked .ru site must not go out directly.
    if let Some(g) = geo.filter(|g| cfg.antifilter && g.antifilter_ready) {
        let mut tags = Vec::new();
        for f in antifilter_files() {
            rule_sets.push(json!({
                "type": "local",
                "tag": f.tag,
                "format": f.format(),
                "path": format!("{}/{}", g.dir.trim_end_matches(['/', '\\']), f.file_name)
            }));
            tags.push(f.tag);
        }
        rules.push(json!({ "rule_set": tags, "outbound": "proxy" }));
    }

    // Geo rule-sets by region, as LOCAL files the app downloads itself (see
    // `geo_files`). The core never fetches them, so a blocked/failed download can't
    // abort startup; without the files the geo rule is simply omitted.
    let region_geo = geo.filter(|g| g.region_ready);
    if let (Some(region), Some(g)) = (cfg.region.as_ref().filter(|r| !r.is_empty()), region_geo) {
        let dir = g.dir;
        let files = geo_files(region);
        let mut tags = Vec::new();
        for f in &files {
            rule_sets.push(json!({
                "type": "local",
                "tag": f.tag,
                "format": "binary",
                "path": format!("{}/{}", dir.trim_end_matches(['/', '\\']), f.file_name)
            }));
            tags.push(f.tag.clone());
        }
        rules.push(json!({
            "rule_set": tags,
            "outbound": sanitize_action(&cfg.geo_action)
        }));
    }

    RouteSpec {
        rules,
        rule_sets,
        final_action: sanitize_action(&cfg.final_action),
    }
}

/// Services (additive): one rule per enabled service (+ one for its geosite list).
/// sing-box takes the FIRST matching rule, so narrower services go first:
/// Gemini (gemini.google.com) must win over Google (google.com) regardless of the
/// order the user added them in. See `service_ranks`.
fn push_service_rules(
    selections: &[ServiceSel],
    catalog: &[Service],
    geo: Option<&GeoInput>,
    rules: &mut Vec<Value>,
    rule_sets: &mut Vec<Value>,
) {
    let enabled: Vec<(&ServiceSel, &Service)> = selections
        .iter()
        .filter_map(|sel| catalog.iter().find(|s| s.id == sel.id).map(|svc| (sel, svc)))
        .collect();
    let ranks = service_ranks(&enabled.iter().map(|(_, svc)| *svc).collect::<Vec<_>>());
    let mut domain_rules: Vec<(usize, Value)> = Vec::new();
    let mut list_rules: Vec<(usize, Value)> = Vec::new();
    for (i, (sel, svc)) in enabled.iter().enumerate() {
        let outbound = match (sanitize_action(&sel.action).as_str(), &sel.profile) {
            ("proxy", Some(pid)) if !pid.is_empty() => profile_tag(pid),
            (action, _) => action.to_string(),
        };
        let mut rule = serde_json::Map::new();
        if !svc.domains.is_empty() {
            rule.insert("domain_suffix".into(), json!(svc.domains));
        }
        if !svc.ip_cidrs.is_empty() {
            rule.insert("ip_cidr".into(), json!(svc.ip_cidrs));
        }
        if !rule.is_empty() {
            rule.insert("outbound".into(), json!(outbound));
            domain_rules.push((ranks[i], Value::Object(rule)));
        }
        if let (Some(name), Some(g)) = (&svc.geosite, geo) {
            if g.geosites.iter().any(|n| n == name) {
                let f = service_geo_file(name);
                if !rule_sets.iter().any(|r: &Value| r["tag"] == f.tag.as_str()) {
                    rule_sets.push(json!({
                        "type": "local",
                        "tag": f.tag,
                        "format": "binary",
                        "path": format!("{}/{}", g.dir.trim_end_matches(['/', '\\']), f.file_name)
                    }));
                }
                list_rules.push((ranks[i], json!({ "rule_set": [f.tag], "outbound": outbound })));
            }
        }
    }
    // Per rank: hand-written domains first, then the community lists (a broad list
    // like geosite-google also contains YouTube's domains).
    let max_rank = ranks.iter().copied().max().unwrap_or(0);
    for r in 0..=max_rank {
        rules.extend(domain_rules.iter().filter(|(k, _)| *k == r).map(|(_, v)| v.clone()));
        rules.extend(list_rules.iter().filter(|(k, _)| *k == r).map(|(_, v)| v.clone()));
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
            geosite: None,
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
            None,
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
            services: vec![ServiceSel { id: "cloudflare".into(), action: "proxy".into(), profile: None }],
            region: Some("ru".into()),
            final_action: "proxy".into(),
            ..Default::default()
        };
        let geo = GeoInput { dir: "C:/data/rules", region_ready: true, geosites: &[], antifilter_ready: false };
        let spec = build_route(&cfg, &catalog(), Some(&geo));
        // private-ip + service + grouped user rule + geo = 4 rules
        assert_eq!(spec.rules.len(), 4);
        assert_eq!(spec.rule_sets.len(), 2);
        assert_eq!(spec.rule_sets[0]["type"], "local");
        assert_eq!(spec.rule_sets[0]["path"], "C:/data/rules/geosite-category-ru.srs");
        // Without downloaded files the geo rule is left out instead of failing.
        let no_geo = build_route(&cfg, &catalog(), None);
        assert_eq!(no_geo.rules.len(), 3);
        assert!(no_geo.rule_sets.is_empty());
        assert_eq!(spec.final_action, "proxy");
        // grouped user rule has both domains
        let user = &spec.rules[2];
        assert_eq!(user["domain_suffix"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn service_geosite_and_pinned_profile() {
        let catalog = vec![Service {
            id: "gemini".into(),
            name: "Gemini".into(),
            icon: "".into(),
            domains: vec!["gemini.google.com".into()],
            ip_cidrs: vec![],
            geosite: Some("google-gemini".into()),
        }];
        let cfg = RoutingConfig {
            mode: "rule".into(),
            services: vec![ServiceSel { id: "gemini".into(), action: "proxy".into(), profile: Some("abc".into()) }],
            final_action: "direct".into(),
            ..Default::default()
        };
        let names = vec!["google-gemini".to_string()];
        let geo = GeoInput { dir: "D:/r", region_ready: false, geosites: &names, antifilter_ready: false };
        let spec = build_route(&cfg, &catalog, Some(&geo));
        // private + domain rule + geosite rule, both pinned to the chosen profile
        assert_eq!(spec.rules.len(), 3);
        assert_eq!(spec.rules[1]["outbound"], "via-abc");
        assert_eq!(spec.rules[2]["rule_set"][0], "svc-geosite-google-gemini");
        assert_eq!(spec.rules[2]["outbound"], "via-abc");
        assert_eq!(spec.rule_sets[0]["path"], "D:/r/geosite-google-gemini.srs");
        // Not downloaded yet -> no geosite rule, domains still routed.
        let spec2 = build_route(&cfg, &catalog, None);
        assert_eq!(spec2.rules.len(), 2);
    }

    #[test]
    fn narrower_services_match_first() {
        let svc = |id: &str, domains: &[&str], geosite: Option<&str>| Service {
            id: id.into(),
            name: id.into(),
            icon: "".into(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            ip_cidrs: vec![],
            geosite: geosite.map(|g| g.into()),
        };
        let catalog = vec![
            svc("google", &["google.com", "googleapis.com"], Some("google")),
            svc("youtube", &["youtube.com", "youtubei.googleapis.com"], None),
            svc("gemini", &["gemini.google.com"], Some("google-gemini")),
            svc("cloudflare", &["cloudflare.com"], None),
        ];
        let sel = |id: &str, profile: Option<&str>| ServiceSel {
            id: id.into(),
            action: "proxy".into(),
            profile: profile.map(|p| p.into()),
        };
        // Added in the "wrong" order: Google first.
        let cfg = RoutingConfig {
            mode: "rule".into(),
            services: vec![sel("google", Some("grpc")), sel("youtube", None), sel("gemini", Some("tcp")), sel("cloudflare", None)],
            final_action: "direct".into(),
            ..Default::default()
        };
        let names = vec!["google".to_string(), "google-gemini".to_string()];
        let geo = GeoInput { dir: "D:/r", region_ready: false, geosites: &names, antifilter_ready: false };
        let spec = build_route(&cfg, &catalog, Some(&geo));
        let pos = |f: &dyn Fn(&Value) -> bool| spec.rules.iter().position(|r| f(r)).unwrap();
        let google_domains = pos(&|r| r["domain_suffix"][0] == "google.com");
        let google_list = pos(&|r| r["rule_set"][0] == "svc-geosite-google");
        let gemini_domains = pos(&|r| r["domain_suffix"][0] == "gemini.google.com");
        let gemini_list = pos(&|r| r["rule_set"][0] == "svc-geosite-google-gemini");
        let youtube = pos(&|r| r["domain_suffix"][0] == "youtube.com");
        assert!(gemini_domains < google_domains && gemini_list < google_domains);
        assert!(youtube < google_domains && youtube < google_list);
        assert!(google_domains < google_list);
        assert_eq!(spec.rules[gemini_domains]["outbound"], "via-tcp");
        assert_eq!(spec.rules[google_domains]["outbound"], "via-grpc");
        // Unrelated services keep the user's order.
        assert!(youtube < pos(&|r| r["domain_suffix"][0] == "cloudflare.com"));
    }

    #[test]
    fn rule_mode_antifilter_before_region() {
        let cfg = RoutingConfig {
            mode: "rule".into(),
            services: vec![ServiceSel { id: "cloudflare".into(), action: "proxy".into(), profile: None }],
            region: Some("ru".into()),
            ..Default::default()
        };
        let geo = GeoInput { dir: "D:/r", region_ready: true, geosites: &[], antifilter_ready: true };
        let spec = build_route(&cfg, &catalog(), Some(&geo));
        // private + service + antifilter + region
        assert_eq!(spec.rules.len(), 4);
        assert_eq!(spec.rules[2]["rule_set"], json!(["antifilter-domains", "antifilter-ip"]));
        assert_eq!(spec.rules[2]["outbound"], "proxy");
        assert_eq!(spec.rules[3]["outbound"], "direct");
        assert_eq!(spec.rule_sets[0]["format"], "source");
        assert_eq!(spec.rule_sets[0]["path"], "D:/r/antifilter-domains.json");
        assert_eq!(spec.final_action, "direct");

        // Lists not downloaded yet / turned off — the rule is left out.
        let not_ready = GeoInput { antifilter_ready: false, ..geo };
        assert_eq!(build_route(&cfg, &catalog(), Some(&not_ready)).rules.len(), 3);
        let off = RoutingConfig { antifilter: false, ..cfg.clone() };
        assert_eq!(build_route(&off, &catalog(), Some(&geo)).rules.len(), 3);
    }

    #[test]
    fn antifilter_mode_of_1_3_0_moves_to_rule() {
        let mut cfg: RoutingConfig = serde_json::from_str(
            r#"{"mode":"antifilter","final_action":"proxy","services":[{"id":"a","action":"proxy"}],
                "antifilter":true,"antifilter_services":[{"id":"a","action":"direct"},{"id":"b","action":"proxy"}],
                "antifilter_final":"direct"}"#,
        )
        .unwrap();
        assert!(cfg.migrate_antifilter_mode());
        assert_eq!(cfg.mode, "rule");
        assert!(cfg.antifilter);
        assert_eq!(cfg.final_action, "direct");
        let ids: Vec<_> = cfg.services.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
        assert!(!serde_json::to_string(&cfg).unwrap().contains("antifilter_services"));
        assert!(!cfg.migrate_antifilter_mode());
    }

    #[test]
    fn fresh_install_defaults() {
        let d = RoutingConfig::default();
        assert_eq!(d.mode, "rule");
        assert!(d.antifilter);
        assert_eq!(d.final_action, "direct");
        // An old saved config without the new fields keeps its mode and gets the list on.
        let old: RoutingConfig = serde_json::from_str(r#"{"mode":"rule","final_action":"proxy"}"#).unwrap();
        assert_eq!(old.mode, "rule");
        assert_eq!(old.final_action, "proxy");
        assert!(old.antifilter);
    }

    #[test]
    fn plain_lists_become_rule_sets() {
        let domains = (0..60).map(|i| format!("site{i}.com")).collect::<Vec<_>>().join("\n") + "\n\"quoted.ru\nbad line\n*.wild.org";
        let json: Value = serde_json::from_str(&list_to_rule_set(GeoKind::DomainList, &domains).unwrap()).unwrap();
        let list = json["rules"][0]["domain_suffix"].as_array().unwrap();
        assert!(list.contains(&json!("quoted.ru")));
        assert!(list.contains(&json!("wild.org")));
        assert!(!list.iter().any(|d| d.as_str().unwrap().contains(' ')));

        let ips = (0..150).map(|i| format!("10.{i}.0.0/16")).collect::<Vec<_>>().join("\n") + "\n<html>";
        let json: Value = serde_json::from_str(&list_to_rule_set(GeoKind::IpList, &ips).unwrap()).unwrap();
        assert_eq!(json["rules"][0]["ip_cidr"].as_array().unwrap().len(), 150);

        assert!(list_to_rule_set(GeoKind::DomainList, "<html>blocked</html>").is_err());
    }
}

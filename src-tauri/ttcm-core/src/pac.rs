//! PAC script for the OS system proxy (pure, testable).
//!
//! A plain "everything → 127.0.0.1:port" system proxy pushes every app that reads it
//! through the core, even traffic the routing sends `direct` anyway — and some apps
//! break behind a local proxy (Discord: no video, 5000 ms voice ping). The PAC script
//! mirrors the sing-box route rules instead: hosts the routing sends anywhere but
//! `direct` go to the local proxy, everything else connects directly, exactly as with
//! the VPN off.
//!
//! Rules are evaluated in order, first match wins (like sing-box). Domain matchers need
//! no DNS; IP matchers (ip_cidr, IP rule-sets) resolve the host, so they run only for
//! hosts no earlier domain rule decided. `ip_is_private` is checked for IP literals
//! only — a domain that resolves to a LAN address and lands in the proxy is still sent
//! direct by the core itself.

use serde_json::{json, Map, Value};
use std::collections::HashMap;

/// Domains / IPs of one rule-set (from a source JSON or a decompiled .srs).
#[derive(Default, Debug, Clone, PartialEq)]
pub struct RuleSetData {
    pub domains: Vec<String>,
    pub suffixes: Vec<String>,
    pub keywords: Vec<String>,
    pub cidrs: Vec<String>,
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    }
}

/// Parse a sing-box source rule-set (`{"version":…, "rules":[{domain, domain_suffix, …}]}`).
pub fn parse_rule_set(text: &str) -> Result<RuleSetData, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("rule-set не JSON: {e}"))?;
    let mut d = RuleSetData::default();
    for r in v.get("rules").and_then(Value::as_array).into_iter().flatten() {
        d.domains.extend(strings(r.get("domain")));
        d.suffixes.extend(strings(r.get("domain_suffix")));
        d.keywords.extend(strings(r.get("domain_keyword")));
        d.cidrs.extend(strings(r.get("ip_cidr")));
    }
    Ok(d)
}

const MATCHERS: [&str; 6] = ["domain", "domain_suffix", "domain_keyword", "ip_cidr", "rule_set", "ip_is_private"];

/// IPv4 CIDRs as merged, sorted [start, end] pairs (IPv6 is skipped: PAC's
/// dnsResolve returns IPv4).
fn ipv4_ranges(cidrs: &[String]) -> Vec<(u32, u32)> {
    let mut r: Vec<(u32, u32)> = cidrs
        .iter()
        .filter_map(|c| {
            let (ip, len) = c.trim().split_once('/').unwrap_or((c.trim(), "32"));
            let ip: std::net::Ipv4Addr = ip.parse().ok()?;
            let len: u32 = len.parse().ok().filter(|l| *l <= 32)?;
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            let start = u32::from(ip) & mask;
            Some((start, start | !mask))
        })
        .collect();
    r.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(r.len());
    for (s, e) in r {
        match merged.last_mut() {
            Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

fn norm(d: &str) -> String {
    d.trim().trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase()
}

/// One route rule as a PAC rule object, or None when it uses a matcher PAC can't
/// evaluate (then it's left out: such traffic falls through to later rules / final).
fn pac_rule(rule: &Value, sets: &HashMap<String, RuleSetData>) -> Option<(bool, Value)> {
    let obj = rule.as_object()?;
    let proxy = match obj.get("outbound").and_then(Value::as_str) {
        Some("direct") => false,
        Some(_) => true,
        None => return None,
    };
    if obj.keys().any(|k| k != "outbound" && !MATCHERS.contains(&k.as_str())) {
        return None;
    }
    let mut data = RuleSetData {
        domains: strings(obj.get("domain")),
        suffixes: strings(obj.get("domain_suffix")),
        keywords: strings(obj.get("domain_keyword")),
        cidrs: strings(obj.get("ip_cidr")),
    };
    for tag in strings(obj.get("rule_set")) {
        if let Some(s) = sets.get(&tag) {
            data.domains.extend(s.domains.iter().cloned());
            data.suffixes.extend(s.suffixes.iter().cloned());
            data.keywords.extend(s.keywords.iter().cloned());
            data.cidrs.extend(s.cidrs.iter().cloned());
        }
    }
    let mut out = Map::new();
    out.insert("o".into(), json!(proxy as u8));
    let set = |v: &[String]| Value::Object(v.iter().map(|d| (norm(d), json!(1))).filter(|(k, _)| !k.is_empty()).collect());
    if !data.domains.is_empty() {
        out.insert("d".into(), set(&data.domains));
    }
    if !data.suffixes.is_empty() {
        out.insert("s".into(), set(&data.suffixes));
    }
    if !data.keywords.is_empty() {
        out.insert("k".into(), json!(data.keywords.iter().map(|k| k.to_ascii_lowercase()).collect::<Vec<_>>()));
    }
    let ranges = ipv4_ranges(&data.cidrs);
    if !ranges.is_empty() {
        out.insert("r".into(), json!(ranges.iter().flat_map(|(s, e)| [*s, *e]).collect::<Vec<_>>()));
    }
    if obj.get("ip_is_private").and_then(Value::as_bool) == Some(true) {
        out.insert("p".into(), json!(1));
    }
    // A rule with nothing left to match (e.g. its rule-set isn't downloaded) is dropped.
    (out.len() > 1).then_some((proxy, Value::Object(out)))
}

const PAC_JS: &str = r#"
function sfx(t,h){for(;;){if(t[h])return true;var i=h.indexOf(".");if(i<0)return false;h=h.substring(i+1);}}
function kw(a,h){for(var i=0;i<a.length;i++)if(h.indexOf(a[i])>=0)return true;return false;}
function ip4(s){var m=/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s);return m?((+m[1])*16777216+(+m[2])*65536+(+m[3])*256+(+m[4])):null;}
function inR(r,n){var lo=0,hi=r.length/2-1;while(lo<=hi){var m=(lo+hi)>>1;if(n<r[2*m])hi=m-1;else if(n>r[2*m+1])lo=m+1;else return true;}return false;}
function priv(n){return n>>>24==10||n>>>24==127||n>>>20==0xAC1||n>>>16==0xC0A8||n>>>16==0xA9FE||n>>>22==0x191;}
function FindProxyForURL(url,host){
 host=host.toLowerCase().replace(/\.$/,"");
 if(isPlainHostName(host))return "DIRECT";
 var lit=ip4(host),ip=lit,tried=lit!==null;
 for(var i=0;i<R.length;i++){var x=R[i];
  if((x.d&&x.d[host])||(x.s&&sfx(x.s,host))||(x.k&&kw(x.k,host))||(x.p&&lit!==null&&priv(lit)))return x.o?P:"DIRECT";
  if(x.r){if(!tried){tried=true;var a=dnsResolve(host);ip=a?ip4(a):null;}if(ip!==null&&inR(x.r,ip))return x.o?P:"DIRECT";}
 }
 return F?P:"DIRECT";
}
"#;

/// The PAC script for the given sing-box route rules. `proxy` is `host:port` of the
/// local mixed inbound; `sets` holds the data of the rule-sets the rules refer to.
pub fn generate(rules: &[Value], final_action: &str, sets: &HashMap<String, RuleSetData>, proxy: &str) -> String {
    let final_proxy = final_action != "direct";
    let mut pac_rules: Vec<(bool, Value)> = rules.iter().filter_map(|r| pac_rule(r, sets)).collect();
    // Trailing rules that end where `final` ends anyway change nothing.
    while pac_rules.last().is_some_and(|(p, _)| *p == final_proxy) {
        pac_rules.pop();
    }
    let rules_json = Value::Array(pac_rules.into_iter().map(|(_, v)| v).collect());
    format!(
        "// TryToCatchMe: hosts the routing sends through the VPN go to the local proxy, the rest directly.\nvar P=\"PROXY {proxy}; DIRECT\";\nvar F={};\nvar R={};{PAC_JS}",
        final_proxy as u8, rules_json
    )
}

/// PAC that sends everything directly (served while disconnected).
pub fn direct_only() -> String {
    "function FindProxyForURL(url,host){return \"DIRECT\";}\n".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sets() -> HashMap<String, RuleSetData> {
        let mut m = HashMap::new();
        m.insert(
            "antifilter-domains".into(),
            parse_rule_set(r#"{"version":1,"rules":[{"domain_suffix":["blocked.ru","rutracker.org"]}]}"#).unwrap(),
        );
        m.insert(
            "antifilter-ip".into(),
            parse_rule_set(r#"{"version":1,"rules":[{"ip_cidr":["149.154.160.0/20","91.108.4.0/22","2001:67c::/32"]}]}"#).unwrap(),
        );
        m
    }

    fn rules() -> Vec<Value> {
        vec![
            json!({ "ip_is_private": true, "outbound": "direct" }),
            json!({ "domain_suffix": ["claude.ai", "anthropic.com"], "outbound": "proxy" }),
            json!({ "domain_suffix": ["direct.claude.ai"], "outbound": "direct" }),
            json!({ "rule_set": ["antifilter-domains", "antifilter-ip"], "outbound": "proxy" }),
            json!({ "rule_set": ["geosite-category-ru"], "outbound": "direct" }),
        ]
    }

    #[test]
    fn rule_sets_parse_from_source_json() {
        let d = parse_rule_set(r#"{"rules":[{"domain":"a.com","domain_suffix":["b.com"],"domain_keyword":"kw"},{"ip_cidr":["1.2.3.0/24"]}]}"#).unwrap();
        assert_eq!(d.domains, ["a.com"]);
        assert_eq!(d.suffixes, ["b.com"]);
        assert_eq!(d.keywords, ["kw"]);
        assert_eq!(d.cidrs, ["1.2.3.0/24"]);
    }

    #[test]
    fn ranges_merge_and_skip_ipv6() {
        let r = ipv4_ranges(&["10.0.0.0/9".into(), "10.128.0.0/9".into(), "1.1.1.1".into(), "::1/128".into()]);
        assert_eq!(r, [(0x01010101, 0x01010101), (0x0A000000, 0x0AFFFFFF)]);
    }

    #[test]
    fn pac_carries_proxied_rules_and_drops_trailing_direct() {
        let pac = generate(&rules(), "direct", &sets(), "127.0.0.1:2080");
        assert!(pac.contains("var P=\"PROXY 127.0.0.1:2080; DIRECT\""));
        assert!(pac.contains("var F=0"));
        assert!(pac.contains("\"claude.ai\":1"));
        assert!(pac.contains("\"rutracker.org\":1"));
        // 149.154.160.0/20 and 91.108.4.0/22 as numbers; IPv6 left out.
        assert!(pac.contains(&(0x959AA000u32).to_string()));
        assert!(pac.contains(&(0x5B6C0400u32).to_string()));
        // The trailing direct geo rule (its set isn't even loaded) is gone; the
        // narrower direct service stays before the broader proxied one is reached.
        assert!(pac.contains("\"direct.claude.ai\":1"));
        assert!(!pac.contains("geosite"));
    }

    #[test]
    fn global_and_direct_modes() {
        assert!(generate(&[], "proxy", &HashMap::new(), "127.0.0.1:2080").contains("var F=1"));
        let direct = generate(&[], "direct", &HashMap::new(), "127.0.0.1:2080");
        assert!(direct.contains("var F=0") && direct.contains("var R=[]"));
    }

    #[test]
    fn rules_with_unknown_matchers_are_left_out() {
        let r = vec![json!({ "process_name": ["x"], "domain": ["x.com"], "outbound": "proxy" })];
        assert!(generate(&r, "direct", &HashMap::new(), "127.0.0.1:2080").contains("var R=[]"));
    }
}

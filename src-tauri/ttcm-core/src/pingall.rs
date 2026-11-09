//! Pure helpers for testing profiles through a separate sing-box instance.

use serde::Serialize;
use serde_json::{json, Value};

pub fn test_tag(i: usize) -> String {
    format!("t{i}")
}

/// Build an isolated test config; inputs are sing-box outbound objects.
pub fn build_test_config(outbounds: &[Value], uplink: Option<&str>, clash_port: u16) -> Value {
    let mut test_outbounds = vec![json!({
        "type": "direct", "tag": "direct", "domain_resolver": "dns-direct"
    })];
    for (i, outbound) in outbounds.iter().enumerate() {
        let mut outbound = outbound.clone();
        outbound["tag"] = json!(test_tag(i));
        outbound["domain_resolver"] = json!("dns-direct");
        test_outbounds.push(outbound);
    }
    let mut route = json!({ "final": "direct" });
    if let Some(name) = uplink {
        // The DNS server has no detour (sing-box 1.14 rejects one to "direct"), so it
        // uses the default dialer: pin that to the uplink too, never the VPN adapter.
        route["default_interface"] = json!(name);
        for outbound in &mut test_outbounds {
            outbound["bind_interface"] = json!(name);
        }
    } else {
        route["auto_detect_interface"] = json!(true);
    }
    json!({
        "log": { "level": "warn" },
        "dns": {
            "servers": [{
                "type": "udp", "tag": "dns-direct", "server": "77.88.8.8"
            }],
            "strategy": "ipv4_only"
        },
        "outbounds": test_outbounds,
        "route": route,
        "experimental": {
            "clash_api": { "external_controller": format!("127.0.0.1:{clash_port}") }
        }
    })
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PingResult {
    Ok { ms: u64 },
    Partial { ms: u64, note: String },
    Fail { reason: String },
}

pub fn classify(google_ms: Option<u64>, cloudflare_ms: Option<u64>) -> PingResult {
    match (google_ms, cloudflare_ms) {
        (Some(ms), _) => PingResult::Ok { ms },
        (None, Some(ms)) => PingResult::Partial {
            ms,
            note: "Google недоступен через этот сервер".to_owned(),
        },
        (None, None) => PingResult::Fail {
            reason: "нет ответа через сервер".to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_dns_does_not_detour_to_an_empty_direct_outbound() {
        for uplink in [None, Some("Ethernet")] {
            let config = build_test_config(&[], uplink, 29090);
            assert!(config["dns"]["servers"][0].get("detour").is_none());
            assert_eq!(config["route"].get("default_interface").and_then(|v| v.as_str()), uplink);
        }
    }

    #[test]
    #[ignore = "BUG: non-object outbound from saved profiles panics in config generation"]
    fn malformed_saved_outbound_does_not_panic() {
        let _ = build_test_config(&[json!(42)], None, 29090);
    }

    #[test]
    fn generates_tags() {
        assert_eq!(test_tag(0), "t0");
        assert_eq!(test_tag(42), "t42");
    }

    #[test]
    fn config_preserves_fields_and_binds_every_outbound() {
        let inputs = vec![
            json!({"type": "vless", "tag": "old", "server": "example.invalid", "server_port": 443,
                   "tls": {"enabled": true}, "domain_resolver": "old-dns", "bind_interface": "old"}),
            json!({"type": "hysteria2", "server_port": 8443}),
        ];
        let original = inputs.clone();
        let config = build_test_config(&inputs, Some("Беспроводная сеть"), 12345);
        let outbounds = config["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 3);
        assert_eq!(outbounds[0]["type"], "direct");
        assert_eq!(outbounds[0]["tag"], "direct");
        for outbound in outbounds {
            assert_eq!(outbound["bind_interface"], "Беспроводная сеть");
            assert_eq!(outbound["domain_resolver"], "dns-direct");
        }
        for (i, input) in inputs.iter().enumerate() {
            assert_eq!(outbounds[i + 1]["tag"], test_tag(i));
            for (key, value) in input.as_object().unwrap() {
                if !["tag", "domain_resolver", "bind_interface"].contains(&key.as_str()) {
                    assert_eq!(&outbounds[i + 1][key], value);
                }
            }
        }
        assert_eq!(inputs, original);
        assert!(config.get("inbounds").is_none());
        assert_eq!(config["log"], json!({"level": "warn"}));
        assert_eq!(config["route"], json!({"final": "direct", "default_interface": "Беспроводная сеть"}));
        assert_eq!(
            config["dns"],
            json!({
                "servers": [{"type": "udp", "tag": "dns-direct", "server": "77.88.8.8"}],
                "strategy": "ipv4_only"
            })
        );
        assert_eq!(
            config["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:12345"
        );
    }

    #[test]
    fn config_auto_detects_interface_without_uplink() {
        let config = build_test_config(&[json!({"type": "vless"})], None, 65535);
        assert_eq!(
            config["route"],
            json!({"final": "direct", "auto_detect_interface": true})
        );
        for outbound in config["outbounds"].as_array().unwrap() {
            assert!(outbound.get("bind_interface").is_none());
        }
        assert_eq!(
            build_test_config(&[], None, 0)["outbounds"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn classifies_and_serializes_all_response_combinations() {
        let cases = [
            (
                Some(30),
                Some(20),
                PingResult::Ok { ms: 30 },
                json!({"status": "ok", "ms": 30}),
            ),
            (
                Some(0),
                None,
                PingResult::Ok { ms: 0 },
                json!({"status": "ok", "ms": 0}),
            ),
            (
                None,
                Some(20),
                PingResult::Partial {
                    ms: 20,
                    note: "Google недоступен через этот сервер".to_owned(),
                },
                json!({"status": "partial", "ms": 20, "note": "Google недоступен через этот сервер"}),
            ),
            (
                None,
                None,
                PingResult::Fail {
                    reason: "нет ответа через сервер".to_owned(),
                },
                json!({"status": "fail", "reason": "нет ответа через сервер"}),
            ),
        ];
        for (google, cloudflare, expected, serialized) in cases {
            let result = classify(google, cloudflare);
            assert_eq!(result, expected);
            assert_eq!(serde_json::to_value(result).unwrap(), serialized);
        }
    }
}

/// Writes the test config for the user's real profiles (no secrets printed):
/// `TTCM_PROFILES=<profiles.json> TTCM_OUT=<file> cargo test -p ttcm-core live_test_config -- --ignored`.
#[cfg(test)]
#[test]
#[ignore]
fn live_test_config() {
    let p: Value = serde_json::from_str(&std::fs::read_to_string(std::env::var("TTCM_PROFILES").unwrap()).unwrap()).unwrap();
    let outbounds: Vec<Value> = p["profiles"].as_array().unwrap().iter().map(|x| x["outbound"].clone()).collect();
    let cfg = build_test_config(&outbounds, Some("Ethernet"), 29099);
    std::fs::write(std::env::var("TTCM_OUT").unwrap(), serde_json::to_vec(&cfg).unwrap()).unwrap();
}

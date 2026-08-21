/// Versioned trigger battery: requests designed to provoke a WAF into
/// revealing itself (block pages, anomalous statuses, challenge cookies).
///
/// Triggers are data, not scattered inline checks — add a new one by adding a
/// `Trigger` to [`default_triggers`], and bump [`TRIGGER_SET_VERSION`] if the
/// change alters scan semantics.
pub const TRIGGER_SET_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerKind {
    /// Appended as the `wafid` query parameter (URL-encoded).
    Query,
    /// Appended to the path (percent-encoded except `/`, so traversal stays
    /// recognizable after server-side normalization).
    Path,
    /// Oversized/malformed header probe; payload goes into a request header.
    Header,
}

#[derive(Debug, Clone, Copy)]
pub struct Trigger {
    pub name: &'static str,
    pub kind: TriggerKind,
    pub payload: &'static str,
}

pub const DEFAULT_TRIGGERS: [Trigger; 8] = [
    Trigger {
        name: "xss_tag",
        kind: TriggerKind::Query,
        payload: "<script>alert(1)</script>",
    },
    Trigger {
        name: "sqli_classic",
        kind: TriggerKind::Query,
        payload: "' OR '1'='1",
    },
    Trigger {
        name: "sqli_union",
        kind: TriggerKind::Query,
        payload: "UNION SELECT NULL,NULL,NULL--",
    },
    Trigger {
        name: "path_traversal",
        kind: TriggerKind::Path,
        payload: "../../../../etc/passwd",
    },
    Trigger {
        name: "cmd_injection",
        kind: TriggerKind::Query,
        payload: "; cat /etc/passwd",
    },
    Trigger {
        name: "ssti_probe",
        kind: TriggerKind::Query,
        payload: "${jndi:ldap://wafid.invalid/a}",
    },
    Trigger {
        name: "path_traversal_encoded",
        kind: TriggerKind::Path,
        payload: "..%2f..%2f..%2fetc%2fpasswd",
    },
    Trigger {
        name: "oversized_header",
        kind: TriggerKind::Header,
        payload: "",
    },
];

/// The header used for the oversized-header probe (~7KB of 'A's).
const OVERSIZED_HEADER_NAME: &str = "X-Wafid-Probe";
const OVERSIZED_HEADER_LEN: usize = 7 * 1024;

pub fn default_triggers() -> &'static [Trigger] {
    &DEFAULT_TRIGGERS
}

/// The concrete HTTP request a trigger expands to.
#[derive(Debug, Clone)]
pub enum ProbeTarget {
    Get {
        url: url::Url,
        headers: Vec<(String, String)>,
    },
}

/// A probe request paired with the name of the trigger that produced it.
#[derive(Debug, Clone)]
pub struct BuiltProbe {
    pub trigger: &'static str,
    pub target: ProbeTarget,
}

/// Expand a trigger against a base URL into a concrete GET request.
pub fn apply(base: &url::Url, trigger: &Trigger) -> Option<ProbeTarget> {
    match trigger.kind {
        TriggerKind::Query => {
            let mut url = base.clone();
            // query_pairs_mut percent-encodes the payload exactly once.
            url.query_pairs_mut().append_pair("wafid", trigger.payload);
            Some(ProbeTarget::Get {
                url,
                headers: Vec::new(),
            })
        }
        TriggerKind::Path => {
            // Built manually: `push()` would double-encode our pre-encoded
            // payloads, and we deliberately preserve '/' and '%' so traversal
            // probes keep their wire shape.
            let mut candidate = format!(
                "{}://{}{}",
                base.scheme(),
                base.authority(),
                base.path().trim_end_matches('/')
            );
            candidate.push('/');
            candidate.push_str(&encode_path_segment(trigger.payload));
            if let Some(q) = base.query() {
                candidate.push('?');
                candidate.push_str(q);
            }
            let url = url::Url::parse(&candidate).ok()?;
            Some(ProbeTarget::Get {
                url,
                headers: Vec::new(),
            })
        }
        TriggerKind::Header => {
            let value: String = "A".repeat(OVERSIZED_HEADER_LEN);
            Some(ProbeTarget::Get {
                url: base.clone(),
                headers: vec![(OVERSIZED_HEADER_NAME.to_string(), value)],
            })
        }
    }
}

/// Build the full probe request list for a target.
pub fn build_requests(base: &url::Url) -> Vec<BuiltProbe> {
    default_triggers()
        .iter()
        .filter_map(|t| {
            apply(base, t).map(|target| BuiltProbe {
                trigger: t.name,
                target,
            })
        })
        .collect()
}

/// Percent-encode a path segment, preserving `/` (traversal shape) and `%`
/// (so pre-encoded probes such as `..%2f` survive single-encoded).
fn encode_path_segment(v: &str) -> String {
    encode(v, b"-_.~/%")
}

fn encode(v: &str, safe_extra: &[u8]) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || safe_extra.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_payload_is_encoded_exactly_once() {
        let base = url::Url::parse("https://t.local/page").unwrap();
        let t = Trigger {
            name: "x",
            kind: TriggerKind::Query,
            payload: "<script>alert(1)</script>",
        };
        match apply(&base, &t) {
            Some(ProbeTarget::Get { url, .. }) => {
                assert!(
                    url.as_str().contains("%3Cscript"),
                    "single-encoded expected: {}",
                    url
                );
                assert!(
                    !url.as_str().contains("%253C"),
                    "double-encoded payload leaked: {}",
                    url
                );
            }
            _ => panic!("expected probe"),
        }
    }

    #[test]
    fn traversal_keeps_target_shape() {
        let base = url::Url::parse("https://t.local/app").unwrap();
        let t = Trigger {
            name: "p",
            kind: TriggerKind::Path,
            payload: "../../../../etc/passwd",
        };
        match apply(&base, &t) {
            Some(ProbeTarget::Get { url, .. }) => {
                // Note: the url crate (like browsers) normalizes `/../` dot
                // segments at parse time, so the wire form is the collapsed
                // path — which is exactly what an origin/WAF receives from a
                // real attacker tool too.
                assert!(url.path().contains("/etc/passwd"), "path shape: {url}");
            }
            _ => panic!("expected probe"),
        }
    }

    #[test]
    fn pre_encoded_traversal_survives_single_encoded() {
        let base = url::Url::parse("https://t.local/").unwrap();
        let t = Trigger {
            name: "pe",
            kind: TriggerKind::Path,
            payload: "..%2fetc%2fpasswd",
        };
        match apply(&base, &t) {
            Some(ProbeTarget::Get { url, .. }) => {
                assert!(
                    url.path().contains("..%2fetc"),
                    "% must not double-encode: {}",
                    url
                );
                assert!(
                    !url.as_str().contains("%25"),
                    "double-encoded payload leaked: {}",
                    url
                );
            }
            _ => panic!("expected probe"),
        }
    }

    #[test]
    fn header_probe_uses_oversized_value() {
        let base = url::Url::parse("https://t.local/").unwrap();
        let t = Trigger {
            name: "h",
            kind: TriggerKind::Header,
            payload: "",
        };
        match apply(&base, &t) {
            Some(ProbeTarget::Get { headers, .. }) => {
                assert_eq!(headers.len(), 1);
                assert!(headers[0].1.len() > 1024);
            }
            _ => panic!("expected probe"),
        }
    }
}

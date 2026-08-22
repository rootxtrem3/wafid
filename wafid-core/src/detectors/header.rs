use super::Detector;
use crate::signatures::VendorSig;
use crate::{Match, Response};

/// Matches response headers against signature rules. Header signals are
/// persistent (a WAF's own headers appear on every response), so both the
/// baseline and triggered responses are inspected.
pub struct HeaderDetector<'a> {
    pack: &'a [VendorSig],
}

impl<'a> HeaderDetector<'a> {
    pub fn new(pack: &'a [VendorSig]) -> Self {
        Self { pack }
    }
}

impl Detector for HeaderDetector<'_> {
    fn name(&self) -> &'static str {
        "header"
    }

    fn analyze(&self, baseline: &Response, triggered: &[super::ProbeResult]) -> Vec<Match> {
        let mut out = Vec::new();
        for vendor in self.pack {
            for sig in &vendor.headers {
                // Each header signal fires at most once per scan; check every
                // response since some headers only appear on block pages.
                let mut responses: Vec<&Response> = vec![baseline];
                responses.extend(triggered.iter().map(|t| &t.response));
                'signals: for resp in responses {
                    for value in resp.header_all(&sig.key) {
                        if sig.matcher.matches(value) {
                            out.push(Match {
                                vendor: vendor.vendor.clone(),
                                detector: self.name(),
                                strength: sig.strength.weight(),
                                strength_tier: sig.strength.tier(),
                                evidence: match sig.matcher {
                                    crate::signatures::ValueMatcher::Exists => {
                                        format!("header:{} exists", sig.key)
                                    }
                                    _ => format!(
                                        "header:{} {} (value '{}')",
                                        sig.key,
                                        sig.matcher.describe(),
                                        truncate(value, 60)
                                    ),
                                },
                            });
                            break 'signals;
                        }
                    }
                }
            }
        }
        out
    }
}

pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::test_support::{probe, resp};
    use crate::signatures::builtin_pack;

    #[test]
    fn detects_cloudflare_header_on_baseline() {
        let pack = builtin_pack().unwrap();
        let d = HeaderDetector::new(&pack);
        let base = resp(
            200,
            &[("server", "cloudflare"), ("cf-ray", "8ab1")],
            "<html/>",
        );
        let m = d.analyze(&base, &[]);
        let vendors: Vec<&str> = m.iter().map(|x| x.vendor.as_str()).collect();
        assert!(vendors.contains(&"Cloudflare"));
        assert!(m.iter().all(|x| x.detector == "header"));
    }

    #[test]
    fn detects_header_only_on_triggered_response() {
        let pack = builtin_pack().unwrap();
        let d = HeaderDetector::new(&pack);
        let base = resp(200, &[("server", "nginx")], "hi");
        let trig = vec![probe(
            "xss_tag",
            403,
            &[("x-amzn-waf-action", "block")],
            "blocked",
        )];
        let m = d.analyze(&base, &trig);
        assert!(m.iter().any(|x| x.vendor == "AWS WAF"));
    }

    #[test]
    fn no_false_positive_on_clean_responses() {
        let pack = builtin_pack().unwrap();
        let d = HeaderDetector::new(&pack);
        let base = resp(200, &[("server", "nginx"), ("x-custom", "zzz")], "hi");
        let trig = vec![probe(
            "xss_tag",
            200,
            &[("content-type", "text/html")],
            "hi",
        )];
        assert!(d.analyze(&base, &trig).is_empty());
    }

    #[test]
    fn regex_mode_matches_server_header() {
        let pack = builtin_pack().unwrap();
        let d = HeaderDetector::new(&pack);
        let base = resp(200, &[("server", "Apache/2.4 Mod_Security/2.9")], "x");
        let m = d.analyze(&base, &[]);
        assert!(m.iter().any(|x| x.vendor == "ModSecurity (generic)"));
    }
}

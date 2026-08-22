use super::Detector;
use crate::signatures::VendorSig;
use crate::{Match, Response};

/// Matches Set-Cookie *names* against signature regexes. Cookie signals are
/// persistent, so all responses are inspected; each signal fires at most once
/// per scan.
pub struct CookieDetector<'a> {
    pack: &'a [VendorSig],
}

impl<'a> CookieDetector<'a> {
    pub fn new(pack: &'a [VendorSig]) -> Self {
        Self { pack }
    }
}

impl Detector for CookieDetector<'_> {
    fn name(&self) -> &'static str {
        "cookie"
    }

    fn analyze(&self, baseline: &Response, triggered: &[super::ProbeResult]) -> Vec<Match> {
        let mut out = Vec::new();
        let mut responses: Vec<&Response> = vec![baseline];
        responses.extend(triggered.iter().map(|t| &t.response));

        for vendor in self.pack {
            for sig in &vendor.cookies {
                'signals: for resp in &responses {
                    for name in resp.cookie_names() {
                        if sig.pattern.is_match(name) {
                            out.push(Match {
                                vendor: vendor.vendor.clone(),
                                detector: self.name(),
                                strength: sig.strength.weight(),
                                strength_tier: sig.strength.tier(),
                                evidence: format!("cookie:{} matched '{}'", sig.pattern_raw, name),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::test_support::{probe, resp};
    use crate::signatures::builtin_pack;

    #[test]
    fn detects_incapsula_session_cookie() {
        let pack = builtin_pack().unwrap();
        let d = CookieDetector::new(&pack);
        let base = resp(
            200,
            &[
                ("set-cookie", "incap_ses_1234Abc=xyz; Path=/"),
                ("server", "nginx"),
            ],
            "hi",
        );
        let m = d.analyze(&base, &[]);
        assert!(m.iter().any(|x| x.vendor == "Imperva/Incapsula"));
        assert_eq!(m[0].detector, "cookie");
        assert!(m[0].evidence.contains("incap_ses_1234Abc"));
    }

    #[test]
    fn detects_cf_cookie_on_triggered_response() {
        let pack = builtin_pack().unwrap();
        let d = CookieDetector::new(&pack);
        let base = resp(200, &[], "hi");
        let trig = vec![probe(
            "xss_tag",
            403,
            &[("set-cookie", "__cf_bm=abc; Path=/")],
            "blocked",
        )];
        let m = d.analyze(&base, &trig);
        assert!(m.iter().any(|x| x.vendor == "Cloudflare"));
    }

    #[test]
    fn unrelated_cookies_match_nothing() {
        let pack = builtin_pack().unwrap();
        let d = CookieDetector::new(&pack);
        let base = resp(200, &[("set-cookie", "session_id=xyz; Path=/")], "hi");
        assert!(d.analyze(&base, &[]).is_empty());
    }
}

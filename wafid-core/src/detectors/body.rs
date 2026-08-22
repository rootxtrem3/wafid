use super::Detector;
use crate::signatures::{BodyMatcher, VendorSig};
use crate::{Match, Response};

/// Matches block-page content in response bodies.
///
/// False-positive control: by default a body signal only counts when the
/// pattern appears in a *triggered* response and is absent from the baseline
/// page — i.e. something changed because we sent an attack string. Signals
/// marked `always: true` (vendor branding injected into every page) also
/// fire on the baseline alone.
pub struct BodyDetector<'a> {
    pack: &'a [VendorSig],
}

impl<'a> BodyDetector<'a> {
    pub fn new(pack: &'a [VendorSig]) -> Self {
        Self { pack }
    }
}

impl Detector for BodyDetector<'_> {
    fn name(&self) -> &'static str {
        "body"
    }

    fn analyze(&self, baseline: &Response, triggered: &[super::ProbeResult]) -> Vec<Match> {
        let mut out = Vec::new();
        let baseline_hit = |m: &BodyMatcher| m.matches(&baseline.body);

        for vendor in self.pack {
            for sig in &vendor.body {
                if sig.always {
                    if baseline_hit(&sig.matcher) {
                        out.push(Match {
                            vendor: vendor.vendor.clone(),
                            detector: self.name(),
                            strength: sig.strength.weight(),
                            strength_tier: sig.strength.tier(),
                            evidence: format!("body:{} on baseline", sig.display),
                        });
                    }
                    continue;
                }
                // Delta match: present under attack, absent when clean.
                if baseline_hit(&sig.matcher) {
                    continue;
                }
                for probe in triggered {
                    if sig.matcher.matches(&probe.response.body) {
                        out.push(Match {
                            vendor: vendor.vendor.clone(),
                            detector: self.name(),
                            strength: sig.strength.weight(),
                            strength_tier: sig.strength.tier(),
                            evidence: format!(
                                "body:{} on trigger '{}'",
                                sig.display, probe.trigger
                            ),
                        });
                        break;
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
    fn delta_match_fires_on_block_page() {
        let pack = builtin_pack().unwrap();
        let d = BodyDetector::new(&pack);
        let base = resp(200, &[], "<html>welcome</html>");
        let trig = vec![probe(
            "xss_tag",
            403,
            &[],
            "<html>Attention Required! | Cloudflare</html>",
        )];
        let m = d.analyze(&base, &trig);
        assert!(m.iter().any(|x| x.vendor == "Cloudflare"));
        assert!(m[0].evidence.contains("trigger"));
    }

    #[test]
    fn pattern_in_baseline_is_not_evidence() {
        // False-positive control: a site whose normal page happens to contain
        // the block-page text must not trip the detector.
        let pack = builtin_pack().unwrap();
        let d = BodyDetector::new(&pack);
        let base = resp(200, &[], "Attention Required! | Cloudflare");
        assert!(d.analyze(&base, &[]).is_empty());
        let trig = vec![probe("xss_tag", 200, &[], "same text again")];
        assert!(d.analyze(&base, &trig).is_empty());
    }

    #[test]
    fn always_signal_fires_on_baseline() {
        // Craft an always:true signal to simulate always-injected branding.
        let sig = VendorSig {
            vendor: "TestBrand".into(),
            category: None,
            headers: vec![],
            cookies: vec![],
            body: vec![crate::signatures::BodySig {
                matcher: BodyMatcher::Literal("powered by testwaf".into()),
                display: "\"powered by testwaf\"".into(),
                strength: crate::signatures::Strength::Medium,
                always: true,
            }],
            status: vec![],
        };
        let pack = [sig];
        let d = BodyDetector::new(&pack);
        let base = resp(200, &[], "<html>hello, powered by TestWAF today</html>");
        let m = d.analyze(&base, &[]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].vendor, "TestBrand");
    }
}

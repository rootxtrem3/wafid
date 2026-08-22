use super::Detector;
use crate::signatures::VendorSig;
use crate::{Match, ProbeResult, Response};

/// Flags anomalous HTTP statuses returned to attack payloads. A signal fires
/// only when a triggered response's status is one of the signature's codes
/// AND differs from the baseline status — an always-403 site is not evidence
/// of a WAF; a site that flips 200 → 403 under `UNION SELECT` is.
pub struct StatusCodeDetector<'a> {
    pack: &'a [VendorSig],
}

impl<'a> StatusCodeDetector<'a> {
    pub fn new(pack: &'a [VendorSig]) -> Self {
        Self { pack }
    }
}

impl Detector for StatusCodeDetector<'_> {
    fn name(&self) -> &'static str {
        "status"
    }

    fn analyze(&self, baseline: &Response, triggered: &[ProbeResult]) -> Vec<Match> {
        let mut out = Vec::new();
        for vendor in self.pack {
            for sig in &vendor.status {
                for probe in triggered {
                    if probe.response.status != baseline.status
                        && sig.codes.contains(&probe.response.status)
                    {
                        out.push(Match {
                            vendor: vendor.vendor.clone(),
                            detector: self.name(),
                            strength: sig.strength.weight(),
                            strength_tier: sig.strength.tier(),
                            evidence: format!(
                                "status:{} on trigger '{}' (baseline {})",
                                probe.response.status, probe.trigger, baseline.status
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
    fn anomalous_403_on_trigger_fires() {
        let pack = builtin_pack().unwrap();
        let d = StatusCodeDetector::new(&pack);
        let base = resp(200, &[], "ok");
        let trig = vec![
            probe("sqli_union", 403, &[], "forbidden"),
            probe("xss_tag", 403, &[], "forbidden"),
            probe("cmd_injection", 403, &[], "forbidden"),
        ];
        let m = d.analyze(&base, &trig);
        assert!(!m.is_empty());
        assert_eq!(m[0].detector, "status");
        assert!(m[0].evidence.contains("baseline 200"));
    }

    #[test]
    fn already_blocked_baseline_is_not_evidence() {
        let pack = builtin_pack().unwrap();
        let d = StatusCodeDetector::new(&pack);
        let base = resp(403, &[], "nope");
        let trig = vec![
            probe("xss_tag", 403, &[], "nope"),
            probe("sqli_classic", 403, &[], "nope"),
        ];
        assert!(d.analyze(&base, &trig).is_empty());
    }
}

use super::Detector;
use crate::{Match, ProbeResult, Response};

/// Latency-delta heuristic: WAFs inspecting malicious payloads often add
/// measurable delay relative to clean requests.
///
/// This is a *supporting* signal only — it can never create or confirm a
/// vendor match (the fingerprint engine uses it solely as a score bump and a
/// standalone `timing_anomaly` flag on the scan result).
///
/// Requirements before firing:
/// - at least [`MIN_SAMPLES`] triggered responses,
/// - median trigger latency exceeds both a ratio of the baseline latency and
///   an absolute floor (to avoid flagging slow-but-normal networks).
pub struct TimingDetector;

const MIN_SAMPLES: usize = 3;
/// Trigger latency must exceed this multiple of the baseline latency...
const RATIO_THRESHOLD: f64 = 2.0;
/// ...and this absolute margin in ms (filters jittery-but-fast networks).
const ABS_MARGIN_MS: f64 = 150.0;

impl Default for TimingDetector {
    fn default() -> Self {
        Self
    }
}

impl Detector for TimingDetector {
    fn name(&self) -> &'static str {
        "timing"
    }

    fn analyze(&self, baseline: &Response, triggered: &[ProbeResult]) -> Vec<Match> {
        if triggered.len() < MIN_SAMPLES || baseline.latency_ms <= 0.0 {
            return Vec::new();
        }

        let mut latencies: Vec<f64> = triggered.iter().map(|t| t.response.latency_ms).collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = latencies[latencies.len() / 2];

        let threshold =
            (baseline.latency_ms * RATIO_THRESHOLD).max(baseline.latency_ms + ABS_MARGIN_MS);
        if median > threshold {
            let strength = crate::signatures::Strength::Low;
            vec![Match {
                vendor: "*behavioral*".into(),
                detector: self.name(),
                strength: strength.weight(),
                strength_tier: strength.tier(),
                evidence: format!(
                    "timing:median trigger latency {:.0}ms vs baseline {:.0}ms",
                    median, baseline.latency_ms
                ),
            }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Response;
    use crate::detectors::ProbeResult;
    use crate::detectors::test_support::resp;
    use crate::fingerprint::TIMING_PSEUDO_VENDOR;

    fn probe_with_latency(name: &'static str, ms: f64) -> ProbeResult {
        ProbeResult {
            trigger: name,
            response: Response {
                url: "https://t.local/?wafid=x".into(),
                status: 200,
                headers: vec![],
                body: String::new(),
                latency_ms: ms,
            },
        }
    }

    #[test]
    fn significant_slowdown_flags_anomaly() {
        let base = resp(200, &[], "ok");
        let trig: Vec<_> = ["a", "b", "c", "d"]
            .iter()
            .map(|n| probe_with_latency(n, 500.0))
            .collect();
        let m = TimingDetector.analyze(&base, &trig);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].vendor, TIMING_PSEUDO_VENDOR);
    }

    #[test]
    fn fast_triggers_do_not_flag() {
        let base = resp(200, &[], "ok");
        let trig: Vec<_> = ["a", "b", "c", "d"]
            .iter()
            .map(|n| probe_with_latency(n, 12.0))
            .collect();
        assert!(TimingDetector.analyze(&base, &trig).is_empty());
    }

    #[test]
    fn too_few_samples_never_flags() {
        let base = resp(200, &[], "ok");
        let trig: Vec<_> = ["a", "b"]
            .iter()
            .map(|n| probe_with_latency(n, 900.0))
            .collect();
        assert!(TimingDetector.analyze(&base, &trig).is_empty());
    }

    #[test]
    fn small_absolute_delta_does_not_flag() {
        // ratio >2 but absolute margin below threshold (jittery fast network)
        let base = resp(200, &[], "ok");
        let trig: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|n| probe_with_latency(n, 25.0))
            .collect();
        assert!(TimingDetector.analyze(&base, &trig).is_empty());
    }
}

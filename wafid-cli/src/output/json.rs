use serde_json::json;
use wafid_core::ScanResult;

/// Stable JSON schema for downstream tooling.
///
/// Single-target scans emit the result object directly; multi-target scans
/// wrap them as `{"schema_version": 1, "results": [...]}`.
pub fn render(results: &[ScanResult]) -> String {
    let value = if results.len() == 1 {
        to_value(&results[0])
    } else {
        json!({
            "schema_version": SCHEMA_VERSION,
            "results": results.iter().map(to_value).collect::<Vec<_>>(),
        })
    };
    serde_json::to_string_pretty(&value).expect("serialization of ScanResult cannot fail") + "\n"
}

const SCHEMA_VERSION: u32 = 1;

fn to_value(r: &ScanResult) -> serde_json::Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "url": r.url,
        "scanned_at": r.scanned_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        "matches": r.matches.iter().map(|m| json!({
            "vendor": m.vendor,
            "category": m.category,
            "confidence": m.confidence.as_str(),
            "score": round2(m.score),
            "evidence": m.evidence,
        })).collect::<Vec<_>>(),
        "unknown": r.unknown,
        "timing_anomaly": r.timing_anomaly,
        "passive": r.passive,
        "errors": r.errors,
    })
}

fn round2(v: f32) -> f64 {
    (v as f64 * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use wafid_core::{Confidence, VendorMatch};

    fn match_cf() -> VendorMatch {
        VendorMatch {
            vendor: "Cloudflare".into(),
            category: Some("cdn_waf".into()),
            confidence: Confidence::Confirmed,
            score: 2.0,
            evidence: vec!["header:cf-ray exists".into(), "cookie:__cf matched".into()],
        }
    }

    fn result(url: &str, matches: Vec<VendorMatch>, errors: Vec<String>) -> ScanResult {
        let unknown = matches.is_empty();
        ScanResult {
            url: url.into(),
            scanned_at: chrono::Utc::now(),
            matches,
            unknown,
            timing_anomaly: false,
            passive: false,
            errors,
        }
    }

    #[test]
    fn single_target_emits_object_not_wrapper() {
        let out = render(&[result("https://a", vec![match_cf()], vec![])]);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("results").is_none(), "single target must not wrap");
        assert_eq!(v["matches"][0]["vendor"], "Cloudflare");
        assert_eq!(v["matches"][0]["confidence"], "confirmed");
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["unknown"], false);
    }

    #[test]
    fn multi_target_uses_results_wrapper() {
        let out = render(&[
            result("https://a", vec![match_cf()], vec![]),
            result("https://b", vec![], vec!["boom".into()]),
        ]);
        let v: Value = serde_json::from_str(&out).unwrap();
        let results = v["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["matches"][0]["vendor"], "Cloudflare");
        assert_eq!(results[1]["unknown"], true);
        assert_eq!(results[1]["errors"][0], "boom");
    }

    #[test]
    fn score_is_rounded_and_expected_fields_present() {
        let v: Value = serde_json::from_str(&render(&[result("https://a", vec![match_cf()], vec![])]))
            .unwrap();
        let m = &v["matches"][0];
        assert_eq!(m["score"], 2.0);
        assert!(m.get("evidence").is_some());
        assert!(m.get("category").is_some());
    }
}

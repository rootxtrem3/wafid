use crate::signatures::{Tier, VendorSig};
use crate::{Confidence, Match, VendorMatch};

/// Pseudo-vendor used by the TimingDetector; filtered out of results because
/// behavioral timing can never be attributed to a product.
pub const TIMING_PSEUDO_VENDOR: &str = "*behavioral*";

/// Score bump applied to every matched vendor when the behavioral timing
/// heuristic fires. Deliberately small: timing can reorder near-ties but can
/// never create or confirm a match on its own.
const TIMING_BONUS: f32 = 0.15;

fn is_high(m: &Match) -> bool {
    m.strength_tier == Tier::High
}

fn is_medium(m: &Match) -> bool {
    m.strength_tier == Tier::Medium
}

/// Aggregate raw detector matches into per-vendor verdicts with confidence
/// tiers and an ordered evidence trail.
///
/// Rules:
/// - `confirmed`: >=2 high-strength signals from *distinct* detectors agree
///   (e.g. Cloudflare's `cf-ray` header **and** its block page).
/// - `likely`: one high-strength signal, or >=2 medium signals.
/// - `possible`: anything else (single weak signal, timing-only support...).
pub fn aggregate(raw: Vec<Match>, pack: &[VendorSig], timing_anomaly: bool) -> Vec<VendorMatch> {
    // Group by vendor, preserving order of first appearance.
    let mut grouped: std::collections::BTreeMap<String, Vec<Match>> =
        std::collections::BTreeMap::new();
    for m in raw {
        if m.vendor == TIMING_PSEUDO_VENDOR {
            continue;
        }
        grouped.entry(m.vendor.clone()).or_default().push(m);
    }

    let mut out: Vec<VendorMatch> = grouped
        .into_iter()
        .map(|(vendor, matches)| {
            let category = pack
                .iter()
                .find(|v| v.vendor == vendor)
                .and_then(|v| v.category.clone());

            // Distinct detector kinds contributing a high-strength signal.
            let high_detectors: std::collections::HashSet<&str> = matches
                .iter()
                .filter(|m| is_high(m))
                .map(|m| m.detector)
                .collect();
            let medium_count = matches.iter().filter(|m| is_medium(m)).count();

            let confidence = if high_detectors.len() >= 2 {
                Confidence::Confirmed
            } else if !high_detectors.is_empty() || medium_count >= 2 {
                Confidence::Likely
            } else {
                Confidence::Possible
            };

            let mut score: f32 = matches.iter().map(|m| m.strength).sum();
            if timing_anomaly {
                score += TIMING_BONUS;
            }

            // Ordered, de-duplicated evidence trail.
            let mut evidence: Vec<String> = matches.iter().map(|m| m.evidence.clone()).collect();
            evidence.sort();
            evidence.dedup();

            VendorMatch {
                vendor,
                category,
                confidence,
                score,
                evidence,
            }
        })
        // A vendor whose ONLY evidence is an anomalous status code is dropped
        // at `possible` tier: dozens of products return 403/406, so such a
        // match attributes nothing and would drown real findings. Status
        // codes remain fully counted for vendors with other signals.
        .filter(|vm| {
            !(vm.confidence == Confidence::Possible
                && vm.evidence.iter().all(|e| e.starts_with("status:")))
        })
        .collect();

    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.vendor.cmp(&b.vendor))
    });
    out
}

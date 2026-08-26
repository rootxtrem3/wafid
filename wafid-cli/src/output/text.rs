use owo_colors::{OwoColorize, Stream};
use wafid_core::{Confidence, ScanResult, VendorMatch};

/// Human-readable, colorized report grouped by confidence tier.
pub fn render(results: &[ScanResult]) -> String {
    let mut out = String::new();
    for res in results {
        out.push_str(&res.url);
        out.push_str("\n\n");

        if res.passive {
            out.push_str("  (passive mode: no attack payloads were sent)\n");
        }

        if res.matches.is_empty() && res.errors.is_empty() {
            push_color(&mut out, "No WAF detected (unknown)", Style::Dim);
            out.push('\n');
        }

        for tier in [
            Confidence::Confirmed,
            Confidence::Likely,
            Confidence::Possible,
        ] {
            let group: Vec<&VendorMatch> = res
                .matches
                .iter()
                .filter(|m| m.confidence == tier)
                .collect();
            if group.is_empty() {
                continue;
            }
            let (label, tier_style) = match tier {
                Confidence::Confirmed => ("CONFIRMED", Style::BoldRed),
                Confidence::Likely => ("LIKELY", Style::Yellow),
                Confidence::Possible => ("POSSIBLE", Style::Cyan),
            };
            push_color(&mut out, &format!("  [{label}]"), tier_style);
            out.push('\n');

            let (vendor_style, evidence_style) = match tier {
                Confidence::Confirmed => (Style::Red, Style::Dim),
                Confidence::Likely => (Style::Yellow, Style::Dim),
                Confidence::Possible => (Style::Cyan, Style::Dim),
            };
            for m in group {
                push_color(&mut out, "    ", Style::Plain);
                push_color(&mut out, &m.vendor, vendor_style);
                out.push_str(&format!(
                    "  score {:.2}{}\n",
                    m.score,
                    match &m.category {
                        Some(c) => format!("  [{c}]"),
                        None => String::new(),
                    }
                ));
                for ev in &m.evidence {
                    push_color(&mut out, &format!("      - {ev}"), evidence_style);
                    out.push('\n');
                }
            }
        }

        if res.timing_anomaly {
            push_color(
                &mut out,
                "  ~ behavioral timing anomaly detected (supporting signal only)",
                Style::Dim,
            );
            out.push('\n');
        }

        if !res.errors.is_empty() {
            push_color(&mut out, "  errors:", Style::Yellow);
            out.push('\n');
            for e in &res.errors {
                out.push_str("    - ");
                out.push_str(e);
                out.push('\n');
            }
        }

        out.push('\n');
    }
    out
}

#[derive(Clone, Copy)]
enum Style {
    Red,
    Yellow,
    Cyan,
    Dim,
    BoldRed,
    Plain,
}

fn push_color(out: &mut String, s: &str, style: Style) {
    let painted = match style {
        Style::Red => s.if_supports_color(Stream::Stdout, |t| t.red()).to_string(),
        Style::Yellow => s
            .if_supports_color(Stream::Stdout, |t| t.yellow())
            .to_string(),
        Style::Cyan => s
            .if_supports_color(Stream::Stdout, |t| t.cyan())
            .to_string(),
        Style::Dim => s
            .if_supports_color(Stream::Stdout, |t| t.dimmed())
            .to_string(),
        Style::BoldRed => s
            .if_supports_color(Stream::Stdout, |t| t.red().bold().to_string())
            .to_string(),
        Style::Plain => s.to_string(),
    };
    out.push_str(&painted);
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafid_core::{Confidence, VendorMatch};

    fn match_v(vendor: &str, conf: Confidence) -> VendorMatch {
        VendorMatch {
            vendor: vendor.into(),
            category: Some("cdn_waf".into()),
            confidence: conf,
            score: 2.0,
            evidence: vec!["header:cf-ray exists".into()],
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
    fn groups_by_confidence_tier_and_lists_evidence() {
        let res = result(
            "https://a",
            vec![
                match_v("Cloudflare", Confidence::Confirmed),
                match_v("Akamai", Confidence::Possible),
            ],
            vec![],
        );
        let out = render(&[res]);
        assert!(out.contains("https://a"));
        assert!(out.contains("[CONFIRMED]"));
        assert!(out.contains("[POSSIBLE]"));
        assert!(out.contains("header:cf-ray exists"));
    }

    #[test]
    fn renders_stack_without_colors_when_unsupported() {
        // exact tier labels must be present regardless of color support
        let res = result(
            "https://a",
            vec![
                match_v("Imperva/Incapsula", Confidence::Confirmed),
                match_v("Cloudflare", Confidence::Likely),
            ],
            vec![],
        );
        let out = render(&[res]);
        assert!(out.contains("[CONFIRMED]"));
        assert!(out.contains("[LIKELY]"));
        assert!(out.contains("Imperva/Incapsula"));
        assert!(out.contains("Cloudflare"));
    }

    #[test]
    fn reports_unknown_errors_and_timing() {
        // unknown + error
        let mut res = result("https://a", vec![], vec!["trigger 'x': boom".into()]);
        res.timing_anomaly = true;
        let out = render(&[res]);
        assert!(out.contains("timing anomaly"));
        assert!(out.contains("trigger 'x': boom"));

        // unknown with no errors -> explicit "no WAF detected"
        let out2 = render(&[result("https://b", vec![], vec![])]);
        assert!(out2.contains("No WAF detected (unknown)"));
    }
}

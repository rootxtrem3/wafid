use wafid_core::ScanResult;

/// One row per target: the flattened top match, plus a summary of any
/// additional vendors detected (stacked WAF/CDN chains).
pub fn render(results: &[ScanResult]) -> String {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    let _ = wtr.write_record([
        "target",
        "vendor",
        "category",
        "confidence",
        "score",
        "evidence",
        "additional_vendors",
        "unknown",
        "timing_anomaly",
        "errors",
    ]);

    for res in results {
        let errors = res.errors.join("; ");
        let evidence = res
            .top_match()
            .map(|m| m.evidence.join("; "))
            .unwrap_or_default();
        let additional = res
            .matches
            .iter()
            .skip(1)
            .map(|m| format!("{}({})", m.vendor, m.confidence.as_str()))
            .collect::<Vec<_>>()
            .join("; ");

        match res.top_match() {
            Some(top) => {
                let _ = wtr.write_record([
                    &res.url,
                    &top.vendor,
                    top.category.as_deref().unwrap_or(""),
                    top.confidence.as_str(),
                    &format!("{:.2}", top.score),
                    &evidence,
                    &additional,
                    &res.unknown.to_string(),
                    &res.timing_anomaly.to_string(),
                    &errors,
                ]);
            }
            None => {
                let _ = wtr.write_record([
                    &res.url,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    &res.unknown.to_string(),
                    &res.timing_anomaly.to_string(),
                    &errors,
                ]);
            }
        }
    }

    let mut buf = Vec::new();
    if wtr.flush().is_ok() {
        buf = wtr.into_inner().unwrap_or_default();
    }
    String::from_utf8_lossy(&buf).into_owned()
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
            score: 1.5,
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

    fn rows(out: &str) -> Vec<Vec<String>> {
        // has_headers(false): the header row is part of the output and must be
        // asserted explicitly, not silently skipped.
        let mut rd = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(out.as_bytes());
        rd.records()
            .map(|r| r.unwrap().iter().map(str::to_string).collect())
            .collect()
    }

    #[test]
    fn header_row_and_one_row_per_target() {
        let out = render(&[
            result("https://a", vec![match_v("Cloudflare", Confidence::Confirmed)], vec![]),
            result("https://b", vec![], vec![]),
        ]);
        let rows = rows(&out);
        assert_eq!(rows.len(), 3, "header + 2 targets");
        assert_eq!(rows[0][0], "target");
        assert_eq!(rows[1][0], "https://a");
        assert_eq!(rows[1][1], "Cloudflare");
        assert_eq!(rows[1][3], "confirmed");
        assert_eq!(rows[2][1], "", "no-match target has blank vendor");
    }

    #[test]
    fn additional_vendors_column_lists_stacked_wafs() {
        let mut res = result(
            "https://a",
            vec![
                match_v("Imperva/Incapsula", Confidence::Confirmed),
                match_v("Cloudflare", Confidence::Likely),
            ],
            vec![],
        );
        res.timing_anomaly = true;
        let rows = rows(&render(&[res]));
        let row = &rows[1];
        assert!(
            row[6].contains("Cloudflare(likely)"),
            "stacked vendor missing: {:?}",
            row[6]
        );
        assert_eq!(row[8], "true", "timing_anomaly column");
    }

    #[test]
    fn errors_column_joins_multiple_errors() {
        let res = result(
            "https://a",
            vec![],
            vec!["trigger 'x': boom".into(), "timeout".into()],
        );
        let rows = rows(&render(&[res]));
        assert_eq!(rows[1][9], "trigger 'x': boom; timeout");
    }
}

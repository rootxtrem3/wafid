//! Golden-file tests: per-vendor response samples mapped to the expected
//! confidence tier. Fixtures live in `tests/fixtures/*.yaml`; each one runs
//! through the *full* pipeline (all detectors + fingerprint aggregation), so
//! these double as regression guards for signature-pack edits.

use serde::Deserialize;
use wafid_core::detectors::{
    BodyDetector, CookieDetector, Detector, HeaderDetector, StatusCodeDetector,
};
use wafid_core::signatures::builtin_pack;
use wafid_core::{Confidence, Match, ProbeResult, Response};

#[derive(Debug, Deserialize)]
struct Fixture {
    vendor: String,
    expect_confidence: Confidence,
    baseline: FixtureResponse,
    #[serde(default)]
    triggered: Vec<FixtureProbe>,
}

#[derive(Debug, Deserialize)]
struct FixtureResponse {
    status: u16,
    latency_ms: f64,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    body: String,
}

#[derive(Debug, Deserialize)]
struct FixtureProbe {
    trigger: String,
    #[serde(flatten)]
    response: FixtureResponse,
}

impl From<&FixtureResponse> for Response {
    fn from(f: &FixtureResponse) -> Self {
        Response {
            url: "https://fixture.invalid/".into(),
            status: f.status,
            headers: f
                .headers
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
                .collect(),
            body: f.body.clone(),
            latency_ms: f.latency_ms,
        }
    }
}

fn run_pipeline(fixture: &Fixture) -> Vec<wafid_core::VendorMatch> {
    let pack = builtin_pack().expect("builtin pack must load");
    let baseline: Response = (&fixture.baseline).into();
    let triggered: Vec<ProbeResult> = fixture
        .triggered
        .iter()
        .map(|p| ProbeResult {
            trigger: leak(p.trigger.as_str()),
            response: (&p.response).into(),
        })
        .collect();

    let mut raw: Vec<Match> = Vec::new();
    for d in [
        &HeaderDetector::new(&pack) as &dyn Detector,
        &CookieDetector::new(&pack),
        &BodyDetector::new(&pack),
        &StatusCodeDetector::new(&pack),
    ] {
        raw.extend(d.analyze(&baseline, &triggered));
    }

    // Timing intentionally excluded from golden tests: fixtures carry static
    // latencies that don't model real behavioral deltas.
    wafid_core::fingerprint::aggregate(raw, &pack, false)
}

// Fixture probe names are 'static in practice (they come from triggers.rs);
// leaking a few bytes inside tests is fine and keeps ProbeResult's shape.
fn leak(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

#[test]
fn all_builtin_vendors_have_golden_fixtures() {
    let pack = builtin_pack().unwrap();
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));

    // Match vendors via each fixture's declared `vendor` field, not filenames.
    let mut covered = std::collections::HashSet::new();
    for entry in std::fs::read_dir(&dir).expect("fixtures dir exists") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("fixture readable");
        #[derive(serde::Deserialize)]
        struct VendorOnly {
            vendor: String,
        }
        if let Ok(v) = serde_yaml::from_str::<VendorOnly>(&text) {
            covered.insert(v.vendor);
        }
    }

    let missing: Vec<&str> = pack
        .iter()
        .map(|v| v.vendor.as_str())
        .filter(|name| !covered.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "vendors without golden fixtures: {missing:?}"
    );
}

fn check_fixture(name: &str) {
    let path = format!("{}/tests/fixtures/{name}.yaml", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("fixture readable");
    let fixture: Fixture =
        serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("bad fixture {name}: {e}"));

    let matches = run_pipeline(&fixture);
    let top = matches
        .first()
        .unwrap_or_else(|| panic!("{name}: expected at least one match"));

    assert_eq!(
        top.vendor, fixture.vendor,
        "{name}: wrong top vendor (stacked or misattributed)"
    );
    assert_eq!(
        top.confidence, fixture.expect_confidence,
        "{name}: confidence mismatch; evidence was {:?}",
        top.evidence
    );
}

macro_rules! golden {
    ($($name:ident => $file:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                check_fixture($file);
            }
        )*
    };
}

golden! {
    cloudflare => "cloudflare";
    cloudflare_headers_only => "cloudflare_headers_only";
    imperva => "imperva";
    aws_waf => "aws_waf";
    akamai => "akamai";
    sucuri => "sucuri";
    f5_bigip => "f5";
    modsecurity => "modsecurity";
    barracuda => "barracuda";
    fortiweb => "fortiweb";
    azure_frontdoor => "azure_front_door";
}

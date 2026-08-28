//! End-to-end pipeline tests against locally simulated WAFs (wiremock).

use std::time::Duration;

use wafid_core::http_client::ClientConfig;
use wafid_core::{Confidence, EngineBuilder};
use wiremock::matchers::method;
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

/// Matches any request whose URL carries one of our probe payloads.
struct AttackProbe;

impl Match for AttackProbe {
    fn matches(&self, req: &Request) -> bool {
        let url = percent_decode(req.url.as_ref()).to_lowercase();
        [
            "<script",
            "' or '1",
            "union select",
            "etc/passwd",
            "cat /etc/passwd",
            "jndi",
        ]
        .iter()
        .any(|needle| url.contains(needle))
    }
}

/// Minimal percent-decoder so payload needles can be written in plain text.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(hex);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn fast_client() -> ClientConfig {
    ClientConfig {
        timeout_secs: 5,
        retries: 0,
        ..Default::default()
    }
}

fn no_timing(mut cfg: ClientConfig) -> ClientConfig {
    cfg.timeout_secs = 5;
    cfg.retries = 0;
    cfg
}

async fn cloudflare_server() -> MockServer {
    let server = MockServer::start().await;

    // Block pages for attack probes (mounted first => lower priority than
    // nothing; wiremock prefers the MOST RECENTLY mounted matching mock, so
    // the catch-all below is mounted second and only catches leftovers).
    let blocked = ResponseTemplate::new(403)
        .insert_header("Server", "cloudflare")
        .insert_header("CF-Ray", "blocked0000000")
        .set_body_string(
            "<html><title>Attention Required! | Cloudflare</title>\
             Sorry, you have been blocked.</html>",
        );
    Mock::given(method("GET"))
        .and(AttackProbe)
        .respond_with(blocked)
        .mount(&server)
        .await;

    let clean = ResponseTemplate::new(200)
        .insert_header("Server", "cloudflare")
        .insert_header("CF-Ray", "8aabbccddeeff001")
        .insert_header("Set-Cookie", "__cf_bm=abc123; Path=/")
        .set_body_string("<html>welcome</html>");
    Mock::given(method("GET"))
        .respond_with(clean)
        .mount(&server)
        .await;

    server
}

#[tokio::test]
async fn detects_cloudflare_as_confirmed() {
    let server = cloudflare_server().await;
    let engine = EngineBuilder::new()
        .client_config(no_timing(fast_client()))
        .build()
        .unwrap();

    let res = engine.scan(server.uri().as_str()).await;
    assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
    let top = res.top_match().expect("should detect Cloudflare");
    assert_eq!(top.vendor, "Cloudflare");
    assert_eq!(top.confidence, Confidence::Confirmed);

    // Evidence from >=2 distinct detector kinds.
    let detectors: Vec<&str> = top
        .evidence
        .iter()
        .map(|e| e.split(':').next().unwrap())
        .collect();
    assert!(detectors.contains(&"header"));
    assert!(detectors.contains(&"body"));
}

#[tokio::test]
async fn reports_stacked_wafs() {
    let server = MockServer::start().await;
    let blocked = ResponseTemplate::new(403)
        .insert_header("X-Iinfo", "5-12345-12345 NNNN")
        .set_body_string("<html>Request unsuccessful. Incapsula incident ID.</html>");
    Mock::given(method("GET"))
        .and(AttackProbe)
        .respond_with(blocked)
        .mount(&server)
        .await;

    let clean = ResponseTemplate::new(200)
        .insert_header("Server", "cloudflare")
        .insert_header("CF-Ray", "front000000000001")
        .insert_header("X-Iinfo", "5-12345-12345 NNNN")
        .insert_header("Set-Cookie", "incap_ses_999=xxyy; Path=/")
        .set_body_string("<html>origin content</html>");
    Mock::given(method("GET"))
        .respond_with(clean)
        .mount(&server)
        .await;

    let engine = EngineBuilder::new()
        .client_config(no_timing(fast_client()))
        .build()
        .unwrap();
    let res = engine.scan(server.uri().as_str()).await;

    eprintln!("STACKED MATCHES: {:?}", res.matches);
    assert_eq!(res.matches.len(), 2, "both layers should be reported");
    assert_eq!(res.matches[0].vendor, "Imperva/Incapsula");
    assert_eq!(res.matches[0].confidence, Confidence::Confirmed);
    assert_eq!(res.matches[1].vendor, "Cloudflare");
    assert_eq!(res.matches[1].confidence, Confidence::Likely);
}

#[tokio::test]
async fn clean_site_is_unknown_without_errors() {
    let server = MockServer::start().await;
    let clean = ResponseTemplate::new(200)
        .insert_header("Server", "nginx/1.24")
        .set_body_string("<html>plain static site</html>");
    Mock::given(method("GET"))
        .respond_with(clean)
        .mount(&server)
        .await;

    let engine = EngineBuilder::new()
        .client_config(no_timing(fast_client()))
        .build()
        .unwrap();
    let res = engine.scan(server.uri().as_str()).await;

    assert!(res.unknown);
    assert!(res.matches.is_empty());
    assert!(res.errors.is_empty());
    assert!(!res.timing_anomaly);
}

#[tokio::test]
async fn passive_mode_never_sends_payloads_but_still_detects() {
    let server = MockServer::start().await;
    let branded = ResponseTemplate::new(200)
        .insert_header("X-Sucuri-ID", "11009")
        .insert_header("Server", "Sucuri/Cloudproxy")
        .set_body_string("<html>blog</html>");
    Mock::given(method("GET"))
        .respond_with(branded)
        .expect(1)
        .mount(&server)
        .await;

    let engine = EngineBuilder::new()
        .client_config(no_timing(fast_client()))
        .passive(true)
        .build()
        .unwrap();
    let res = engine.scan(server.uri().as_str()).await;

    // Exactly one request ever hit the server: the baseline.
    server.verify().await;

    let top = res
        .top_match()
        .expect("persistent signals should detect Sucuri");
    assert_eq!(top.vendor, "Sucuri");
    assert!(res.passive);
}

#[tokio::test]
async fn batch_preserves_order_and_isolates_failures() {
    let ok_server = cloudflare_server().await;

    // A target on a closed port: connection refused, fails fast.
    let dead_target = "http://127.0.0.1:9/";

    // An HTTP 500-only server: valid responses, no WAF signals.
    let erring = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&erring)
        .await;

    let engine = EngineBuilder::new()
        .client_config(no_timing(fast_client()))
        .build()
        .unwrap();

    let targets = vec![
        ok_server.uri(),
        erring.uri(),
        dead_target.to_string(),
        ok_server.uri(), // duplicate target: same result expected twice
    ];
    let results = engine.scan_batch(targets, 4, None).await;

    assert_eq!(results.len(), 4);
    assert_eq!(results[0].top_match().unwrap().vendor, "Cloudflare");
    assert!(results[1].unknown && results[1].errors.is_empty());
    assert!(!results[2].errors.is_empty(), "dead target records errors");
    assert_eq!(results[3].url, results[0].url, "input order preserved");
}

#[tokio::test]
async fn timing_detector_flags_slow_inspection() {
    let server = MockServer::start().await;

    let slow_block = ResponseTemplate::new(403)
        .set_delay(Duration::from_millis(900))
        .set_body_string("<html>generic block</html>");
    Mock::given(method("GET"))
        .and(AttackProbe)
        .respond_with(slow_block)
        .mount(&server)
        .await;

    let fast_clean = ResponseTemplate::new(200).set_body_string("<html>hi</html>");
    Mock::given(method("GET"))
        .respond_with(fast_clean)
        .mount(&server)
        .await;

    // Warm up connection/mock machinery so the baseline latency isn't
    // dominated by cold-start noise.
    let url = wafid_core::normalize_target(server.uri().as_str()).unwrap();
    let warm = wafid_core::http_client::HttpClient::build(no_timing(fast_client())).unwrap();
    warm.fetch(&url, &[]).await.expect("warmup request");

    let engine = EngineBuilder::new()
        .client_config(no_timing(fast_client()))
        .timing(true)
        .build()
        .unwrap();
    let res = engine.scan(server.uri().as_str()).await;
    eprintln!(
        "TIMING DEBUG: anomaly={} errors={:?}",
        res.timing_anomaly, res.errors
    );
    assert!(res.timing_anomaly, "delayed triggers should flag timing");

    let engine_off = EngineBuilder::new()
        .client_config(no_timing(fast_client()))
        .timing(false)
        .build()
        .unwrap();
    let res_off = engine_off.scan(server.uri().as_str()).await;
    assert!(!res_off.timing_anomaly);
}

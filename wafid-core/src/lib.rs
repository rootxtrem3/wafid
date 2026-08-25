pub mod detectors;
pub mod error;
pub mod fingerprint;
pub mod http_client;
pub mod signatures;
pub mod triggers;

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{debug, warn};

use crate::detectors::{
    BodyDetector, CookieDetector, Detector, HeaderDetector, StatusCodeDetector, TimingDetector,
};
use crate::error::{Result, WafidError};
use crate::http_client::{ClientConfig, HttpClient};
use crate::signatures::VendorSig;
/// Re-export for downstream users implementing custom detectors.
pub use detectors::ProbeResult;

/// Confidence tiers for a vendor match, from strongest to weakest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Confirmed,
    Likely,
    Possible,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Likely => "likely",
            Confidence::Possible => "possible",
        }
    }
}

/// A single raw signal match emitted by a detector.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Match {
    pub vendor: String,
    pub detector: &'static str,
    /// Numeric weight for scoring / JSON output.
    pub strength: f32,
    /// The underlying strength bucket, used by the fingerprint engine to
    /// classify confidence without re-deriving tiers from floats. Internal
    /// only; not part of the serialized match (numeric `strength` is).
    #[serde(skip)]
    pub strength_tier: crate::signatures::Tier,
    pub evidence: String,
}

/// An aggregated verdict for a single vendor.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VendorMatch {
    pub vendor: String,
    pub category: Option<String>,
    pub confidence: Confidence,
    pub score: f32,
    /// Human-readable evidence trail, formatted as `detector: detail`.
    pub evidence: Vec<String>,
}

/// Cap applied to response bodies kept in memory.
pub const BODY_CAP_BYTES: usize = 64 * 1024;

/// Normalized HTTP response handed to detectors. Detectors only ever see this
/// struct, which makes them trivially unit-testable without a network.
#[derive(Debug, Clone)]
pub struct Response {
    pub url: String,
    pub status: u16,
    /// Header names are lowercased; duplicates (e.g. multiple Set-Cookie) preserved.
    pub headers: Vec<(String, String)>,
    /// Response body, capped at [`BODY_CAP_BYTES`].
    pub body: String,
    /// Measured round-trip time in milliseconds.
    pub latency_ms: f64,
}

impl Response {
    pub fn header_all(&self, name: &str) -> impl Iterator<Item = &str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(move |(k, _)| *k == lower)
            .map(|(_, v)| v.as_str())
    }

    pub fn header_first(&self, name: &str) -> Option<&str> {
        self.header_all(name).next()
    }

    /// Cookie names extracted from all Set-Cookie headers.
    pub fn cookie_names(&self) -> Vec<&str> {
        let mut names = Vec::new();
        for v in self.header_all("set-cookie") {
            if let Some(end) = v.find('=') {
                let name = v[..end].trim();
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
        names
    }

    /// Test helper for constructing responses without a network.
    #[cfg(test)]
    pub(crate) fn synthetic(status: u16, headers: &[(&str, &str)], body: &str) -> Self {
        Response {
            url: "https://test.local/".into(),
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
                .collect(),
            body: body.into(),
            latency_ms: 10.0,
        }
    }
}

/// Result of scanning one target. Never panics; failures degrade to
/// `unknown = true` with entries in `errors`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    pub url: String,
    pub scanned_at: chrono::DateTime<Utc>,
    /// All vendors detected, sorted by score descending.
    pub matches: Vec<VendorMatch>,
    /// True when no signal fired at all.
    pub unknown: bool,
    /// True when triggered requests were consistently slower than baseline
    /// beyond the timing threshold (supporting signal only).
    pub timing_anomaly: bool,
    pub passive: bool,
    pub errors: Vec<String>,
}

impl ScanResult {
    pub fn top_match(&self) -> Option<&VendorMatch> {
        self.matches.first()
    }

    fn failed(url: String, passive: bool, errors: Vec<String>) -> Self {
        ScanResult {
            url,
            scanned_at: Utc::now(),
            matches: Vec::new(),
            unknown: true,
            timing_anomaly: false,
            passive,
            errors,
        }
    }
}

/// Builder-style configuration for the engine.
#[derive(Debug, Clone)]
pub struct EngineBuilder {
    client: ClientConfig,
    timing_enabled: bool,
    passive: bool,
    extra_signatures: Option<std::path::PathBuf>,
    disable_builtin_signatures: bool,
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self {
            client: ClientConfig::default(),
            timing_enabled: true,
            passive: false,
            extra_signatures: None,
            disable_builtin_signatures: false,
        }
    }
}

impl EngineBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn client_config(mut self, cfg: ClientConfig) -> Self {
        self.client = cfg;
        self
    }

    pub fn timing(mut self, enabled: bool) -> Self {
        self.timing_enabled = enabled;
        self
    }

    pub fn passive(mut self, enabled: bool) -> Self {
        self.passive = enabled;
        self
    }

    /// Load an additional signature pack on top of the builtin one.
    /// Vendors present in the custom pack override builtin definitions of the
    /// same name.
    pub fn signatures(mut self, path: std::path::PathBuf) -> Self {
        self.extra_signatures = Some(path);
        self
    }

    /// Skip the builtin pack entirely (only meaningful together with `signatures`).
    pub fn no_builtin_signatures(mut self) -> Self {
        self.disable_builtin_signatures = true;
        self
    }

    pub fn build(self) -> Result<Engine> {
        let mut pack = if self.disable_builtin_signatures {
            Vec::new()
        } else {
            signatures::builtin_pack()?
        };
        if let Some(path) = &self.extra_signatures {
            let overlay = signatures::load_pack(path)?;
            pack = signatures::merge_packs(pack, overlay);
        }
        signatures::check_pack(&pack)?;
        // Global per-target deadline: worst case is baseline + N triggers,
        // each taking up to timeout * (retries + 1), plus backoff slack.
        let global_timeout =
            Duration::from_secs(self.client.timeout_secs * u64::from(self.client.retries + 2) + 10)
                .max(Duration::from_secs(15));
        let http = Arc::new(HttpClient::build(self.client.clone())?);
        Ok(Engine {
            pack: Arc::new(pack),
            http,
            timing_enabled: self.timing_enabled,
            passive: self.passive,
            global_timeout,
        })
    }
}

/// The detection engine. Cheap to clone (all fields are `Arc`); share across
/// tasks.
#[derive(Clone)]
pub struct Engine {
    pack: Arc<Vec<VendorSig>>,
    http: Arc<HttpClient>,
    timing_enabled: bool,
    passive: bool,
    global_timeout: Duration,
}

/// Progress callback invoked as each batch target completes:
/// `(index_into_input, result)`.
pub type ProgressFn = Arc<dyn Fn(usize, &ScanResult) + Send + Sync>;

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::new()
    }

    pub fn passive(&self) -> bool {
        self.passive
    }

    pub fn signature_count(&self) -> usize {
        self.pack.len()
    }

    /// Scan a single target. This never returns an error: any failure is
    /// captured inside the returned `ScanResult`, keeping batch scans isolated
    /// per target.
    pub async fn scan(&self, target: &str) -> ScanResult {
        match tokio::time::timeout(self.global_timeout, self.scan_inner(target)).await {
            Ok(res) => res,
            Err(_) => {
                let url = normalize_target(target)
                    .map(|u| u.to_string())
                    .unwrap_or_else(|_| target.to_string());
                ScanResult::failed(
                    url,
                    self.passive,
                    vec![format!(
                        "target exceeded global scan timeout of {}s",
                        self.global_timeout.as_secs()
                    )],
                )
            }
        }
    }

    async fn scan_inner(&self, target: &str) -> ScanResult {
        let mut errors = Vec::new();
        let url = match normalize_target(target) {
            Ok(u) => u,
            Err(e) => {
                return ScanResult::failed(target.to_string(), self.passive, vec![e.to_string()]);
            }
        };

        debug!(url = %url, "fetching baseline");
        let baseline = match self.http.fetch(&url, &[]).await {
            Ok(r) => r,
            Err(e) => {
                return ScanResult::failed(url.to_string(), self.passive, vec![e.to_string()]);
            }
        };

        // Robust baseline latency: the TimingDetector compares trigger latency
        // against a single baseline sample today; sample a couple more when
        // timing is on and active so a jittery baseline can't skew the verdict.
        // Skipped in passive mode (no trigger battery → no timing comparison) to
        // avoid wasting extra requests. The first response still owns the
        // headers/body/status the other detectors see.
        let baseline = if self.timing_enabled && !self.passive {
            let mut latencies = vec![baseline.latency_ms];
            for _ in 0..2 {
                match self.http.fetch(&url, &[]).await {
                    Ok(extra) => latencies.push(extra.latency_ms),
                    Err(e) => {
                        warn!(url = %url, error = %e, "extra baseline sample failed");
                    }
                }
            }
            latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            Response {
                latency_ms: latencies[latencies.len() / 2],
                ..baseline
            }
        } else {
            baseline
        };

        // Fire the trigger battery sequentially per target so latency
        // measurements stay clean and we don't hammer one host with parallel
        // attack strings. Cross-target parallelism is handled by scan_batch.
        let mut triggered: Vec<ProbeResult> = Vec::new();
        if !self.passive {
            for probe in triggers::build_requests(&url) {
                let triggers::ProbeTarget::Get { url, headers } = probe.target;
                debug!(url = %url, trigger = probe.trigger, "sending trigger");
                match self.http.fetch(&url, &headers).await {
                    Ok(resp) => triggered.push(ProbeResult {
                        trigger: probe.trigger,
                        response: resp,
                    }),
                    Err(e) => {
                        warn!(url = %url, error = %e, "trigger request failed");
                        errors.push(format!("trigger '{}': {}", sanitize_url(&url), e));
                    }
                }
            }
        }

        let mut raw: Vec<Match> = Vec::new();
        for d in [
            &HeaderDetector::new(&self.pack) as &dyn Detector,
            &CookieDetector::new(&self.pack),
            &BodyDetector::new(&self.pack),
            &StatusCodeDetector::new(&self.pack),
        ] {
            raw.extend(d.analyze(&baseline, &triggered));
        }

        let timing_anomaly =
            self.timing_enabled && !TimingDetector.analyze(&baseline, &triggered).is_empty();
        let matches = fingerprint::aggregate(raw, &self.pack, timing_anomaly);
        let unknown = matches.is_empty();
        ScanResult {
            url: url.to_string(),
            scanned_at: Utc::now(),
            matches,
            unknown,
            timing_anomaly,
            passive: self.passive,
            errors,
        }
    }

    /// Scan many targets with bounded concurrency. Per-target isolation: a
    /// failing target yields a `ScanResult` with errors populated, never a
    /// failed task. Results preserve input order.
    pub async fn scan_batch(
        &self,
        targets: Vec<String>,
        concurrency: usize,
        progress: Option<ProgressFn>,
    ) -> Vec<ScanResult> {
        let concurrency = concurrency.max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut set = tokio::task::JoinSet::new();

        for (idx, target) in targets.into_iter().enumerate() {
            let sem = semaphore.clone();
            let progress = progress.clone();
            let engine = self.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await;
                let res = engine.scan(&target).await;
                if let Some(p) = progress {
                    // A panicking progress callback must never drop the target's
                    // result or abort the batch task; swallow the panic and keep
                    // going.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        p(idx, &res);
                    }));
                }
                (idx, res)
            });
        }

        let mut out: Vec<(usize, ScanResult)> = Vec::with_capacity(set.len());
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((idx, res)) => out.push((idx, res)),
                Err(e) => {
                    // Defensive: scan() itself must not panic, but a panic in
                    // a task must never take the batch down.
                    warn!(error = %e, "batch task panicked");
                }
            }
        }
        out.sort_by_key(|(idx, _)| *idx);
        out.into_iter().map(|(_, r)| r).collect()
    }
}

/// Strip query/fragment from a URL before embedding it in an error string, so
/// payloads don't leak into logs.
fn sanitize_url(u: &url::Url) -> String {
    let mut cleaned = u.clone();
    cleaned.set_query(None);
    cleaned.set_fragment(None);
    cleaned.to_string()
}

/// Normalize user-supplied targets: add a scheme when missing and require
/// http/https.
pub fn normalize_target(target: &str) -> Result<url::Url> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(WafidError::InvalidUrl {
            target: target.to_string(),
            reason: "empty".into(),
        });
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = url::Url::parse(&candidate).map_err(|e| WafidError::InvalidUrl {
        target: target.to_string(),
        reason: e.to_string(),
    })?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        other => Err(WafidError::InvalidUrl {
            target: target.to_string(),
            reason: format!("unsupported scheme '{other}'"),
        }),
    }
}

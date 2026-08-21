use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::Rng;
use tracing::{debug, warn};

use crate::Response;
use crate::error::{Result, WafidError};

/// Common browser user agents for `--random-ua`.
pub const RANDOM_USER_AGENTS: [&str; 8] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
];

const DEFAULT_UA: &str = concat!("wafid/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    pub user_agent: Option<String>,
    pub random_user_agent: bool,
    pub proxy: Option<String>,
    /// Retries per request *in addition to* the initial attempt.
    pub retries: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            user_agent: None,
            random_user_agent: false,
            proxy: None,
            retries: 2,
        }
    }
}

/// How long a host's 429 penalty is remembered before it decays back to the
/// normal backoff. Prevents one rate-limited host from slowing the whole batch
/// forever while still keeping us gentle with that host.
const RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(30);

/// Thin async wrapper over reqwest implementing retries with exponential
/// backoff, latency measurement and capped body reads.
#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    cfg: ClientConfig,
    ua: String,
    /// Tracks 429s per host (URL authority) so only a rate-limited target backs
    /// off harder, and the penalty decays after [`RATE_LIMIT_COOLDOWN`].
    rate_limited_hosts: Arc<Mutex<HashMap<String, Instant>>>,
}

/// Extract the authority (host[:port]) a URL belongs to; used to key per-host
/// rate-limit state so one target's 429s don't punish the whole batch.
fn authority_of(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    let auth = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Some(auth)
}

impl HttpClient {
    pub fn build(cfg: ClientConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs.max(1)))
            .connect_timeout(Duration::from_secs(10))
            // WAFs commonly redirect block traffic; follow them.
            .redirect(reqwest::redirect::Policy::limited(10));

        let ua = if let Some(ua) = &cfg.user_agent {
            ua.clone()
        } else if cfg.random_user_agent {
            let idx = rand::rng().random_range(0..RANDOM_USER_AGENTS.len());
            RANDOM_USER_AGENTS[idx].to_string()
        } else {
            DEFAULT_UA.to_string()
        };
        builder = builder.user_agent(&ua);

        if let Some(proxy) = &cfg.proxy {
            let p = reqwest::Proxy::all(proxy)
                .map_err(|e| WafidError::HttpConfig(format!("invalid proxy '{proxy}': {e}")))?;
            builder = builder.proxy(p);
        }

        let inner = builder
            .build()
            .map_err(|e| WafidError::HttpConfig(e.to_string()))?;
        Ok(Self {
            inner,
            cfg,
            ua,
            rate_limited_hosts: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn user_agent(&self) -> &str {
        &self.ua
    }

    /// Whether `authority` is currently under a 429 penalty that has not yet
    /// decayed. Also prunes any *other* expired entries opportunistically.
    fn is_rate_limited(&self, authority: &str) -> bool {
        let mut hosts = self.rate_limited_hosts.lock().unwrap();
        let now = Instant::now();
        hosts.retain(|_, at| now.duration_since(*at) < RATE_LIMIT_COOLDOWN);
        hosts.contains_key(authority)
    }

    fn mark_rate_limited(&self, authority: &str) {
        self.rate_limited_hosts
            .lock()
            .unwrap()
            .insert(authority.to_string(), Instant::now());
    }

    fn backoff_ms(&self, attempt: u32, authority: Option<&str>) -> u64 {
        let base = if authority.map(|a| self.is_rate_limited(a)).unwrap_or(false) {
            1500
        } else {
            400
        };
        let growth = base * (1u64 << attempt.min(4)) / 2;
        let jitter = rand::rng().random_range(0..=growth / 4).max(50);
        growth + jitter
    }

    /// GET `url` with retries + exponential backoff on network errors and
    /// 429s. Other HTTP statuses are returned as-is (a 403/503 block page is
    /// a signal, not a failure).
    pub async fn fetch(
        &self,
        url: &url::Url,
        extra_headers: &[(String, String)],
    ) -> Result<Response> {
        let attempts = self.cfg.retries + 1;
        let mut last_err: Option<reqwest::Error> = None;
        let authority = authority_of(url);

        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(
                    self.backoff_ms(attempt, authority.as_deref()),
                ))
                .await;
            }

            let mut req = self.inner.get(url.clone());
            for (k, v) in extra_headers {
                req = req.header(k.as_str(), v.as_str());
            }

            let start = Instant::now();
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // Retry 429s with a longer backoff; if we exhaust
                    // attempts, return the last 429 response as-is — it's a
                    // valid signal source, not a transport failure.
                    if status == 429 && attempt + 1 < attempts {
                        if let Some(a) = &authority {
                            self.mark_rate_limited(a);
                        }
                        warn!(url = %url, status, "rate limited (429); backing off");
                        continue;
                    }
                    let headers = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().to_ascii_lowercase(),
                                v.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<Vec<_>>();
                    let body = read_body_capped(resp).await;
                    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                    debug!(url = %url, status, latency_ms, "response");
                    return Ok(Response {
                        url: url.to_string(),
                        status,
                        headers,
                        body,
                        latency_ms,
                    });
                }
                Err(e) => {
                    debug!(url = %url, attempt, error = %e, "request error");
                    last_err = Some(e);
                }
            }
        }

        Err(WafidError::RequestFailed {
            url: sanitize_for_error(url),
            attempts,
            detail: last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "request failed without a specific error".into()),
        })
    }
}

fn sanitize_for_error(u: &url::Url) -> String {
    let mut c = u.clone();
    c.set_query(None);
    c.set_fragment(None);
    c.to_string()
}

/// Drain the response body up to [`crate::BODY_CAP_BYTES`] so oversized pages
/// can't balloon memory during large batch scans.
async fn read_body_capped(resp: reqwest::Response) -> String {
    let mut resp = resp;
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    while buf.len() < crate::BODY_CAP_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = crate::BODY_CAP_BYTES - buf.len();
                buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
                if chunk.len() > room {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

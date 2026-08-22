pub mod body;
pub mod cookie;
pub mod header;
pub mod status_code;
pub mod timing;

use crate::{Match, Response};

pub use body::BodyDetector;
pub use cookie::CookieDetector;
pub use header::HeaderDetector;
pub use status_code::StatusCodeDetector;
pub use timing::TimingDetector;

/// A triggered response paired with the trigger that produced it.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub trigger: &'static str,
    pub response: Response,
}

/// A pluggable signal source. Each detector inspects the baseline response
/// and any triggered (attack-probe) responses and emits raw matches; scoring
/// and confidence assignment happen centrally in [`crate::fingerprint`].
pub trait Detector {
    fn name(&self) -> &'static str;
    fn analyze(&self, baseline: &Response, triggered: &[ProbeResult]) -> Vec<Match>;
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::{ProbeResult, Response};

    pub(crate) fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        Response::synthetic(status, headers, body)
    }

    pub(crate) fn probe(
        trigger: &'static str,
        status: u16,
        headers: &[(&str, &str)],
        body: &str,
    ) -> ProbeResult {
        let mut r = Response::synthetic(status, headers, body);
        r.url = "https://test.local/?wafid=probe".into();
        ProbeResult {
            trigger,
            response: r,
        }
    }
}

use std::path::Path;

use serde::Deserialize;
use tracing::debug;

use crate::error::{Result, WafidError};

/// Builtin seed pack, embedded at compile time so binaries are self-contained.
pub const DEFAULT_SIGNATURES: &str = include_str!("../signatures/default.yaml");

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    Low,
    Medium,
    High,
}

impl Strength {
    pub fn weight(self) -> f32 {
        match self {
            Strength::Low => 0.3,
            Strength::Medium => 0.6,
            Strength::High => 1.0,
        }
    }

    pub fn is_high(self) -> bool {
        self == Strength::High
    }

    /// Confidence-tier bucket for a signal of this strength. Detectors emit
    /// the `Strength` enum so tier classification lives in one place instead
    /// of re-deriving it from floating-point weights in the fingerprint
    /// engine (which would drift if weights ever changed).
    pub fn tier(self) -> Tier {
        match self {
            Strength::High => Tier::High,
            Strength::Medium => Tier::Medium,
            Strength::Low => Tier::Low,
        }
    }
}

/// Coarse signal-strength bucket used by the fingerprint engine to assign
/// confidence tiers. Deliberately derived from [`Strength`] so there is a
/// single source of truth for what counts as "high"/"medium".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    Exists,
    Contains,
    Exact,
    Prefix,
    Regex,
}

/// Compiled matcher for a header value (or body literal).
#[derive(Debug, Clone)]
pub enum ValueMatcher {
    Exists,
    Contains(String),
    Exact(String),
    Prefix(String),
    Regex(regex::Regex),
}

impl ValueMatcher {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            // Header existence checks are case-insensitive substring probes
            // against an empty needle would be silly; Exists is handled by
            // callers checking presence first.
            ValueMatcher::Exists => true,
            ValueMatcher::Contains(needle) => value
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
            ValueMatcher::Exact(needle) => value.eq_ignore_ascii_case(needle),
            ValueMatcher::Prefix(prefix) => {
                value.len() >= prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix)
            }
            ValueMatcher::Regex(re) => re.is_match(value),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            ValueMatcher::Exists => "exists".into(),
            ValueMatcher::Contains(s) => format!("contains '{s}'"),
            ValueMatcher::Exact(s) => format!("is '{s}'"),
            ValueMatcher::Prefix(s) => format!("starts with '{s}'"),
            ValueMatcher::Regex(r) => format!("matches /{}/", r.as_str()),
        }
    }
}

fn compile_regex(pattern: &str) -> std::result::Result<regex::Regex, regex::Error> {
    // Match anywhere in the input by default; anchors in user patterns still work.
    regex::Regex::new(pattern)
}

// ---------------------------------------------------------------------------
// Raw (deserialized) shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PackSource {
    Bare(Vec<VendorRaw>),
    Wrapped(PackFile),
}

#[derive(Debug, Deserialize)]
struct PackFile {
    #[serde(default)]
    version: Option<String>,
    #[serde(default = "Vec::new")]
    signatures: Vec<VendorRaw>,
}

#[derive(Debug, Deserialize)]
struct VendorRaw {
    vendor: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    signals: SignalsRaw,
}

#[derive(Debug, Default, Deserialize)]
struct SignalsRaw {
    #[serde(default)]
    headers: Vec<HeaderRaw>,
    #[serde(default)]
    cookies: Vec<CookieRaw>,
    #[serde(default)]
    body: Vec<BodyRaw>,
    #[serde(default)]
    status: Vec<StatusRaw>,
}

#[derive(Debug, Deserialize)]
struct HeaderRaw {
    key: String,
    /// Either the literal sentinel `exists`, or a value to match.
    #[serde(default)]
    r#match: Option<String>,
    /// Explicit match mode; inferred when omitted (`exists` sentinel or
    /// case-insensitive contains).
    #[serde(default)]
    mode: Option<MatchMode>,
    strength: Strength,
}

impl HeaderRaw {
    fn into_sig(self) -> Result<HeaderSig> {
        let key = self.key;
        let strength = self.strength;
        let mode = self.mode;
        let mval = self.r#match;
        let matcher = match (mode, mval.as_deref()) {
            (Some(MatchMode::Exists), _) | (None, Some("exists")) | (None, None) => {
                ValueMatcher::Exists
            }
            (Some(MatchMode::Contains), Some(v)) => ValueMatcher::Contains(v.to_string()),
            (Some(MatchMode::Exact), Some(v)) => ValueMatcher::Exact(v.to_string()),
            (Some(MatchMode::Prefix), Some(v)) => ValueMatcher::Prefix(v.to_string()),
            (Some(MatchMode::Regex), Some(v)) => {
                ValueMatcher::Regex(compile_regex(v).map_err(|e| {
                    WafidError::signature_invalid(format!("header '{key}': bad regex: {e}"))
                })?)
            }
            (Some(m), None) => {
                return Err(WafidError::signature_invalid(format!(
                    "header '{key}' declares mode {m:?} but has no `match` value"
                )));
            }
            (None, Some(v)) => ValueMatcher::Contains(v.to_string()),
        };
        Ok(HeaderSig {
            key,
            matcher,
            strength,
        })
    }
}

#[derive(Debug, Deserialize)]
struct CookieRaw {
    pattern: String,
    strength: Strength,
}

#[derive(Debug, Deserialize)]
struct BodyRaw {
    /// Regex pattern. Mutually exclusive with `literal`.
    #[serde(default)]
    pattern: Option<String>,
    /// Plain case-insensitive substring.
    #[serde(default)]
    literal: Option<String>,
    strength: Strength,
    /// Also allow this signal on the baseline response (for WAF branding
    /// injected into *every* page, not just block pages). Default: only count
    /// when present in a triggered response but absent from baseline.
    #[serde(default)]
    always: bool,
}

impl BodyRaw {
    fn into_sig(self) -> Result<BodySig> {
        let (matcher, display) = match (&self.pattern, &self.literal) {
            (Some(p), None) => {
                let re = compile_regex(p).map_err(|e| {
                    WafidError::signature_invalid(format!("bad body regex '{p}': {e}"))
                })?;
                (BodyMatcher::Regex(re), format!("/{p}/"))
            }
            (None, Some(l)) => (BodyMatcher::Literal(l.to_lowercase()), format!("\"{l}\"")),
            (Some(_), Some(_)) => {
                return Err(WafidError::signature_invalid(
                    "body signal cannot declare both `pattern` and `literal`",
                ));
            }
            (None, None) => {
                return Err(WafidError::signature_invalid(
                    "body signal needs either `pattern` or `literal`",
                ));
            }
        };
        Ok(BodySig {
            matcher,
            display,
            strength: self.strength,
            always: self.always,
        })
    }
}

#[derive(Debug, Deserialize)]
struct StatusRaw {
    codes: Vec<u16>,
    strength: Strength,
}

// ---------------------------------------------------------------------------
// Compiled shapes used by detectors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum BodyMatcher {
    Regex(regex::Regex),
    Literal(String),
}

impl BodyMatcher {
    pub fn matches(&self, body: &str) -> bool {
        match self {
            BodyMatcher::Regex(re) => re.is_match(body),
            BodyMatcher::Literal(lit) => body.to_lowercase().contains(lit),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeaderSig {
    pub key: String,
    pub matcher: ValueMatcher,
    pub strength: Strength,
}

#[derive(Debug, Clone)]
pub struct CookieSig {
    pub pattern_raw: String,
    pub pattern: regex::Regex,
    pub strength: Strength,
}

#[derive(Debug, Clone)]
pub struct BodySig {
    pub matcher: BodyMatcher,
    pub display: String,
    pub strength: Strength,
    pub always: bool,
}

#[derive(Debug, Clone)]
pub struct StatusSig {
    pub codes: Vec<u16>,
    pub strength: Strength,
}

#[derive(Debug, Clone)]
pub struct VendorSig {
    pub vendor: String,
    pub category: Option<String>,
    pub headers: Vec<HeaderSig>,
    pub cookies: Vec<CookieSig>,
    pub body: Vec<BodySig>,
    pub status: Vec<StatusSig>,
}

impl VendorSig {
    pub fn total_signals(&self) -> usize {
        self.headers.len() + self.cookies.len() + self.body.len() + self.status.len()
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

fn parse_yaml(text: &str) -> Result<(Option<String>, Vec<VendorRaw>)> {
    let source: PackSource = serde_yaml::from_str(text).map_err(|e| WafidError::SignatureLoad {
        path: "<memory>".into(),
        source: e,
    })?;
    match source {
        PackSource::Bare(list) => Ok((None, list)),
        PackSource::Wrapped(f) => Ok((f.version, f.signatures)),
    }
}

fn compile_vendor(raw: VendorRaw) -> Result<VendorSig> {
    let mut sig = VendorSig {
        vendor: raw.vendor,
        category: raw.category,
        headers: Vec::new(),
        cookies: Vec::new(),
        body: Vec::new(),
        status: Vec::new(),
    };
    let s = raw.signals;
    for h in s.headers {
        sig.headers.push(h.into_sig()?);
    }
    for c in s.cookies {
        let re = compile_regex(&c.pattern).map_err(|e| {
            WafidError::signature_invalid(format!(
                "vendor '{}': bad cookie regex '{}': {e}",
                sig.vendor, c.pattern
            ))
        })?;
        sig.cookies.push(CookieSig {
            pattern_raw: c.pattern.clone(),
            pattern: re,
            strength: c.strength,
        });
    }
    for b in s.body {
        sig.body.push(b.into_sig()?);
    }
    for st in s.status {
        if st.codes.is_empty() {
            return Err(WafidError::signature_invalid(format!(
                "vendor '{}': status signal has empty codes list",
                sig.vendor
            )));
        }
        sig.status.push(StatusSig {
            codes: st.codes,
            strength: st.strength,
        });
    }
    Ok(sig)
}

/// Load a signature pack from a YAML file.
pub fn load_pack(path: &Path) -> Result<Vec<VendorSig>> {
    let text = std::fs::read_to_string(path)?;
    let (version, raws) = serde_yaml::from_str::<PackSource>(&text)
        .map(|src| match src {
            PackSource::Bare(list) => (None, list),
            PackSource::Wrapped(f) => (f.version, f.signatures),
        })
        .map_err(|source| WafidError::SignatureLoad {
            path: path.display().to_string(),
            source,
        })?;
    debug!(path = %path.display(), version = version.as_deref().unwrap_or("unversioned"), vendors = raws.len(), "loaded signature pack");
    raws.into_iter().map(compile_vendor).collect()
}

/// The builtin seed pack compiled from the embedded YAML.
pub fn builtin_pack() -> Result<Vec<VendorSig>> {
    let (version, raws) = parse_yaml(DEFAULT_SIGNATURES)?;
    debug!(
        vendors = raws.len(),
        version = version.as_deref().unwrap_or("unversioned"),
        "compiled builtin signature pack"
    );
    raws.into_iter().map(compile_vendor).collect()
}

/// Merge two packs: overlay entries replace base entries with the same vendor
/// name (case-sensitive); others are appended.
pub fn merge_packs(base: Vec<VendorSig>, overlay: Vec<VendorSig>) -> Vec<VendorSig> {
    let mut out = base;
    for ov in overlay {
        if let Some(existing) = out.iter_mut().find(|v| v.vendor == ov.vendor) {
            *existing = ov;
        } else {
            out.push(ov);
        }
    }
    out
}

/// Post-merge sanity checks.
pub fn check_pack(pack: &[VendorSig]) -> Result<()> {
    if pack.is_empty() {
        return Err(WafidError::signature_invalid(
            "signature pack is empty (no vendors)",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for v in pack {
        if !seen.insert(v.vendor.as_str()) {
            return Err(WafidError::signature_invalid(format!(
                "duplicate vendor '{}' in merged signature pack",
                v.vendor
            )));
        }
        if v.total_signals() == 0 {
            return Err(WafidError::signature_invalid(format!(
                "vendor '{}' has zero signals",
                v.vendor
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Linter (backing `wafid signatures validate`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub vendor: Option<String>,
    pub section: Option<String>,
    pub message: String,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] ", self.severity)?;
        if let Some(v) = &self.vendor {
            write!(f, "{v}: ")?;
        }
        if let Some(s) = &self.section {
            write!(f, "{s}: ")?;
        }
        write!(f, "{}", self.message)
    }
}

/// Validate a YAML file without compiling it wholesale, reporting per-entry
/// diagnostics so authors see every problem, not just the first one.
pub fn lint_file(path: &Path) -> Vec<Diagnostic> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            return vec![Diagnostic {
                severity: Severity::Error,
                vendor: None,
                section: None,
                message: format!("cannot read {}: {e}", path.display()),
            }];
        }
    };

    let value: serde_yaml::Value = match serde_yaml::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return vec![Diagnostic {
                severity: Severity::Error,
                vendor: None,
                section: None,
                message: format!("invalid YAML: {e}"),
            }];
        }
    };

    // Unwrap to the vendor sequence.
    let entries: &serde_yaml::Sequence = match &value {
        serde_yaml::Value::Sequence(seq) => seq,
        serde_yaml::Value::Mapping(m) => {
            match m.get(serde_yaml::Value::String("signatures".into())) {
                Some(serde_yaml::Value::Sequence(seq)) => seq,
                _ => {
                    return vec![Diagnostic {
                    severity: Severity::Error,
                    vendor: None,
                    section: None,
                    message: "expected a top-level list of vendors, or a mapping with a `signatures` list".into(),
                }];
                }
            }
        }
        _ => {
            return vec![Diagnostic {
                severity: Severity::Error,
                vendor: None,
                section: None,
                message:
                    "expected a top-level list of vendors, or a mapping with a `signatures` list"
                        .into(),
            }];
        }
    };

    let mut diags = Vec::new();
    let mut seen_vendors = std::collections::HashSet::new();

    for entry in entries {
        let map = match entry {
            serde_yaml::Value::Mapping(m) => m,
            _ => {
                diags.push(Diagnostic {
                    severity: Severity::Error,
                    vendor: None,
                    section: None,
                    message: format!("entry is not a mapping: {entry:?}"),
                });
                continue;
            }
        };

        let vendor = map
            .get(serde_yaml::Value::String("vendor".into()))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let vendor_label = vendor.clone().unwrap_or_else(|| "<unnamed>".into());

        if vendor.is_none() {
            diags.push(Diagnostic {
                severity: Severity::Error,
                vendor: None,
                section: None,
                message: "missing required field `vendor`".into(),
            });
        }
        if let Some(v) = &vendor
            && !seen_vendors.insert(v.clone())
        {
            diags.push(Diagnostic {
                severity: Severity::Warning,
                vendor: Some(vendor_label.clone()),
                section: None,
                message:
                    "duplicate vendor entry (later definitions override earlier ones at load time)"
                        .into(),
            });
        }

        let signals = map.get(serde_yaml::Value::String("signals".into()));
        let signals_map = match signals {
            None | Some(serde_yaml::Value::Null) => {
                diags.push(Diagnostic {
                    severity: Severity::Warning,
                    vendor: Some(vendor_label),
                    section: None,
                    message: "no signals defined; this vendor can never match".into(),
                });
                continue;
            }
            Some(serde_yaml::Value::Mapping(m)) => m,
            Some(other) => {
                diags.push(Diagnostic {
                    severity: Severity::Error,
                    vendor: Some(vendor_label),
                    section: None,
                    message: format!("`signals` must be a mapping, got: {other:?}"),
                });
                continue;
            }
        };

        const SECTIONS: [(&str, SignalKind); 4] = [
            ("headers", SignalKind::Header),
            ("cookies", SignalKind::Cookie),
            ("body", SignalKind::Body),
            ("status", SignalKind::Status),
        ];

        let mut total = 0usize;
        for (section, kind) in SECTIONS {
            let key = serde_yaml::Value::String(section.into());
            let items = match signals_map.get(&key) {
                None | Some(serde_yaml::Value::Null) => continue,
                Some(serde_yaml::Value::Sequence(seq)) => seq,
                Some(other) => {
                    diags.push(Diagnostic {
                        severity: Severity::Error,
                        vendor: Some(vendor_label.clone()),
                        section: Some(section.into()),
                        message: format!("must be a list, got: {other:?}"),
                    });
                    continue;
                }
            };
            for (i, item) in items.iter().enumerate() {
                let label = format!("{section}[{i}]");
                diags.extend(lint_signal(kind, &vendor_label, &label, item));
                total += 1;
            }
        }
        if total == 0 {
            diags.push(Diagnostic {
                severity: Severity::Warning,
                vendor: Some(vendor_label),
                section: None,
                message: "`signals` mapping is present but defines no signals".into(),
            });
        }
    }

    diags.sort_by_key(|d| d.severity);
    diags
}

#[derive(Clone, Copy)]
enum SignalKind {
    Header,
    Cookie,
    Body,
    Status,
}

fn lint_signal(
    kind: SignalKind,
    vendor: &str,
    label: &str,
    item: &serde_yaml::Value,
) -> Vec<Diagnostic> {
    let fail = |severity: Severity, msg: String| {
        vec![Diagnostic {
            severity,
            vendor: Some(vendor.to_string()),
            section: Some(label.to_string()),
            message: msg,
        }]
    };
    let map = match item {
        serde_yaml::Value::Mapping(m) => m,
        other => return fail(Severity::Error, format!("not a mapping: {other:?}")),
    };
    let get = |k: &str| map.get(serde_yaml::Value::String(k.into()));

    if get("strength").is_none() {
        return fail(
            Severity::Error,
            "missing required field `strength` (high|medium|low)".into(),
        );
    }
    match get("strength").and_then(|v| v.as_str()) {
        Some("high" | "medium" | "low") => {}
        other => {
            return fail(
                Severity::Error,
                format!("strength must be high|medium|low, got {:?}", other),
            );
        }
    }

    match kind {
        SignalKind::Header => {
            let Some(key) = get("key").and_then(|v| v.as_str()) else {
                return fail(Severity::Error, "missing required field `key`".into());
            };
            if key.is_empty() {
                return fail(Severity::Error, "`key` must not be empty".into());
            }
            let mode = get("mode").and_then(|v| v.as_str());
            let mval = get("match");
            match mode {
                None | Some("exists") => {
                    if mode.is_some() && mval.map(|v| v != "exists").unwrap_or(false) {
                        return fail(
                            Severity::Warning,
                            "`match` value is ignored when mode is `exists`".into(),
                        );
                    }
                }
                Some(m @ ("contains" | "exact" | "prefix")) => {
                    if mval.and_then(|v| v.as_str()).is_none() {
                        return fail(
                            Severity::Error,
                            format!("mode `{m}` requires a string `match` value"),
                        );
                    }
                }
                Some("regex") => {
                    let pat = mval.and_then(|v| v.as_str()).unwrap_or_default();
                    if pat.is_empty() {
                        return fail(
                            Severity::Error,
                            "mode `regex` requires a `match` value".into(),
                        );
                    }
                    if let Err(e) = compile_regex(pat) {
                        return fail(Severity::Error, format!("invalid regex '{pat}': {e}"));
                    }
                }
                Some(other) => {
                    return fail(
                        Severity::Error,
                        format!("unknown mode `{other}` (exists|contains|exact|prefix|regex)"),
                    );
                }
            }
            Vec::new()
        }
        SignalKind::Cookie => {
            let Some(pat) = get("pattern").and_then(|v| v.as_str()) else {
                return fail(
                    Severity::Error,
                    "missing required field `pattern` (regex over cookie names)".into(),
                );
            };
            if let Err(e) = compile_regex(pat) {
                return fail(Severity::Error, format!("invalid regex '{pat}': {e}"));
            }
            Vec::new()
        }
        SignalKind::Body => {
            let pat = get("pattern");
            let lit = get("literal");
            match (pat, lit) {
                (Some(_), Some(_)) => fail(
                    Severity::Error,
                    "declare either `pattern` or `literal`, not both".into(),
                ),
                (Some(serde_yaml::Value::String(p)), _) => match compile_regex(p) {
                    Ok(_) => Vec::new(),
                    Err(e) => fail(Severity::Error, format!("invalid regex '{p}': {e}")),
                },
                (_, Some(serde_yaml::Value::String(_))) => Vec::new(),
                (None, None) => fail(
                    Severity::Error,
                    "body signal needs either `pattern` (regex) or `literal` (substring)".into(),
                ),
                _ => fail(
                    Severity::Error,
                    "`pattern`/`literal` must both be strings when present".into(),
                ),
            }
        }
        SignalKind::Status => {
            let Some(codes) = get("codes") else {
                return fail(Severity::Error, "missing required field `codes`".into());
            };
            let Some(list) = codes.as_sequence() else {
                return fail(Severity::Error, "`codes` must be a list of integers".into());
            };
            for c in list {
                match c.as_u64() {
                    Some(n @ 100..=599) => {
                        let _ = n;
                    }
                    _ => {
                        return fail(
                            Severity::Error,
                            format!("`codes` entries must be HTTP status integers, got {c:?}"),
                        );
                    }
                }
            }
            if list.is_empty() {
                return fail(Severity::Error, "`codes` must not be empty".into());
            }
            Vec::new()
        }
    }
}

# wafid — Technical Guide

Everything you need to run, configure and extend **wafid**. For a high-level overview see [`README.md`](README.md).

## Why not wafw00f

| | wafw00f | wafid |
|---|---|---|
| Scanning model | Sequential, one target at a time | Async concurrent batches (`tokio`) |
| Detection result | Binary detected/not | Confidence tiers: `confirmed` / `likely` / `possible`, with evidence trail |
| Matching | Flat regex list | Weighted multi-signal scoring; body/status signals must *differ from baseline*, killing most false positives |
| Stacked WAFs | First match wins | All layers reported (e.g. Cloudflare in front of ModSecurity) |
| Output | Text only | Text, stable-schema JSON, CSV |
| Signatures | Hardcoded Python | Editable YAML packs, versioned, hot-swappable, lintable (`signatures validate`) |
| Failure modes | Hangs/crashes take down the run | Per-target isolation; failures degrade to `unknown` + errors list |
| Timing analysis | None | Behavioral latency-delta heuristic (supporting signal only) |
| Reuse | CLI only | Library-first: `wafid-core` embeds anywhere |

## Install / build

Prerequisites: Rust **1.85+** (edition 2024). Dependencies are pulled from crates.io on first build.

```sh
cargo build --release          # binary at target/release/wafid
cargo test                     # unit + golden + integration tests
cargo bench -p wafid-core      # concurrent-vs-sequential benchmark
```

## CLI reference

```sh
wafid -u https://example.com                  # scan one target
wafid -l targets.txt                          # batch scan (one URL per line, '#' comments, '-' = stdin)
wafid -u https://example.com --json           # structured output for piping
wafid -l targets.txt -o csv -O results.csv    # spreadsheet-friendly
wafid -u https://example.com --concurrency 50 # parallel batch scanning
wafid -u https://example.com --no-timing      # disable behavioral timing probe
wafid -u https://example.com --passive        # never send attack payloads
wafid -u https://example.com --signatures ./custom.yaml
wafid signatures validate ./custom.yaml       # lint a signature pack
wafid -u https://example.com -v               # verbose evidence/logging
wafid -l targets.txt --dedupe                 # scan each unique target once
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--timeout <secs>` | 10 | per-request timeout |
| `--proxy <url>` | – | HTTP(S)/SOCKS proxy |
| `--user-agent <s>` / `--random-ua` | `wafid/x.y` | UA control |
| `--concurrency <n>` | 20 | parallel targets in batch mode |
| `--retries <n>` | 2 | retries on network errors & 429s (exponential backoff) |
| `--dedupe` | off | scan each unique target only once (first occurrence wins) |
| `--no-timing` | off | skip latency-delta detection |
| `--passive` | off | baseline signals only — zero attack payloads sent |
| `--signatures <path>` | builtin pack | extra pack; same-vendor entries override builtins |
| `--no-builtin-signatures` | off | use *only* the custom pack |

**Exit codes:** `0` at least one WAF found · `1` none found · `2` operational error. CI-friendly.

## JSON output schema

Single target emits the object directly; multiple targets wrap them under `results`. `schema_version` lets you pin against changes.

```json
{
  "schema_version": 1,
  "url": "https://example.com/",
  "scanned_at": "2026-08-22T10:00:00+00:00",
  "matches": [
    {
      "vendor": "Cloudflare",
      "category": "cdn_waf",
      "confidence": "confirmed",
      "score": 2.45,
      "evidence": [
        "header:cf-ray exists",
        "body:/Attention Required! \\| Cloudflare/ on trigger 'xss_tag'"
      ]
    }
  ],
  "unknown": false,
  "timing_anomaly": false,
  "passive": false,
  "errors": []
}
```

## How detection works

1. **Baseline request** — a clean GET.
2. **Trigger battery** (8 requests): XSS, SQLi (classic + UNION), path traversal (raw + pre-encoded), command injection, JNDI probe, oversized header — injected into query and/or path.
3. **Detectors** run over baseline + triggered responses:

   | Detector | Signal source | Anti-FP rule |
   |---|---|---|
   | header | vendor headers (`cf-ray`, `x-iinfo`, …) | persistent, checked everywhere |
   | cookie | Set-Cookie names (`incap_ses_*`, `ak_bmsc`, …) | persistent, checked everywhere |
   | body | block-page content | must appear under attack but NOT on baseline (unless marked `always`) |
   | status | anomalous codes to payloads (403/406/…) | must differ from baseline status |
   | timing | latency delta under payload load | supporting signal only — can never create or confirm a match |

4. **Scoring** — each signal carries a `Strength` enum (`high`/`medium`/`low`) whose weight feeds the score; confidence tiers are derived directly from the enum, not from floating-point thresholds:

   - `confirmed`: ≥2 high-strength signals from **distinct detectors**
   - `likely`: one high-strength signal, or ≥2 medium
   - `possible`: anything else

   A vendor whose *only* evidence is an anomalous status code is dropped: dozens of products return 403, so it attributes nothing (status still counts fully as supporting evidence).

### Passive mode

`--passive` skips step 2 entirely. Only persistent signals (headers, cookies, always-on branding) fire — useful when you're authorized to *look* but not to *poke*.

## Signature packs

The builtin pack lives at [`wafid-core/signatures/default.yaml`](wafid-core/signatures/default.yaml) and covers Cloudflare, Akamai, Imperva/Incapsula, AWS WAF, Sucuri, F5 BIG-IP, ModSecurity (generic), Barracuda, Fortinet FortiWeb and Azure Front Door.

Schema:

```yaml
version: "1"

signatures:
  - vendor: Cloudflare            # unique display name
    category: cdn_waf             # free-form label
    signals:
      headers:
        - key: cf-ray
          match: exists           # or a value...
          # mode: contains|exact|prefix|regex   (default: contains)
          strength: high
      cookies:
        - pattern: "^(__cf|cf_)[\\w-]*"   # regex over Set-Cookie names
          strength: medium
      body:
        - pattern: 'Attention Required! \| Cloudflare'  # regex
          # literal: plain substring alternative to pattern
          # always: true   → also counts on the baseline page (branding)
          strength: high
      status:
        - codes: [403, 429]     # anomalous codes observed on triggered probes
          strength: low
```

Notes:

- Header keys are matched case-insensitively; string values case-insensitive contains unless `mode` says otherwise.
- Body patterns are **delta-matched by default**: they count only when present in a triggered response and absent from the clean baseline. Set `always: true` for branding injected into every response.
- In double-quoted YAML strings escape backslashes (`\\|`, `\\w`); prefer single quotes for regexes.

Validate any pack before shipping it:

```sh
wafid signatures validate mypack.yaml
# [Error] AcmeWAF: body[0]: invalid regex '(foo': unclosed group
# [Warning] OldVendor: no signals defined; this vendor can never match
```

Extend or override the builtins:

```sh
wafid -u https://target --signatures mypack.yaml              # merged over builtins
wafid -u https://target --signatures mypack.yaml --no-builtin-signatures   # custom only
```

A custom entry whose `vendor` name equals a builtin name replaces it — convenient for tightening thresholds without forking the whole pack.

## Embedding the library

`wafid-core` is a standalone library that can be embedded without shelling out to the CLI.

```toml
[dependencies]
wafid-core = "0.1"
tokio = { version = "1", features = ["full"] }
```

```rust
use wafid_core::{EngineBuilder, ProgressFn};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let engine = EngineBuilder::new()
        .timing(true)
        .build()
        .unwrap();

    // One target — never panics, errors land in ScanResult::errors.
    let res = engine.scan("https://example.com").await;
    println!("{}", serde_json::to_string_pretty(&res).unwrap());

    // Batch with bounded concurrency.
    let targets = vec!["https://a.example".into(), "https://b.example".into()];
    let results = engine.scan_batch(targets, 20, None).await;
}
```

### Extending detectors

Custom detectors implement one trait:

```rust
pub trait Detector {
    fn name(&self) -> &'static str;
    fn analyze(&self, baseline: &Response, triggered: &[ProbeResult]) -> Vec<Match>;
}
```

See `wafid-core/src/detectors/` for five reference implementations.

## Reliability guarantees

- No panics on network errors, malformed responses or garbage input URLs — every target returns a `ScanResult`.
- Global per-target deadline (derived from `--timeout`/`--retries`) plus per-request timeouts; a hung host can't stall a batch.
- Per-host rate limiting with automatic decay: a 429 from one target slows only that target for a cooldown window; other targets are unaffected.
- Multi-sample timing baseline: baseline latency is measured across 3 samples (median) instead of one, preventing jitter from producing false timing anomalies.
- Progress callbacks are panic-safe: a panicking `ProgressFn` never drops a target's result or aborts the batch.
- Response bodies capped at 64 KB in memory.

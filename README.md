░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█████████████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓███████▓▒░  
                                                                   
                                                                   

**wafid** is a fast, accurate WAF (Web Application Firewall) fingerprinting tool. Give it a URL and it tells you which firewall or CDN sits in front of the target — Cloudflare, Akamai, AWS WAF, Sucuri, F5, ModSecurity, and more.

Unlike a simple "detected / not detected" check, wafid combines multiple independent signals — response headers, cookies, block-page content, status-code changes and timing behavior — into a weighted **confidence verdict** (`confirmed` / `likely` / `possible`) with an evidence trail you can inspect.

## Key features

- **Async, concurrent** — scans hundreds of targets in parallel, not one at a time.
- **Confidence scoring, not guesswork** — weighted multi-signal analysis that cuts false positives, and reports *stacked* WAFs (e.g. Cloudflare in front of ModSecurity).
- **Structured output** — stable-schema JSON for automation, plus human-readable text and CSV.
- **Editable signature database** — YAML signature packs you can extend, override and lint, no recompiling.
- **Library-first** — the detection engine (`wafid-core`) is a standalone crate you can embed in other tools.

## Quick start

```sh
git clone https://github.com/rootxtrem3/wafid.git
cd wafid
cargo build --release            # binary at target/release/wafid
```

```sh
./target/release/wafid -u https://example.com          # scan one target
./target/release/wafid -u https://example.com --json   # machine-readable output
```

## Documentation

Full technical reference — CLI flags, JSON schema, signature-pack format, how detection works, embedding the library — is in [**GUIDE.md**](GUIDE.md).

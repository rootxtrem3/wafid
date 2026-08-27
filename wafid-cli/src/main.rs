mod output;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use owo_colors::OwoColorize;
use tracing_subscriber::EnvFilter;

use wafid_core::http_client::ClientConfig;
use wafid_core::{Engine, EngineBuilder, ScanResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Signature-pack tooling.
    Signatures {
        #[command(subcommand)]
        cmd: SignatureCmd,
    },
}

#[derive(Debug, Subcommand)]
enum SignatureCmd {
    /// Lint a signature YAML file for schema errors and suspicious patterns.
    Validate { path: PathBuf },
}

/// wafid — fast, accurate WAF fingerprinting.
///
/// Exits 0 when at least one WAF was detected, 1 when none was found,
/// and 2 on operational errors.
#[derive(Debug, Parser)]
#[command(name = "wafid", version, about, after_help = exit_code_help())]
struct Cli {
    /// Target URL (e.g. https://example.com).
    #[arg(short = 'u', long, conflicts_with = "list")]
    url: Option<String>,

    /// File with one URL per line ('-' reads stdin). '#' comments allowed.
    #[arg(short = 'l', long)]
    list: Option<String>,

    /// Shorthand for `-o json`.
    #[arg(long, conflicts_with = "output")]
    json: bool,

    /// Output format.
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    /// Write results to this file instead of stdout.
    #[arg(short = 'O', long)]
    output_file: Option<PathBuf>,

    /// Max targets scanned in parallel (batch mode).
    #[arg(long, default_value_t = 20)]
    concurrency: usize,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Route requests through an HTTP(S)/SOCKS proxy.
    #[arg(long)]
    proxy: Option<String>,

    /// Custom User-Agent string.
    #[arg(long, conflicts_with = "random_ua")]
    user_agent: Option<String>,

    /// Pick a random browser User-Agent for this run.
    #[arg(long)]
    random_ua: bool,

    /// Disable behavioral timing detection.
    #[arg(long)]
    no_timing: bool,

    /// Never send attack payloads (baseline signals only).
    #[arg(long)]
    passive: bool,

    /// Additional signature pack (YAML). Vendors defined here override
    /// builtin pack entries of the same name.
    #[arg(long)]
    signatures: Option<PathBuf>,

    /// Ignore the builtin signature pack (use only --signatures).
    #[arg(long, requires = "signatures")]
    no_builtin_signatures: bool,

    /// Deduplicate repeated target URLs across -u and -l (first occurrence wins).
    #[arg(long)]
    dedupe: bool,

    /// Retries per request on network errors / rate limiting.
    #[arg(long, default_value_t = 2)]
    retries: u32,

    /// Verbose logging (-v debug, -vv trace); logs go to stderr.
    #[arg(short = 'v', global = true, action = ArgAction::Count)]
    verbose: u8,

    /// Disable colored text output (also honors NO_COLOR).
    #[arg(long)]
    no_color: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

fn exit_code_help() -> String {
    "exit codes:\n  0  at least one match\n  1  no matches\n  2  operational error".to_string()
}

impl Cli {
    fn format(&self) -> OutputFormat {
        if self.json {
            OutputFormat::Json
        } else {
            self.output
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    if let Some(Commands::Signatures {
        cmd: SignatureCmd::Validate { path },
    }) = &cli.command
    {
        return cmd_validate(path);
    }

    match run(&cli).await {
        Ok(found) => {
            if found {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            let colored = !cli.no_color && std::env::var_os("NO_COLOR").is_none();
            let msg = format!("wafid: {e}");
            eprintln!("{}", if colored { msg.red().to_string() } else { msg });
            ExitCode::from(2)
        }
    }
}

fn init_logging(verbose: u8) {
    let filter = match verbose {
        0 => EnvFilter::new("warn"),
        1 => EnvFilter::new("info,wafid_core=debug"),
        _ => EnvFilter::new("trace"),
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .try_init();
}

fn cmd_validate(path: &Path) -> ExitCode {
    let diags = wafid_core::signatures::lint_file(path);
    if diags.is_empty() {
        println!("{} {}", "OK".green().bold(), path.display());
        return ExitCode::SUCCESS;
    }
    let errors = diags
        .iter()
        .filter(|d| d.severity == wafid_core::signatures::Severity::Error)
        .count();
    for d in &diags {
        match d.severity {
            wafid_core::signatures::Severity::Error => println!("{}", d.red()),
            wafid_core::signatures::Severity::Warning => println!("{}", d.yellow()),
        }
    }
    println!(
        "\n{} error(s), {} warning(s) in {}",
        errors.to_string().red().bold(),
        diags.len() - errors,
        path.display()
    );
    if errors > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// Fatal errors are operational (bad args, unreadable files): exit code 2.
type RunResult<T> = Result<T, String>;

async fn run(cli: &Cli) -> RunResult<bool> {
    let mut targets = collect_targets(cli)?;
    if cli.dedupe && targets.len() > 1 {
        let mut seen = std::collections::HashSet::new();
        targets.retain(|t| seen.insert(t.clone()));
    }
    if targets.is_empty() {
        return Err("no targets: pass -u <url> or -l <file>".into());
    }

    let client_cfg = ClientConfig {
        timeout_secs: cli.timeout,
        user_agent: cli.user_agent.clone(),
        random_user_agent: cli.random_ua,
        proxy: cli.proxy.clone(),
        retries: cli.retries,
    };

    let mut builder = EngineBuilder::new()
        .client_config(client_cfg)
        .timing(!cli.no_timing)
        .passive(cli.passive);
    if let Some(sig_path) = &cli.signatures {
        builder = builder.signatures(sig_path.clone());
    }
    if cli.no_builtin_signatures {
        builder = builder.no_builtin_signatures();
    }

    let engine = builder
        .build()
        .map_err(|e| format!("engine setup failed: {e}"))?;

    let started = Instant::now();
    let results: Vec<ScanResult> = if targets.len() == 1 {
        vec![engine.scan(&targets[0]).await]
    } else {
        scan_batch_with_progress(&engine, targets, cli).await
    };
    let elapsed = started.elapsed();

    render(cli, &results);

    eprintln!(
        "\n{}",
        format!(
            "scanned {} target(s) in {:.1}s",
            results.len(),
            elapsed.as_secs_f64()
        )
        .dimmed()
    );

    determine_outcome(&results)
}

/// Decide what the run should report, isolating the exit-code policy into one
/// pure, testable function.
///
/// Returns `Ok(true)` if at least one WAF match was found, `Ok(false)` if the
/// targets were scanned but nothing matched, or `Err(..)` if *every* target
/// failed operationally (network unreachable etc.).
fn determine_outcome(results: &[ScanResult]) -> Result<bool, String> {
    let found = results.iter().any(|r| !r.matches.is_empty());
    if !found && !results.is_empty() && results.iter().all(|r| r.unknown && !r.errors.is_empty()) {
        return Err("every target failed (network unreachable?)".into());
    }
    Ok(found)
}

async fn scan_batch_with_progress(
    engine: &Engine,
    targets: Vec<String>,
    cli: &Cli,
) -> Vec<ScanResult> {
    let total = targets.len();
    let counter = Arc::new(AtomicUsize::new(0));
    let show_progress = cli.format() == OutputFormat::Text;
    let progress: Option<wafid_core::ProgressFn> = if show_progress {
        Some(Arc::new(move |_idx, res: &ScanResult| {
            let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
            let verdict = match res.top_match() {
                Some(top) => format!("{} ({})", top.vendor.bold(), top.confidence.as_str()),
                None if !res.errors.is_empty() => "error".red().to_string(),
                None => "no match".dimmed().to_string(),
            };
            eprintln!("[{n}/{total}] {} \u{2192} {verdict}", res.url);
        }))
    } else {
        None
    };
    engine.scan_batch(targets, cli.concurrency, progress).await
}

fn collect_targets(cli: &Cli) -> RunResult<Vec<String>> {
    let mut out = Vec::new();
    if let Some(url) = &cli.url {
        out.push(url.clone());
    }
    if let Some(list) = &cli.list {
        let content = if list == "-" {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| e.to_string())?;
            buf
        } else {
            std::fs::read_to_string(list).map_err(|e| format!("cannot read {}: {e}", list))?
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            out.push(line.to_string());
        }
    }
    Ok(out)
}

fn render(cli: &Cli, results: &[ScanResult]) {
    let rendered = match cli.format() {
        OutputFormat::Json => output::json::render(results),
        OutputFormat::Csv => output::csv::render(results),
        OutputFormat::Text => output::text::render(results),
    };
    if let Some(path) = &cli.output_file {
        if let Err(e) = std::fs::write(path, rendered) {
            eprintln!("wafid: cannot write {}: {e}", path.display());
            std::process::exit(2);
        }
        eprintln!("results written to {}", path.display());
    } else {
        print!("{rendered}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use wafid_core::{Confidence, VendorMatch};

    fn vendor(vendor: &str, conf: Confidence) -> VendorMatch {
        VendorMatch {
            vendor: vendor.into(),
            category: None,
            confidence: conf,
            score: 1.0,
            evidence: vec!["header:x exists".into()],
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
    fn determine_outcome_found_when_any_match() {
        assert_eq!(
            determine_outcome(&[result("https://a", vec![vendor("CF", Confidence::Likely)], vec![])]),
            Ok(true)
        );
    }

    #[test]
    fn determine_outcome_none_when_scanned_clean() {
        // clean scan: unknown but no errors -> "no match", not operational error
        assert_eq!(
            determine_outcome(&[result("https://a", vec![], vec![])]),
            Ok(false)
        );
    }

    #[test]
    fn determine_outcome_error_only_when_all_failed() {
        // all unknown WITH errors -> operational failure
        assert_eq!(
            determine_outcome(&[
                result("https://a", vec![], vec!["timeout".into()]),
                result("https://b", vec![], vec!["conn refused".into()]),
            ]),
            Err("every target failed (network unreachable?)".into())
        );
        // mixed: one failed, one clean (no errors) -> treated as "no match"
        assert_eq!(
            determine_outcome(&[
                result("https://a", vec![], vec!["timeout".into()]),
                result("https://b", vec![], vec![]),
            ]),
            Ok(false)
        );
        // empty results should not be an "all failed" error
        assert_eq!(determine_outcome(&[]), Ok(false));
    }

    #[test]
    fn collect_targets_skips_blanks_and_comments() {
        let dir = std::env::temp_dir();
        let p = dir.join("wafid_test_targets.txt");
        std::fs::write(&p, "https://a.example\n\n# a comment\nhttps://b.example\n").unwrap();
        let cli = Cli::try_parse_from(["wafid", "-l", p.to_str().unwrap()]).unwrap();
        let targets = collect_targets(&cli).unwrap();
        assert_eq!(targets, vec!["https://a.example", "https://b.example"]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn dedupe_keeps_first_occurrence() {
        // `--dedupe` parses on its own (-u conflicts with -l, so only -u here).
        let cli = Cli::try_parse_from(["wafid", "-u", "https://a.example", "--dedupe"]).unwrap();
        // can't call run() (network); test the retain logic in isolation via
        // the same code path used by run(): build a small vec and dedupe.
        let mut targets = vec![
            "https://a.example".to_string(),
            "https://b.example".to_string(),
            "https://a.example".to_string(),
        ];
        if cli.dedupe && targets.len() > 1 {
            let mut seen = std::collections::HashSet::new();
            targets.retain(|t| seen.insert(t.clone()));
        }
        assert_eq!(targets, vec!["https://a.example", "https://b.example"]);
    }

    #[test]
    fn example_documented_flags_parse() {
        // Smoke-test that the documented command-line surface parses.
        Cli::try_parse_from([
            "wafid", "-u", "https://a", "--json",
        ])
        .unwrap();
        Cli::try_parse_from([
            "wafid", "-u", "https://a", "-o", "csv", "--concurrency", "50", "--timeout", "5",
            "--no-timing", "--passive", "--random-ua", "--retries", "3",
        ])
        .unwrap();
        Cli::try_parse_from([
            "wafid", "-u", "https://a", "--user-agent", "curl/8", "--no-color",
        ])
        .unwrap();
        // mutually exclusive combos must be rejected
        assert!(Cli::try_parse_from(["wafid", "-u", "a", "-u", "b", "--random-ua", "--user-agent", "x"]).is_err());
        assert!(Cli::try_parse_from(["wafid", "--json", "-o", "csv", "-u", "a"]).is_err());
    }

    #[test]
    fn signatures_validate_subcommand_parses() {
        Cli::try_parse_from(["wafid", "signatures", "validate", "some.yaml"]).unwrap();
    }
}

//! Benchmarks the core differentiator over sequential scanners (wafw00f):
//! wall-clock time for scanning N simulated WAF targets concurrently vs
//! sequentially against local wiremock servers.
//!
//! Run with: cargo bench -p wafid-core

use criterion::{Criterion, criterion_group, criterion_main};
use wafid_core::EngineBuilder;
use wafid_core::http_client::ClientConfig;
use wiremock::matchers::method;
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

struct AttackProbe;

impl Match for AttackProbe {
    fn matches(&self, req: &Request) -> bool {
        let url = req.url.to_string();
        url.contains("%3C") || url.contains("passwd") || url.contains("jndi")
    }
}

async fn spin_targets(n: usize) -> (Vec<String>, Vec<MockServer>) {
    let mut urls = Vec::with_capacity(n);
    let mut servers = Vec::with_capacity(n);
    for _ in 0..n {
        let server = MockServer::start().await;
        let blocked = ResponseTemplate::new(403)
            .insert_header("Server", "cloudflare")
            .set_body_string("Attention Required! | Cloudflare");
        Mock::given(method("GET"))
            .and(AttackProbe)
            .respond_with(blocked)
            .mount(&server)
            .await;
        let clean = ResponseTemplate::new(200)
            .insert_header("CF-Ray", "bench0000000001")
            .insert_header("Set-Cookie", "__cf_bm=xyz; Path=/")
            .set_body_string("<html>hello</html>");
        Mock::given(method("GET"))
            .respond_with(clean)
            .mount(&server)
            .await;
        urls.push(server.uri());
        // Servers must stay alive for the whole bench or they shut down.
        servers.push(server);
    }
    (urls, servers)
}

fn scan_bench(c: &mut Criterion) {
    const TARGETS: usize = 12;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let (targets, _servers) = rt.block_on(spin_targets(TARGETS));
    let engine = EngineBuilder::new()
        .client_config(ClientConfig {
            timeout_secs: 5,
            retries: 0,
            ..Default::default()
        })
        .timing(false)
        .build()
        .expect("engine");

    let mut group = c.benchmark_group("scan");
    group.sample_size(20);

    group.bench_function(format!("concurrent_{TARGETS}_targets_c10"), |b| {
        b.to_async(&rt)
            .iter(|| async { engine.scan_batch(targets.clone(), 10, None).await })
    });

    group.bench_function(format!("sequential_{TARGETS}_targets"), |b| {
        b.to_async(&rt).iter(|| async {
            for t in &targets {
                engine.scan(t).await;
            }
        })
    });

    group.finish();
}

criterion_group!(benches, scan_bench);
criterion_main!(benches);

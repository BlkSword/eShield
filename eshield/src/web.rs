use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::state::Stats;

pub async fn run(stats: Arc<Stats>, port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/stats", get(stats_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(stats);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("web dashboard listening on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(serde::Serialize)]
struct StatsResponse {
    total_dropped: u64,
    top_attackers: Vec<Attacker>,
}

#[derive(serde::Serialize)]
struct Attacker {
    ip: String,
    count: u64,
}

async fn index_handler(State(stats): State<Arc<Stats>>) -> Html<String> {
    let total_dropped = stats
        .total_dropped
        .load(std::sync::atomic::Ordering::Relaxed);
    let mut rows = String::new();
    for entry in stats.top_attackers.iter() {
        let ip = Ipv4Addr::from(entry.key().to_be_bytes());
        let count = entry.value().load(std::sync::atomic::Ordering::Relaxed);
        rows.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>\n", ip, count));
    }

    Html(format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>eShield Dashboard</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; }}
    table {{ border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ border: 1px solid #ccc; padding: 0.5rem 1rem; text-align: left; }}
  </style>
</head>
<body>
  <h1>eShield Dashboard</h1>
  <p>Total dropped: <strong>{}</strong></p>
  <h2>Top attackers</h2>
  <table>
    <tr><th>Source IP</th><th>Dropped</th></tr>
    {}
  </table>
  <p><a href="/metrics">Prometheus metrics</a> | <a href="/api/stats">JSON API</a></p>
</body>
</html>"#,
        total_dropped, rows
    ))
}

async fn stats_handler(State(stats): State<Arc<Stats>>) -> Json<StatsResponse> {
    let total_dropped = stats
        .total_dropped
        .load(std::sync::atomic::Ordering::Relaxed);
    let mut top_attackers: Vec<Attacker> = stats
        .top_attackers
        .iter()
        .map(|entry| Attacker {
            ip: Ipv4Addr::from(entry.key().to_be_bytes()).to_string(),
            count: entry.value().load(std::sync::atomic::Ordering::Relaxed),
        })
        .collect();
    top_attackers.sort_by_key(|a| std::cmp::Reverse(a.count));
    top_attackers.truncate(20);
    Json(StatsResponse {
        total_dropped,
        top_attackers,
    })
}

async fn metrics_handler(State(stats): State<Arc<Stats>>) -> Response {
    let total_dropped = stats
        .total_dropped
        .load(std::sync::atomic::Ordering::Relaxed);
    let mut body = format!(
        "# HELP eshield_dropped_total Total dropped packets\n\
         # TYPE eshield_dropped_total counter\n\
         eshield_dropped_total {}\n",
        total_dropped
    );

    for entry in stats.top_attackers.iter() {
        let ip = Ipv4Addr::from(entry.key().to_be_bytes());
        let count = entry.value().load(std::sync::atomic::Ordering::Relaxed);
        body.push_str(&format!(
            "# HELP eshield_source_dropped_total Dropped packets per source IP\n\
             # TYPE eshield_source_dropped_total counter\n\
             eshield_source_dropped_total{{ip=\"{}\"}} {}\n",
            ip, count
        ));
    }

    ([("content-type", "text/plain; charset=utf-8")], body).into_response()
}

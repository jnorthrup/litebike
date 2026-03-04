//! ModelMux - Model Multiplexer

use std::env;
use std::sync::Arc;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)] pub struct Model { id: String, provider: String, free: bool }
#[derive(Debug, Clone, Serialize, Default)] pub struct ProviderQuota { provider: String, remaining_tokens: Option<u64>, is_free: bool }
#[derive(Debug, Clone)] pub struct State { models: Vec<Model>, quotas: Vec<ProviderQuota> }

impl State {
    pub fn new() -> Self {
        let (mut models, mut quotas) = (Vec::new(), Vec::new());
        for (key, _) in env::vars() {
            if key.ends_with("_API_KEY") && !key.contains("_SEARCH_") {
                let p = key.trim_end_matches("_API_KEY").to_lowercase();
                models.push(Model { id: format!("{}/{}-model", p, p), provider: p.clone(), free: true });
                models.push(Model { id: format!("{}/default", p), provider: p.clone(), free: true });
                quotas.push(ProviderQuota { provider: p, remaining_tokens: None, is_free: true });
            }
        }
        Self { models, quotas }
    }
    pub fn select_best(&self) -> Option<&ProviderQuota> {
        self.quotas.iter().filter(|q| q.is_free).min_by(|a, b| b.remaining_tokens.unwrap_or(0).cmp(&a.remaining_tokens.unwrap_or(0)))
    }
}

#[tokio::main] async fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().skip(1).collect();
    let exe_name = env::args().next().unwrap_or_else(|| "modelmux".to_string());
    let exe = std::path::Path::new(&exe_name).file_name().and_then(|s| s.to_str()).unwrap_or("modelmux").to_string();
    let is_agent8888 = exe == "agent8888" || args.iter().any(|a| a == "--agent8888");
    let port: u16 = args.iter().position(|a| a == "--port").and_then(|i| args.get(i+1)).and_then(|p| p.parse().ok()).unwrap_or(if is_agent8888 { 8888 } else { 8889 });
    
    let state = Arc::new(State::new());
    log::info!("ModelMux ({}): {} providers, {} models", exe, state.quotas.len(), state.models.len());
    
    if is_agent8888 || args.iter().any(|a| a == "--serve") { serve_http(port, state).await; }
    else { run_cli(args, state); }
}

async fn serve_http(port: u16, state: Arc<State>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await.expect("bind");
    log::info!("Listening on 0.0.0.0:{}", port);
    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let state = Arc::clone(&state);
        tokio::spawn(async move { handle_conn(stream, state).await; });
    }
}

async fn handle_conn(stream: tokio::net::TcpStream, state: Arc<State>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() { return; }
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() < 2 { return; }
    let method = parts[0].to_string();
    let path = parts[1].to_string();
    loop { line.clear(); if reader.read_line(&mut line).await.is_err() || line.trim().is_empty() { break; } }
    
    let body = match (method.as_str(), path.as_str()) {
        ("GET", "/v1/models") | ("GET", "/models") => serde_json::to_string(&serde_json::json!({
            "object": "list", "data": state.models.iter().map(|m| serde_json::json!({"id": m.id, "owned_by": m.provider})).collect::<Vec<_>>()
        })).unwrap(),
        ("GET", "/health") => serde_json::to_string(&serde_json::json!({
            "status": "ready", "providers": state.quotas.len(), "models": state.models.len(),
            "best_quota": state.select_best().map(|q| serde_json::json!({"provider": q.provider, "free": q.is_free}))
        })).unwrap(),
        ("GET", "/quota") => serde_json::to_string(&serde_json::json!({"quotas": state.quotas, "best": state.select_best()})).unwrap(),
        _ => r#"{"error":"not found"}"#.into(),
    };
    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
    let _ = reader.get_mut().write_all(resp.as_bytes()).await;
}

fn run_cli(args: Vec<String>, state: Arc<State>) {
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("ModelMux\n\nUsage: modelmux [OPTIONS]\n\nOptions:\n  --serve, --port, --agent8888, --list, --quota\n\nBinary: modelmux, agent8888, ollama");
        return;
    }
    if args.iter().any(|a| a == "--list") { println!("Models ({}):", state.models.len()); for m in &state.models { println!("  {} ({})", m.id, if m.free { "free" } else { "paid" }); } }
    else if args.iter().any(|a| a == "--quota") { println!("Quota:"); if let Some(b) = state.select_best() { println!("  Best: {} (free: {})", b.provider, b.is_free); } }
    else { println!("ModelMux ready - Providers: {}, Models: {}", state.quotas.len(), state.models.len()); }
}

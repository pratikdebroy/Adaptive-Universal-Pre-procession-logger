use aegislog_ai_worker::OllamaAiWorker;
use aegislog_engine::models::{OCSFEvent, ParserVariant, TypeConstraint};
use aegislog_engine::pipeline::AegisPipeline;
use aegislog_engine::{MerkleTree, QuarantineManager};
use aegislog_ingestion::{EvidenceVault, IngestionReceiver};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Debug, Serialize, Deserialize)]
struct IngestRequest {
    pub raw_log: String,
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RollbackRequest {
    pub variant_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EngineStats {
    pub total_ingested: usize,
    pub total_parsed: usize,
    pub slm_invocations: usize,
    pub event_quarantine_count: usize,
    pub parser_quarantine_count: usize,
    pub registered_skeletons: usize,
    pub registered_variants: usize,
}

struct AppState {
    pipeline: AegisPipeline,
    receiver: IngestionReceiver,
    quarantine: Arc<QuarantineManager>,
    merkle_tree: Arc<Mutex<MerkleTree>>,
    recent_events: Mutex<VecDeque<OCSFEvent>>,
    total_ingested: Mutex<usize>,
    total_parsed: Mutex<usize>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============================================================");
    println!(" AegisLog Production-Oriented Architectural Prototype");
    println!(" Self-Healing, High-Throughput OCSF Log Pipeline");
    println!("============================================================");

    let data_dir = PathBuf::from("data");
    std::fs::create_dir_all(&data_dir)?;

    let vault = Arc::new(EvidenceVault::new(&data_dir)?);
    let receiver = IngestionReceiver::new(vault);

    let merkle_db = data_dir.join("provenance_ledger.db");
    let merkle_tree = Arc::new(Mutex::new(MerkleTree::new(500, merkle_db)?));

    let quar_db = data_dir.join("quarantine.db");
    let quarantine = Arc::new(QuarantineManager::new(quar_db)?);

    let mut pipeline = AegisPipeline::new(merkle_tree.clone(), quarantine.clone());

    // Connect AI worker for self-healing drift resolution
    let ai_worker = Arc::new(OllamaAiWorker::new("http://localhost:11434", "llama3"));
    pipeline.set_ai_provider(ai_worker);

    // Seed default baseline parser variants for deterministic fast path
    seed_baseline_parsers(&pipeline);

    let state = Arc::new(AppState {
        pipeline,
        receiver,
        quarantine,
        merkle_tree,
        recent_events: Mutex::new(VecDeque::with_capacity(200)),
        total_ingested: Mutex::new(0),
        total_parsed: Mutex::new(0),
    });

    // 1. Spawn Syslog UDP listener on port 5140
    let udp_state = state.clone();
    tokio::spawn(async move {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:5140").await {
            println!("[Syslog UDP] Ingestion listener active on 0.0.0.0:5140");
            let mut buf = [0u8; 65536];
            loop {
                if let Ok((len, src)) = socket.recv_from(&mut buf).await {
                    if let Ok(msg) = std::str::from_utf8(&buf[..len]) {
                        let _ = process_single_log(msg, &src.to_string(), &udp_state).await;
                    }
                }
            }
        }
    });

    // 2. Start HTTP API Server on port 8080
    let http_addr: SocketAddr = "0.0.0.0:8080".parse()?;
    let listener = TcpListener::bind(http_addr).await?;
    println!("[Engine API] HTTP Server listening on http://{}", http_addr);

    loop {
        let (mut stream, _remote) = listener.accept().await?;
        let app_state = state.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 131072]; // 128 KB buffer
            let mut total_read = 0;

            loop {
                let n = match stream.read(&mut buf[total_read..]).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return,
                };
                total_read += n;

                if let Some(header_end) = buf[..total_read].windows(4).position(|w| w == b"\r\n\r\n") {
                    let (method, uri, content_length) = {
                        let headers_str = String::from_utf8_lossy(&buf[..header_end]);
                        let mut lines = headers_str.lines();
                        let req_line = lines.next().unwrap_or("");
                        let mut parts = req_line.split_whitespace();
                        let method = parts.next().unwrap_or("GET").to_string();
                        let uri = parts.next().unwrap_or("/").to_string();

                        let mut cl = 0;
                        for line in lines {
                            let lower = line.to_lowercase();
                            if lower.starts_with("content-length:") {
                                if let Some(val) = line.split(':').nth(1) {
                                    cl = val.trim().parse::<usize>().unwrap_or(0);
                                }
                            }
                        }
                        (method, uri, cl)
                    };

                    let body_start = header_end + 4;
                    let body_needed = body_start + content_length;

                    while total_read < body_needed && total_read < buf.len() {
                        let n = match stream.read(&mut buf[total_read..]).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        total_read += n;
                    }

                    let body = &buf[body_start..total_read.min(body_needed)];
                    let response = handle_http_request(&method, &uri, body, &app_state).await;

                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                    break;
                }
            }
        });
    }
}

async fn handle_http_request(method: &str, uri: &str, body: &[u8], state: &AppState) -> String {
    if method == "OPTIONS" {
        return "HTTP/1.1 204 No Content\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type\r\n\
\r\n"
            .to_string();
    }

    let cors_headers = "Access-Control-Allow-Origin: *\r\nContent-Type: application/json\r\n";

    match (method, uri) {
        ("GET", "/health") => {
            format!(
                "HTTP/1.1 200 OK\r\n{}\r\n{{\"status\":\"healthy\",\"service\":\"aegislog-engine\"}}",
                cors_headers
            )
        }
        ("GET", "/api/stats") => {
            let total_ingested = *state.total_ingested.lock().unwrap();
            let total_parsed = *state.total_parsed.lock().unwrap();
            let slm_invocations = *state.pipeline.slm_invocation_count.lock().unwrap();
            let event_quarantine_count = state.quarantine.event_quarantine_count();
            let parser_quarantine_count = state.quarantine.parser_quarantine_count();
            let (registered_skeletons, registered_variants) = {
                let reg = state.pipeline.registry.lock().unwrap();
                let tree = state.pipeline.bdpt.lock().unwrap();
                (tree.total_skeletons(), reg.total_count())
            };

            let stats = EngineStats {
                total_ingested,
                total_parsed,
                slm_invocations,
                event_quarantine_count,
                parser_quarantine_count,
                registered_skeletons,
                registered_variants,
            };

            let json_body = serde_json::to_string(&stats).unwrap_or_default();
            format!("HTTP/1.1 200 OK\r\n{}\r\n{}", cors_headers, json_body)
        }
        ("POST", "/api/ingest") => {
            let req: IngestRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => {
                    let raw = String::from_utf8_lossy(body).to_string();
                    IngestRequest {
                        raw_log: raw,
                        source: Some("http_raw".to_string()),
                    }
                }
            };

            let source = req.source.unwrap_or_else(|| "127.0.0.1:http".to_string());
            match process_single_log(&req.raw_log, &source, state).await {
                Ok(ocsf) => {
                    let resp = serde_json::json!({
                        "success": true,
                        "event": ocsf
                    });
                    format!("HTTP/1.1 200 OK\r\n{}\r\n{}", cors_headers, resp)
                }
                Err(quar) => {
                    let resp = serde_json::json!({
                        "success": false,
                        "quarantined": true,
                        "details": quar
                    });
                    format!("HTTP/1.1 422 Unprocessable Entity\r\n{}\r\n{}", cors_headers, resp)
                }
            }
        }
        ("GET", "/api/bpt") => {
            let tree = state.pipeline.bdpt.lock().unwrap();
            let leaves = tree.list_all_leaves();
            let json_body = serde_json::to_string(&leaves).unwrap_or_default();
            format!("HTTP/1.1 200 OK\r\n{}\r\n{}", cors_headers, json_body)
        }
        ("GET", "/api/events") => {
            let events = state.recent_events.lock().unwrap();
            let list: Vec<OCSFEvent> = events.iter().cloned().collect();
            let json_body = serde_json::to_string(&list).unwrap_or_default();
            format!("HTTP/1.1 200 OK\r\n{}\r\n{}", cors_headers, json_body)
        }
        ("GET", "/api/quarantine/events") => {
            let entries = state.quarantine.list_event_quarantine(50).unwrap_or_default();
            let json_body = serde_json::to_string(&entries).unwrap_or_default();
            format!("HTTP/1.1 200 OK\r\n{}\r\n{}", cors_headers, json_body)
        }
        ("GET", "/api/quarantine/parsers") => {
            let entries = state.quarantine.list_parser_quarantine(50).unwrap_or_default();
            let json_body = serde_json::to_string(&entries).unwrap_or_default();
            format!("HTTP/1.1 200 OK\r\n{}\r\n{}", cors_headers, json_body)
        }
        ("POST", "/api/registry/rollback") => {
            if let Ok(req) = serde_json::from_slice::<RollbackRequest>(body) {
                let mut reg = state.pipeline.registry.lock().unwrap();
                let success = reg.rollback_variant(&req.variant_id);
                let resp = serde_json::json!({ "success": success });
                format!("HTTP/1.1 200 OK\r\n{}\r\n{}", cors_headers, resp)
            } else {
                format!("HTTP/1.1 400 Bad Request\r\n{}\r\n{{\"error\":\"invalid payload\"}}", cors_headers)
            }
        }
        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
    }
}

async fn process_single_log(
    raw_log: &str,
    source: &str,
    state: &AppState,
) -> Result<OCSFEvent, aegislog_engine::models::EventQuarantineEntry> {
    {
        let mut count = state.total_ingested.lock().unwrap();
        *count += 1;
    }

    let copy = state
        .receiver
        .ingest(raw_log, source)
        .map_err(|e| aegislog_engine::models::EventQuarantineEntry {
            quarantine_id: uuid::Uuid::new_v4().to_string(),
            event_id: uuid::Uuid::new_v4().to_string(),
            raw_sha256: "".to_string(),
            raw_message: raw_log.to_string(),
            failure_reason: format!("Ingestion rejected: {}", e),
            failed_check: "ingestion.size_or_format".to_string(),
            timestamp: chrono::Utc::now(),
        })?;

    let result = state.pipeline.process_event(copy).await;

    if let Ok(ref event) = result {
        let mut count = state.total_parsed.lock().unwrap();
        *count += 1;

        let mut events = state.recent_events.lock().unwrap();
        if events.len() >= 200 {
            events.pop_front();
        }
        events.push_back(event.clone());
    }

    result
}

fn seed_baseline_parsers(pipeline: &AegisPipeline) {
    let skel_fw = "SRC=<VAR> DST=<VAR> DPT=<VAR> ACTION=<VAR>";
    let v_fw = ParserVariant::new(
        "var_fw_standard",
        "Standard Firewall Variant",
        r"^SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+DPT=(?P<port>\d+)\s+ACTION=(?P<act>\S+)$",
        HashMap::from([
            ("src".into(), "src_endpoint.ip".into()),
            ("dst".into(), "dst_endpoint.ip".into()),
            ("port".into(), "src_endpoint.port".into()),
            ("act".into(), "action".into()),
        ]),
        HashMap::from([
            ("src".into(), "ip".into()),
            ("dst".into(), "ip".into()),
            ("port".into(), "port".into()),
            ("act".into(), "string".into()),
        ]),
        TypeConstraint::IpAddress,
    )
    .unwrap();

    pipeline.registry.lock().unwrap().register_variant(skel_fw, v_fw.clone());
    pipeline.bdpt.lock().unwrap().insert(skel_fw, Some(v_fw));

    let skel_auth = "USER=<VAR> HOST=<VAR> STATUS=<VAR>";
    let v_auth = ParserVariant::new(
        "var_auth_standard",
        "Authentication Login Variant",
        r"^USER=(?P<user>\S+)\s+HOST=(?P<host>\S+)\s+STATUS=(?P<status>\S+)$",
        HashMap::from([
            ("user".into(), "actor.user.name".into()),
            ("host".into(), "device.hostname".into()),
            ("status".into(), "action".into()),
        ]),
        HashMap::from([
            ("user".into(), "string".into()),
            ("host".into(), "string".into()),
            ("status".into(), "string".into()),
        ]),
        TypeConstraint::GenericString,
    )
    .unwrap();

    pipeline.registry.lock().unwrap().register_variant(skel_auth, v_auth.clone());
    pipeline.bdpt.lock().unwrap().insert(skel_auth, Some(v_auth));
}

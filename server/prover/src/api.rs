//! The HTTP API (spec §6), admission (spec §4, §7) and the job queue.
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Semaphore};

use crate::config::Config;
use crate::pipeline::{self, BridgeOutput};
use crate::rpc::{short_string, Rpc};
use crate::statement::{Submission, SubmissionJson};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    Queued,
    Running,
    Done,
    Failed,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Status::Queued => "queued",
            Status::Running => "running",
            Status::Done => "done",
            Status::Failed => "failed",
        }
    }
}

struct Job {
    status: Status,
    stage: String,
    created: Instant,
    finished: Option<Instant>,
    submission: Option<Submission>,
    bridge: Option<BridgeOutput>,
    result: Option<Value>,
    error: Option<String>,
    dedup_key: String,
    address_key: String,
    dir: PathBuf,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

struct Refusal {
    count: u32,
    until: Instant,
}

pub struct AppState {
    pub config: Config,
    pub rpc: Rpc,
    pub info: Value,
    jobs: Mutex<HashMap<String, Job>>,
    order: Mutex<VecDeque<String>>,
    dedup: Mutex<HashMap<String, String>>,
    refusals: Mutex<HashMap<String, Refusal>>,
    buckets: Mutex<HashMap<String, Bucket>>,
    checks: Semaphore,
    queue: mpsc::Sender<String>,
}

type Reply = (StatusCode, Json<Value>);

fn err(code: StatusCode, msg: impl Into<String>) -> Reply {
    (code, Json(json!({"error": msg.into()})))
}

/// The rate-limit key: the IPv4 address, or the IPv6 /64.
fn address_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

fn client_ip(state: &AppState, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if state.config.server.trust_forwarded_for {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

pub fn router(state: Arc<AppState>) -> Router {
    let limit = state.config.server.max_body_bytes;
    Router::new()
        .route("/v1/jobs", post(submit))
        .route("/v1/jobs/{id}", get(status))
        .route("/v1/info", get(info))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

async fn info(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.info.clone())
}

async fn submit(State(state): State<Arc<AppState>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap,
                body: axum::body::Bytes) -> Reply {
    let key = address_key(client_ip(&state, peer, &headers));
    // Rate limit: a token bucket per address key, refilled over the hour.
    {
        let rate = state.config.limits.submissions_per_hour as f64;
        let mut buckets = state.buckets.lock().unwrap();
        let b = buckets.entry(key.clone()).or_insert(Bucket { tokens: rate, updated: Instant::now() });
        let now = Instant::now();
        b.tokens = (b.tokens + now.duration_since(b.updated).as_secs_f64() * rate / 3600.0).min(rate);
        b.updated = now;
        if b.tokens < 1.0 {
            return err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
        }
        b.tokens -= 1.0;
    }
    {
        let jobs = state.jobs.lock().unwrap();
        let queued = jobs.values().filter(|j| j.address_key == key && matches!(j.status, Status::Queued | Status::Running)).count();
        if queued >= state.config.limits.queued_per_address {
            return err(StatusCode::TOO_MANY_REQUESTS, "too many jobs in progress from this address");
        }
        if jobs.values().filter(|j| j.status == Status::Queued).count() >= state.config.server.queue_capacity {
            return err(StatusCode::SERVICE_UNAVAILABLE, "queue full");
        }
    }
    // 1. Size and encoding.
    let parsed: SubmissionJson = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "malformed body"),
    };
    let sub = match Submission::parse(parsed, state.config.server.max_proof_felts) {
        Ok(s) => s,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    let Some(rel) = state.config.relation(sub.relation.name()).cloned() else {
        return err(StatusCode::BAD_REQUEST, "relation not served");
    };
    // 2. Configuration match.
    let chain_ok = short_string(&state.config.network.chain_id).map(|c| c == sub.chain).unwrap_or(false);
    let pool_ok = crate::rpc::felt(&state.config.network.pool).map(|p| p == sub.pool).unwrap_or(false);
    if !chain_ok || !pool_ok {
        return err(StatusCode::BAD_REQUEST, "chain or pool not served");
    }
    // 3. Work deduplication and backoff.
    let dkey = sub.dedup_key();
    {
        let mut refusals = state.refusals.lock().unwrap();
        if let Some(r) = refusals.get(&dkey) {
            if Instant::now() < r.until {
                return err(StatusCode::TOO_MANY_REQUESTS, "this note was submitted recently; retry later");
            }
        }
        let dedup = state.dedup.lock().unwrap();
        if dedup.contains_key(&dkey) {
            let r = refusals.entry(dkey.clone()).or_insert(Refusal { count: 0, until: Instant::now() });
            r.count += 1;
            r.until = Instant::now() + Duration::from_secs(state.config.limits.duplicate_backoff_secs << r.count.min(10));
            return err(StatusCode::CONFLICT, "a job for this note is already queued, running or done");
        }
    }
    // 4. Chain state.
    if let Err(e) = pipeline::chain_state(&state.rpc, &state.config, &sub).await {
        return err(StatusCode::CONFLICT, format!("{e:#}"));
    }
    // 5. The bridge, in a child process.
    let id = format!("{:032x}", rand::random::<u128>());
    let dir = state.config.server.data_dir.join(&id);
    if std::fs::create_dir_all(&dir).is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "job directory");
    }
    let bridge = {
        let _permit = state.checks.acquire().await;
        pipeline::check(&state.config, &rel, &sub, &dir, &id).await
    };
    let bridge = match bridge {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return err(StatusCode::BAD_REQUEST, format!("{e:#}"));
        }
    };
    {
        let mut dedup = state.dedup.lock().unwrap();
        if dedup.contains_key(&dkey) {
            let _ = std::fs::remove_dir_all(&dir);
            return err(StatusCode::CONFLICT, "a job for this note is already queued, running or done");
        }
        dedup.insert(dkey.clone(), id.clone());
        state.jobs.lock().unwrap().insert(id.clone(), Job {
            status: Status::Queued, stage: "queued".into(), created: Instant::now(), finished: None, submission: Some(sub),
            bridge: Some(bridge), result: None, error: None, dedup_key: dkey, address_key: key, dir,
        });
        state.order.lock().unwrap().push_back(id.clone());
    }
    if state.queue.try_send(id.clone()).is_err() {
        return err(StatusCode::SERVICE_UNAVAILABLE, "queue full");
    }
    let position = state.order.lock().unwrap().iter().position(|x| *x == id).unwrap_or(0);
    tracing::info!(job = %id, "admitted");
    (StatusCode::ACCEPTED, Json(json!({"id": id, "position": position})))
}

async fn status(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Reply {
    let jobs = state.jobs.lock().unwrap();
    let Some(j) = jobs.get(&id) else {
        return err(StatusCode::NOT_FOUND, "no such job");
    };
    let position = state.order.lock().unwrap().iter().position(|x| *x == id);
    (StatusCode::OK, Json(json!({
        "id": id, "status": j.status.name(), "stage": j.stage, "position": position,
        "result": j.result, "error": j.error,
    })))
}

/// Creates the state, the worker pool and the retention sweeper.
pub fn start(config: Config, rpc: Rpc, info: Value) -> Arc<AppState> {
    let (tx, rx) = mpsc::channel::<String>(config.server.queue_capacity.max(1) * 4);
    let state = Arc::new(AppState {
        info, rpc, jobs: Mutex::new(HashMap::new()), order: Mutex::new(VecDeque::new()), dedup: Mutex::new(HashMap::new()),
        refusals: Mutex::new(HashMap::new()), buckets: Mutex::new(HashMap::new()), checks: Semaphore::new(2), queue: tx,
        config,
    });
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    for _ in 0..state.config.server.max_concurrent_jobs {
        let (state, rx) = (state.clone(), rx.clone());
        tokio::spawn(async move {
            loop {
                let Some(id) = rx.lock().await.recv().await else { return };
                work(&state, &id).await;
            }
        });
    }
    let sweeper = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            sweep(&sweeper);
        }
    });
    state
}

async fn work(state: &Arc<AppState>, id: &str) {
    let (sub, bridge, dir) = {
        let mut jobs = state.jobs.lock().unwrap();
        let Some(j) = jobs.get_mut(id) else { return };
        j.status = Status::Running;
        j.stage = "starting".into();
        (j.submission.clone().unwrap(), j.bridge.clone().unwrap(), j.dir.clone())
    };
    state.order.lock().unwrap().retain(|x| x != id);
    let rel = state.config.relation(sub.relation.name()).unwrap().clone();
    let st = state.clone();
    let idc = id.to_string();
    let stage = move |s: &str| {
        if let Some(j) = st.jobs.lock().unwrap().get_mut(&idc) {
            j.stage = s.to_string();
        }
    };
    let outcome = pipeline::run(&state.config, &state.rpc, &rel, &sub, &bridge, &dir, id, &stage).await;
    let mut jobs = state.jobs.lock().unwrap();
    let Some(j) = jobs.get_mut(id) else { return };
    j.finished = Some(Instant::now());
    j.submission = None;
    match outcome {
        Ok(r) => {
            j.status = Status::Done;
            j.stage = "done".into();
            j.result = Some(r.value);
            tracing::info!(job = %id, "done");
        }
        Err(e) => {
            j.status = Status::Failed;
            j.error = Some(format!("{e:#}"));
            // A failed job does not count for deduplication: a retry is allowed.
            state.dedup.lock().unwrap().remove(&j.dedup_key);
            tracing::info!(job = %id, stage = %j.stage, "failed");
        }
    }
}

/// Deletes finished jobs past retention with their directories, and expired refusals and buckets.
fn sweep(state: &Arc<AppState>) {
    let retention = Duration::from_secs(state.config.server.retention_secs);
    let now = Instant::now();
    let mut jobs = state.jobs.lock().unwrap();
    let expired: Vec<String> = jobs
        .iter()
        .filter(|(_, j)| j.finished.map(|f| now.duration_since(f) > retention).unwrap_or(false) || now.duration_since(j.created) > retention * 4)
        .filter(|(_, j)| !matches!(j.status, Status::Running))
        .map(|(id, _)| id.clone())
        .collect();
    let mut dedup = state.dedup.lock().unwrap();
    for id in expired {
        if let Some(j) = jobs.remove(&id) {
            let _ = std::fs::remove_dir_all(&j.dir);
            if dedup.get(&j.dedup_key) == Some(&id) {
                dedup.remove(&j.dedup_key);
            }
        }
    }
    state.refusals.lock().unwrap().retain(|_, r| r.until > now);
    state.buckets.lock().unwrap().retain(|_, b| now.duration_since(b.updated) < Duration::from_secs(3600));
}

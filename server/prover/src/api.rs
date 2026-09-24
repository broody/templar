//! The HTTP API (spec §6), admission (spec §4, §7) and the job queue.
//!
//! All job state (jobs, queue order, deduplication, refusals) sits behind one mutex, so there is no
//! lock order to get wrong (PI-1); the rate-limit buckets have their own and are never held with it.
//! No lock is held across an await.
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
    finished: Option<Instant>,
    submission: Option<Submission>,
    bridge: Option<BridgeOutput>,
    result: Option<Value>,
    error: Option<String>,
    dedup_key: String,
    address_key: String,
    dir: PathBuf,
}

struct Refusal {
    count: u32,
    until: Instant,
}

#[derive(Default)]
struct Registry {
    jobs: HashMap<String, Job>,
    order: VecDeque<String>,
    /// Note key → the job holding it (queued, running or done).
    dedup: HashMap<String, String>,
    refusals: HashMap<String, Refusal>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

pub struct AppState {
    pub config: Config,
    pub rpc: Rpc,
    pub info: Value,
    registry: Mutex<Registry>,
    buckets: Mutex<HashMap<String, Bucket>>,
    checks: Arc<Semaphore>,
    queue: mpsc::Sender<String>,
}

type Reply = (StatusCode, Json<Value>);

fn err(code: StatusCode, msg: impl Into<String>) -> Reply {
    (code, Json(json!({"error": msg.into()})))
}

/// The rate-limit key: the IPv4 address (IPv4-mapped IPv6 included), or the IPv6 /64 (PI-4).
pub fn address_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = a.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// The client address. Behind a trusted proxy, the proxy appends the address it saw as the last
/// `X-Forwarded-For` entry; anything to its left came from the client and is ignored (PI-4).
pub fn client_ip(trust_forwarded_for: bool, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if trust_forwarded_for {
        if let Some(ip) = headers
            .get_all("x-forwarded-for")
            .iter()
            .last()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

pub fn router(state: Arc<AppState>, ohttp: Option<Arc<crate::ohttp::OhttpState>>) -> Router {
    let limit = state.config.server.max_body_bytes;
    let router = Router::new()
        .route("/v1/jobs", post(submit))
        .route("/v1/jobs/{id}", get(status))
        .route("/v1/info", get(info))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state);
    match ohttp {
        // The middleware wraps the whole router (as its fallback), so it sees every path, and a
        // decapsulated request is routed afresh by the inner router.
        Some(o) => Router::new().fallback_service(router).layer(axum::middleware::from_fn_with_state(o, crate::ohttp::middleware)),
        None => router,
    }
}

async fn info(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.info.clone())
}

async fn submit(State(state): State<Arc<AppState>>, ConnectInfo(peer): ConnectInfo<SocketAddr>,
                ohttp: Option<axum::Extension<crate::ohttp::Ohttp>>, headers: HeaderMap, body: axum::body::Bytes) -> Reply {
    // Over OHTTP the peer is the relay: its clients share one larger bucket and no per-address
    // queue cap (spec §7); per-note deduplication applies regardless.
    let via_relay = ohttp.is_some();
    let key = if via_relay {
        format!("relay:{}", address_key(peer.ip()))
    } else {
        address_key(client_ip(state.config.server.trust_forwarded_for, peer, &headers))
    };
    {
        let rate = match (&state.config.ohttp, via_relay) {
            (Some(o), true) => o.submissions_per_hour_per_relay as f64,
            _ => state.config.limits.submissions_per_hour as f64,
        };
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
        let reg = state.registry.lock().unwrap();
        let active = |j: &&Job| matches!(j.status, Status::Queued | Status::Running);
        if !via_relay && reg.jobs.values().filter(active).filter(|j| j.address_key == key).count() >= state.config.limits.queued_per_address {
            return err(StatusCode::TOO_MANY_REQUESTS, "too many jobs in progress from this address");
        }
        if reg.jobs.values().filter(|j| j.status == Status::Queued).count() >= state.config.server.queue_capacity {
            return err(StatusCode::SERVICE_UNAVAILABLE, "queue full");
        }
    }
    // 1. Size and encoding.
    let Ok(parsed) = serde_json::from_slice::<SubmissionJson>(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed body");
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
        let mut reg = state.registry.lock().unwrap();
        let now = Instant::now();
        if reg.refusals.get(&dkey).is_some_and(|r| now < r.until) {
            return err(StatusCode::TOO_MANY_REQUESTS, "this note was submitted recently; retry later");
        }
        if reg.dedup.contains_key(&dkey) {
            let backoff = state.config.limits.duplicate_backoff_secs;
            let r = reg.refusals.entry(dkey.clone()).or_insert(Refusal { count: 0, until: now });
            r.count += 1;
            r.until = now + Duration::from_secs(backoff << r.count.min(10));
            return err(StatusCode::CONFLICT, "a job for this note is already queued, running or done");
        }
    }
    // 4. Chain state.
    if let Err(e) = pipeline::chain_state(&state.rpc, &state.config, &sub).await {
        return err(StatusCode::CONFLICT, format!("{e:#}"));
    }
    // 5. The bridge, in a child process. It runs in its own task, so a client that disconnects
    // does not cancel it half-way: it finishes and cleans up (PI-2). At most the configured number
    // run at once; beyond that the submission is refused rather than queued unboundedly (PI-11).
    let Ok(permit) = state.checks.clone().try_acquire_owned() else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "pre-checks busy; retry shortly");
    };
    let id = format!("{:032x}", rand::random::<u128>());
    let dir = state.config.server.data_dir.join(&id);
    if std::fs::create_dir_all(&dir).is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "job directory");
    }
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<usize, Reply>>();
    {
        let (state, rel, sub, dir, id) = (state.clone(), rel.clone(), sub.clone(), dir.clone(), id.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let out = pipeline::check(&state.config, &rel, &sub, &dir, &id).await;
            let reply = match out {
                // A client that went away gets no job: nobody could collect the result.
                Ok(_) if tx.is_closed() => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return;
                }
                Ok(bridge) => admit(&state, id, sub, bridge, dkey, key, dir),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    Err(err(StatusCode::BAD_REQUEST, format!("{e:#}")))
                }
            };
            let _ = tx.send(reply);
        });
    }
    match rx.await {
        Ok(Ok(position)) => (StatusCode::ACCEPTED, Json(json!({"id": id, "position": position}))),
        Ok(Err(reply)) => reply,
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "pre-check task failed"),
    }
}

/// Records an accepted submission and queues it; on any refusal, removes what it created (PI-8).
fn admit(state: &Arc<AppState>, id: String, sub: Submission, bridge: BridgeOutput, dkey: String, key: String, dir: PathBuf)
         -> Result<usize, Reply> {
    let mut reg = state.registry.lock().unwrap();
    if reg.dedup.contains_key(&dkey) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(err(StatusCode::CONFLICT, "a job for this note is already queued, running or done"));
    }
    if state.queue.try_send(id.clone()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "queue full"));
    }
    reg.dedup.insert(dkey.clone(), id.clone());
    reg.jobs.insert(id.clone(), Job {
        status: Status::Queued, stage: "queued".into(), finished: None, submission: Some(sub),
        bridge: Some(bridge), result: None, error: None, dedup_key: dkey, address_key: key, dir,
    });
    reg.order.push_back(id.clone());
    tracing::info!(job = %id, "admitted");
    Ok(reg.order.len() - 1)
}

async fn status(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Reply {
    let reg = state.registry.lock().unwrap();
    let Some(j) = reg.jobs.get(&id) else {
        return err(StatusCode::NOT_FOUND, "no such job");
    };
    let position = reg.order.iter().position(|x| *x == id);
    (StatusCode::OK, Json(json!({
        "id": id, "status": j.status.name(), "stage": j.stage, "position": position,
        "result": j.result, "error": j.error,
    })))
}

/// Creates the state, the worker pool and the retention sweeper.
pub fn start(config: Config, rpc: Rpc, info: Value) -> Arc<AppState> {
    let (tx, rx) = mpsc::channel::<String>(config.server.queue_capacity.max(1) * 4);
    let state = Arc::new(AppState {
        info, rpc, registry: Mutex::new(Registry::default()), buckets: Mutex::new(HashMap::new()),
        checks: Arc::new(Semaphore::new(config.server.max_concurrent_checks)), queue: tx, config,
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
        let mut reg = state.registry.lock().unwrap();
        reg.order.retain(|x| x != id);
        let Some(j) = reg.jobs.get_mut(id) else { return };
        j.status = Status::Running;
        j.stage = "starting".into();
        (j.submission.clone().unwrap(), j.bridge.clone().unwrap(), j.dir.clone())
    };
    let rel = state.config.relation(sub.relation.name()).unwrap().clone();
    let st = state.clone();
    let idc = id.to_string();
    let stage = move |s: &str| {
        if let Some(j) = st.registry.lock().unwrap().jobs.get_mut(&idc) {
            j.stage = s.to_string();
        }
    };
    let outcome = pipeline::run(&state.config, &state.rpc, &rel, &sub, &bridge, &dir, id, &stage).await;
    let mut reg = state.registry.lock().unwrap();
    let Some(j) = reg.jobs.get_mut(id) else { return };
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
            tracing::info!(job = %id, stage = %j.stage, "failed");
            // A failed job does not count for deduplication: a retry is allowed.
            let key = j.dedup_key.clone();
            reg.dedup.remove(&key);
        }
    }
}

/// Deletes finished jobs past retention with their directories, and expired refusals and buckets.
fn sweep(state: &Arc<AppState>) {
    let retention = Duration::from_secs(state.config.server.retention_secs);
    let now = Instant::now();
    let dirs: Vec<PathBuf> = {
        let mut reg = state.registry.lock().unwrap();
        let expired: Vec<String> = reg
            .jobs
            .iter()
            .filter(|(_, j)| !matches!(j.status, Status::Running | Status::Queued))
            .filter(|(_, j)| j.finished.map(|f| now.duration_since(f) > retention).unwrap_or(false))
            .map(|(id, _)| id.clone())
            .collect();
        let mut dirs = vec![];
        for id in expired {
            if let Some(j) = reg.jobs.remove(&id) {
                if reg.dedup.get(&j.dedup_key) == Some(&id) {
                    reg.dedup.remove(&j.dedup_key);
                }
                dirs.push(j.dir);
            }
        }
        reg.refusals.retain(|_, r| r.until > now);
        dirs
    };
    for d in dirs {
        let _ = std::fs::remove_dir_all(d);
    }
    state.buckets.lock().unwrap().retain(|_, b| now.duration_since(b.updated) < Duration::from_secs(3600));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn address_keys() {
        assert_eq!(address_key("1.2.3.4".parse().unwrap()), "1.2.3.4");
        // IPv4 on a dual-stack listener arrives IPv4-mapped; it keeps its own bucket.
        assert_eq!(address_key("::ffff:1.2.3.4".parse().unwrap()), "1.2.3.4");
        assert_ne!(address_key("::ffff:1.2.3.4".parse().unwrap()), address_key("::ffff:1.2.3.5".parse().unwrap()));
        assert_eq!(address_key("2001:db8:1:2:3:4:5:6".parse().unwrap()), "2001:db8:1:2::/64");
        assert_eq!(address_key("2001:db8:1:2:ffff::1".parse().unwrap()), address_key("2001:db8:1:2::9".parse().unwrap()));
    }

    #[test]
    fn forwarded_for_takes_the_proxys_entry() {
        let peer: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6, 1.2.3.4"));
        assert_eq!(client_ip(true, peer, &h), "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(false, peer, &h), peer.ip());
        h.append("x-forwarded-for", HeaderValue::from_static("5.5.5.5"));
        assert_eq!(client_ip(true, peer, &h), "5.5.5.5".parse::<IpAddr>().unwrap());
    }
}

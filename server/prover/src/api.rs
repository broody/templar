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
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use sha2::Digest;
use tokio::sync::{mpsc, Semaphore};

use crate::config::Config;
use crate::pipeline::{self, BridgeOutput};
use crate::rpc::{short_string, Rpc};
use crate::statement::{Submission, SubmissionJson};
use crate::tickets::{self, PaymentJson, Reservation, Ticket, Tickets};
use starknet_types_core::felt::Felt;

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Reserved tickets that return to their holder unless the admission takes or consumes them
/// (spec §9, ticket states): every early refusal releases them by dropping the guard.
struct Held {
    tickets: Option<Arc<Tickets>>,
    reservation: Option<Reservation>,
}

impl Held {
    /// A bridge rejection or a calldata mismatch keeps them spent (spec §9 step 7). If the spend
    /// cannot be synced, the tickets stay held (never released), the ledger takes no new
    /// reservation until its log is writable, and then spends them first (AB-SM5, recheck N6).
    fn consume(mut self) {
        if let (Some(t), Some(r)) = (&self.tickets, self.reservation.take()) {
            t.consume(&r);
        }
    }
    fn take(mut self) -> Option<Reservation> {
        self.reservation.take()
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let (Some(t), Some(r)) = (&self.tickets, self.reservation.take()) {
            t.release(&r);
        }
    }
}

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
    /// sha256 of the submission body: an identical resubmission gets the same job (PI-13).
    body_hash: [u8; 32],
    address_key: String,
    dir: PathBuf,
    /// The last block the result may land in (`valid_until` for R0 V4 and P1, `send_deadline` for
    /// R0 V5); the note is released after it.
    deadline: Option<u64>,
    /// The job's tickets, and whether job start spent them.
    reservation: Option<Reservation>,
    spent: bool,
    /// Replacement tickets for a job the server failed (blind signatures on the job's requests).
    refund: Option<Value>,
    /// A free full withdrawal (the low-priority queue).
    free: bool,
    /// The relayer's answer, shown to the client (account-bound spec §7.3, AB-P31): `pending`,
    /// `submitted` with the transaction hash, `refused` with the reason, or `expired`.
    relay: Option<Value>,
}

/// A finished R0 V5 result waiting for the relayer (P4b handoff). It is kept apart from the job's
/// result, so the client's acknowledgement never takes it from the relayer, and it goes when the
/// relayer reports or its deadline passes.
struct RelayItem {
    result: Value,
    nullifiers: Vec<Vec<String>>,
    root: Vec<String>,
    deadline: u64,
    /// The relayer claimed it before sending: it is no longer refused for lateness (AB-RL9).
    claimed: bool,
}

struct Refusal {
    count: u32,
    until: Instant,
}

#[derive(Default)]
struct Registry {
    jobs: HashMap<String, Job>,
    /// Body hash → job id, for the identical-resubmission lookup (SDK-IP19).
    by_body: HashMap<[u8; 32], String>,
    order: VecDeque<String>,
    /// Note key → the job holding it (queued, running or done).
    dedup: HashMap<String, String>,
    refusals: HashMap<String, Refusal>,
    /// Job id → result waiting for the relayer.
    relay: HashMap<String, RelayItem>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn full(rate: f64, now: Instant) -> Bucket {
        Bucket { tokens: rate, updated: now }
    }
    /// Refills at `rate` per hour; whether one token is there.
    fn ready(&mut self, rate: f64, now: Instant) -> bool {
        self.tokens = (self.tokens + now.duration_since(self.updated).as_secs_f64() * rate / 3600.0).min(rate);
        self.updated = now;
        self.tokens >= 1.0
    }
}

/// The free full withdrawals' allowances and prover share (spec §7.2). Debited only once a job
/// passed the bridge and the calldata match (AB-SP2).
#[derive(Default)]
struct FreeState {
    /// All free jobs, per hour.
    bucket: Option<Bucket>,
    /// Per address bucket (relays are bound by the global bucket only).
    addresses: HashMap<String, Bucket>,
    /// When free jobs finished and the prover seconds they took, over the last hour (AB-SP3).
    ran: VecDeque<(Instant, f64)>,
}

pub struct AppState {
    pub config: Config,
    pub rpc: Rpc,
    pub info: Value,
    pub tickets: Option<Arc<Tickets>>,
    registry: Mutex<Registry>,
    buckets: Mutex<HashMap<String, Bucket>>,
    checks: Arc<Semaphore>,
    queue: mpsc::Sender<String>,
    /// Free full withdrawals: their own queue, never ahead of a paid job (spec §7.2).
    free_queue: mpsc::Sender<String>,
    free: Mutex<FreeState>,
    /// The latest block number and when it was read (the lookup reads it at most every 10 s).
    latest: Mutex<Option<(Instant, u64)>>,
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

/// Whether `ip` is the address or inside the CIDR block `block` (`a.b.c.d`, `a.b.c.d/n`, IPv6 alike).
pub fn in_block(ip: IpAddr, block: &str) -> bool {
    let (addr, bits) = match block.split_once('/') {
        Some((a, n)) => (a, n.parse::<u32>().ok()),
        None => (block, None),
    };
    let Ok(net) = addr.trim().parse::<IpAddr>() else { return false };
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let n = bits.unwrap_or(32).min(32);
            let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let n = bits.unwrap_or(128).min(128);
            let mask = if n == 0 { 0 } else { u128::MAX << (128 - n) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
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
        .route("/v1/jobs/{id}", delete(acknowledge))
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
    // Relay treatment only for configured relays (PI-12); behind a proxy, the relay's address is
    // the proxy's entry.
    let ip = client_ip(state.config.server.trust_forwarded_for, peer, &headers);
    let via_relay = ohttp.is_some() && state.config.ohttp.as_ref().is_some_and(|o| o.relays.iter().any(|r| in_block(ip, r)));
    let key = if via_relay { format!("relay:{}", address_key(ip)) } else { address_key(ip) };
    let body_hash: [u8; 32] = sha2::Sha256::digest(&body).into();
    // An identical resubmission (a client that lost the admission reply, or re-wrapping after its
    // result's window passed) is answered before any rate or queue check spends anything
    // (docs/sdk-spec.md §8, SDK-P3, SDK-IP15).
    if let Some(reply) = existing_job(&state, &body_hash).await {
        return reply;
    }
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
    }
    // 1. Size and encoding.
    let Ok(parsed) = serde_json::from_slice::<SubmissionJson>(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed body");
    };
    let payment = parsed.payment.clone();
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
    // 3. Payment (spec §7.2, §9): tickets verified locally and reserved, or the free full
    // withdrawal's check routing the job to the free queue. Before any proving or account call.
    let mut held = Held { tickets: state.tickets.clone(), reservation: None };
    let mut free = false;
    if let Some(t) = &state.tickets {
        let cost = t.cost(&sub);
        match payment.as_ref().map(tickets::parse_payment).transpose() {
            Err(e) => return err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            Ok(None) if t.config.required => return err(StatusCode::PAYMENT_REQUIRED, format!("this job costs {cost} ticket(s)")),
            Ok(None) => {}
            Ok(Some(PaymentJson::Tickets { tickets, refund_requests })) => {
                let parsed: anyhow::Result<Vec<Ticket>> = tickets.iter().map(Ticket::parse).collect();
                let requests = tickets::decode_requests(&refund_requests);
                let (ts, requests) = match (parsed, requests) {
                    (Ok(ts), Ok(r)) => (ts, r),
                    (Err(e), _) | (_, Err(e)) => return err(StatusCode::BAD_REQUEST, format!("{e:#}")),
                };
                if ts.len() != cost as usize {
                    return err(StatusCode::PAYMENT_REQUIRED, format!("this job costs {cost} ticket(s), not {}", ts.len()));
                }
                match t.reserve(&ts, requests, unix_now()) {
                    Ok(r) => held.reservation = Some(r),
                    Err(e) => return err(StatusCode::PAYMENT_REQUIRED, format!("{e:#}")),
                }
            }
            Ok(Some(PaymentJson::FreeFullWithdrawal { free_full_withdrawal })) => {
                if let Err(e) = t.free_full_withdrawal(&sub, &free_full_withdrawal.openings) {
                    return err(StatusCode::PAYMENT_REQUIRED, format!("{e:#}"));
                }
                let queued = state.registry.lock().unwrap().jobs.values().filter(|j| j.free && j.status == Status::Queued).count();
                if queued >= t.config.free.queue_capacity {
                    return err(StatusCode::SERVICE_UNAVAILABLE, "the free queue is full; retry later or pay one ticket");
                }
                // Only looked at here; debited once the job passed every check (AB-SP2).
                if let Err(reply) = free_allowance(&state, t, &key, via_relay, false) {
                    return reply;
                }
                free = true;
            }
        }
    }
    // Paid capacity: free jobs have their own queue and never count against it (AB-SP3).
    if !free {
        let reg = state.registry.lock().unwrap();
        if reg.jobs.values().filter(|j| j.status == Status::Queued && !j.free).count() >= state.config.server.queue_capacity {
            return err(StatusCode::SERVICE_UNAVAILABLE, "queue full");
        }
    }
    // 4. Work deduplication and backoff.
    let dkey = sub.dedup_key();
    // A finished job whose proof is past its `valid_until` can no longer be submitted, so it stops
    // holding its note (docs/sdk-spec.md §8, SDK-P3). The job itself is kept until retention.
    let stale = {
        let reg = state.registry.lock().unwrap();
        reg.dedup.get(&dkey).and_then(|id| {
            let j = reg.jobs.get(id)?;
            let until = j.deadline?;
            matches!(j.status, Status::Done).then(|| (id.clone(), until))
        })
    };
    if let Some((id, until)) = stale {
        if state.rpc.block_number().await.is_ok_and(|latest| latest > until) {
            let mut reg = state.registry.lock().unwrap();
            if reg.dedup.get(&dkey) == Some(&id) {
                reg.dedup.remove(&dkey);
                reg.refusals.remove(&dkey);
            }
        }
    }
    {
        let mut reg = state.registry.lock().unwrap();
        let now = Instant::now();
        if reg.refusals.get(&dkey).is_some_and(|r| now < r.until) {
            return err(StatusCode::TOO_MANY_REQUESTS, "this note was submitted recently; retry later");
        }
        if reg.refusals.get(&body_key(&body_hash)).is_some_and(|r| now < r.until) {
            return err(StatusCode::TOO_MANY_REQUESTS, "this submission failed its pre-check recently; retry later");
        }
        if reg.dedup.contains_key(&dkey) {
            let backoff = state.config.limits.duplicate_backoff_secs;
            let r = reg.refusals.entry(dkey.clone()).or_insert(Refusal { count: 0, until: now });
            r.count += 1;
            r.until = now + Duration::from_secs(backoff << r.count.min(10));
            return err(StatusCode::CONFLICT, "a job for this note is already queued, running or done");
        }
    }
    // 5. Expiry (R0 V5, spec §9 step 5): room for the queue, the proof and the relay.
    let latest = match (&sub.v5, latest_block(&state).await) {
        (None, l) => l,
        (Some(_), Some(l)) => Some(l),
        (Some(_), None) => return err(StatusCode::SERVICE_UNAVAILABLE, "the node did not answer; retry"),
    };
    if let (Some(j), Some(latest)) = (&sub.v5, latest) {
        // Per queue (AB-SP3): a paid job waits behind queued paid jobs and the running ones; a free
        // job behind every queued job, and later paid jobs still go first (free is best-effort).
        let ahead = {
            let reg = state.registry.lock().unwrap();
            let running = reg.jobs.values().filter(|j| j.status == Status::Running).count();
            running + reg.jobs.values().filter(|j| j.status == Status::Queued && (free || !j.free)).count()
        };
        if let Err(e) = pipeline::expiry_admits(&state.config, j.statement.valid_until, latest, ahead) {
            return err(StatusCode::BAD_REQUEST, format!("{e:#}"));
        }
        if let Err(e) = pipeline::pool_rules(&state.config, &sub, latest) {
            return err(StatusCode::BAD_REQUEST, format!("{e:#}"));
        }
    }
    // 6. Chain state: the root, the nullifiers, and for R0 V5 the root at the deadline (AB-PV6);
    // the verifier and no change of it due (AB-SP1); an invoke's pool state (AB-SP7).
    if let Err(e) = pipeline::chain_state(&state.rpc, &state.config, &sub).await {
        return err(StatusCode::CONFLICT, format!("{e:#}"));
    }
    if let Err(e) = pipeline::verifier_unchanged(&state.rpc, &state.config, &rel).await {
        return err(StatusCode::SERVICE_UNAVAILABLE, format!("{e:#}"));
    }
    if let (Some(_), Some(latest)) = (&sub.v5, latest) {
        let deadline = pipeline::send_deadline(&state.config, &sub, latest);
        if let Err(e) = pipeline::root_fresh(&state.rpc, &state.config, &sub, deadline).await {
            return err(StatusCode::CONFLICT, format!("{e:#}"));
        }
        if let Err(e) = pipeline::invoke_state(&state.rpc, &state.config, &sub).await {
            return err(StatusCode::BAD_REQUEST, format!("{e:#}"));
        }
    }
    // 7. The bridge and the calldata match, in a child process. It runs in its own task, so a client that disconnects
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
            let reply = match pipeline::check(&state.config, &rel, &sub, &dir, &id).await {
                // A bridge rejection or a calldata mismatch consumes the tickets (spec §9): an
                // honest client checks these first. A failure of the server's own (a sandbox, a
                // disk, a time-out) releases them (AB-SP5).
                // Either way the submission backs off, so a release cannot become a loop (recheck
                // N9): the note only when the bridge had accepted the proof, otherwise the exact
                // body, since anyone can name another's nullifier in a junk proof (N10).
                Err(e) if pipeline::is_client_fault(&e) => {
                    held.consume();
                    let _ = std::fs::remove_dir_all(&dir);
                    let k = if pipeline::is_proven_fault(&e) { dkey.clone() } else { body_key(&body_hash) };
                    back_off(&mut state.registry.lock().unwrap(), &k, state.config.limits.duplicate_backoff_secs);
                    Err(err(StatusCode::BAD_REQUEST, format!("{e:#}")))
                }
                Err(e) => {
                    drop(held);
                    let _ = std::fs::remove_dir_all(&dir);
                    back_off(&mut state.registry.lock().unwrap(), &body_key(&body_hash), state.config.limits.duplicate_backoff_secs);
                    tracing::warn!("pre-check failed on the server's side: {e:#}");
                    Err(err(StatusCode::SERVICE_UNAVAILABLE, "the pre-check failed on the server's side; retry later"))
                }
                Ok(bridge) => match admission_tail(&state, free, &key, via_relay).await {
                    // A signature failure or a free-allowance refusal releases the tickets.
                    Err(reply) => {
                        drop(held);
                        let _ = std::fs::remove_dir_all(&dir);
                        Err(reply)
                    }
                    // A client that went away gets no job: nobody could collect the result. No
                    // allowance was taken: `admit` takes it.
                    Ok(_) if tx.is_closed() => {
                        drop(held);
                        let _ = std::fs::remove_dir_all(&dir);
                        return;
                    }
                    Ok(debit) => admit(&state, id, sub, bridge, dkey, body_hash, key, dir, held, debit),
                },
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

/// A free job's allowances, taken by `admit` once the job is really queued (AB-SP2).
struct FreeDebit {
    key: String,
    via_relay: bool,
}

/// A free withdrawal's allowances are looked at again; `admit` takes them only when it queues the
/// job, so a refused, duplicate or abandoned submission takes nothing (spec §7.2, AB-SP2, recheck
/// N1). Bound spends are not served (ADR-0027), so there is no signature step.
async fn admission_tail(state: &Arc<AppState>, free: bool, key: &str, via_relay: bool) -> Result<Option<FreeDebit>, Reply> {
    match (&state.tickets, free) {
        (Some(t), true) => {
            free_allowance(state, t, key, via_relay, false)?;
            Ok(Some(FreeDebit { key: key.to_string(), via_relay }))
        }
        _ => Ok(None),
    }
}

/// The free allowances (spec §7.2): the global hourly bucket, and the address's (not for relays).
/// With `debit`, both are checked, then both taken, under one lock.
fn free_allowance(state: &Arc<AppState>, t: &Tickets, key: &str, via_relay: bool, debit: bool) -> Result<(), Reply> {
    let limits = t.config.free;
    let now = Instant::now();
    let mut f = state.free.lock().unwrap();
    let (global, per_address) = (limits.per_hour as f64, limits.per_address_per_hour as f64);
    if !f.bucket.get_or_insert_with(|| Bucket::full(global, now)).ready(global, now) {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "free withdrawals are rate-limited; retry later or pay one ticket"));
    }
    if !via_relay && !f.addresses.entry(key.to_string()).or_insert_with(|| Bucket::full(per_address, now)).ready(per_address, now) {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "this address's free withdrawals are used for now; retry later or pay one ticket"));
    }
    if debit {
        f.bucket.as_mut().expect("set above").tokens -= 1.0;
        if !via_relay {
            f.addresses.get_mut(key).expect("set above").tokens -= 1.0;
        }
    }
    Ok(())
}

/// Returns allowances `free_allowance` took, for a job that was not queued after all.
fn free_credit(state: &Arc<AppState>, t: &Tickets, d: &FreeDebit) {
    let limits = t.config.free;
    let mut f = state.free.lock().unwrap();
    if let Some(b) = f.bucket.as_mut() {
        b.tokens = (b.tokens + 1.0).min(limits.per_hour as f64);
    }
    if !d.via_relay {
        if let Some(b) = f.addresses.get_mut(&d.key) {
            b.tokens = (b.tokens + 1.0).min(limits.per_address_per_hour as f64);
        }
    }
}

/// A refused or failed note waits `base`, doubling per refusal (duplicates, failed jobs and failed
/// pre-checks share the count).
fn back_off(reg: &mut Registry, dkey: &str, base: u64) {
    let now = Instant::now();
    let r = reg.refusals.entry(dkey.to_string()).or_insert(Refusal { count: 0, until: now });
    r.count += 1;
    r.until = now + Duration::from_secs(base << (r.count - 1).min(10));
}

/// The refusal key of one exact body (a pre-check failure before the proof was verified).
fn body_key(body_hash: &[u8; 32]) -> String {
    format!("body:{}", hex::encode(body_hash))
}

/// Whether free jobs may take the prover now: the free jobs of the last hour took less than
/// `max_share_percent` of every worker's hour (AB-SP3).
fn free_budget_left(state: &Arc<AppState>) -> bool {
    let Some(t) = &state.tickets else { return true };
    let budget = t.config.free.max_share_percent as f64 / 100.0 * 3600.0 * state.config.server.max_concurrent_jobs as f64;
    let mut f = state.free.lock().unwrap();
    let hour = Duration::from_secs(3600);
    while f.ran.front().is_some_and(|(at, _)| at.elapsed() > hour) {
        f.ran.pop_front();
    }
    f.ran.iter().map(|(_, s)| s).sum::<f64>() < budget
}

/// Records an accepted submission and queues it (free withdrawals on their own queue, taking their
/// allowances only here, under the registry lock, after the duplicate check); on any refusal,
/// removes what it created (PI-8) and releases the tickets. Lock order: registry, then free.
#[allow(clippy::too_many_arguments)]
fn admit(state: &Arc<AppState>, id: String, sub: Submission, bridge: BridgeOutput, dkey: String, body_hash: [u8; 32], key: String,
         dir: PathBuf, held: Held, debit: Option<FreeDebit>) -> Result<usize, Reply> {
    let mut reg = state.registry.lock().unwrap();
    if reg.dedup.contains_key(&dkey) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(err(StatusCode::CONFLICT, "a job for this note is already queued, running or done"));
    }
    let free = debit.is_some();
    if let (Some(t), Some(d)) = (&state.tickets, &debit) {
        if let Err(reply) = free_allowance(state, t, &d.key, d.via_relay, true) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(reply);
        }
    }
    let queue = if free { &state.free_queue } else { &state.queue };
    if queue.try_send(id.clone()).is_err() {
        if let (Some(t), Some(d)) = (&state.tickets, &debit) {
            free_credit(state, t, d);
        }
        let _ = std::fs::remove_dir_all(&dir);
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "queue full"));
    }
    reg.dedup.insert(dkey.clone(), id.clone());
    reg.by_body.insert(body_hash, id.clone());
    reg.jobs.insert(id.clone(), Job {
        status: Status::Queued, stage: "queued".into(), finished: None, submission: Some(sub),
        bridge: Some(bridge), result: None, error: None, dedup_key: dkey, body_hash, address_key: key, dir,
        deadline: None, reservation: held.take(), spent: false, refund: None, free, relay: None,
    });
    reg.order.push_back(id.clone());
    tracing::info!(job = %id, "admitted");
    Ok(reg.order.len() - 1)
}

/// The client acknowledges its result: a finished job drops its result and directory now. The job
/// keeps holding its note until its deadline (spec §9: results are deleted on receipt).
async fn acknowledge(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Reply {
    let dir = {
        let mut reg = state.registry.lock().unwrap();
        let Some(j) = reg.jobs.get_mut(&id) else {
            return err(StatusCode::NOT_FOUND, "no such job");
        };
        if matches!(j.status, Status::Queued | Status::Running) {
            return err(StatusCode::CONFLICT, "the job has not finished");
        }
        j.result = None;
        j.error = None;
        j.dir.clone()
    };
    let _ = std::fs::remove_dir_all(dir);
    (StatusCode::OK, Json(json!({"id": id, "acknowledged": true})))
}

async fn status(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Reply {
    let reg = state.registry.lock().unwrap();
    let Some(j) = reg.jobs.get(&id) else {
        return err(StatusCode::NOT_FOUND, "no such job");
    };
    let position = reg.order.iter().position(|x| *x == id);
    (StatusCode::OK, Json(json!({
        "id": id, "status": j.status.name(), "stage": j.stage, "position": position,
        "result": j.result, "error": j.error, "refund": j.refund, "relay": j.relay,
    })))
}

/// The job an identical submission already holds, unless it is a finished job whose proof is past
/// its `valid_until`: that one releases its note, and the submission is admitted afresh.
async fn existing_job(state: &Arc<AppState>, body_hash: &[u8; 32]) -> Option<Reply> {
    let found = {
        let reg = state.registry.lock().unwrap();
        let id = reg.by_body.get(body_hash)?;
        let j = reg.jobs.get(id)?;
        if reg.dedup.get(&j.dedup_key) != Some(id) {
            return None;
        }
        let until = matches!(j.status, Status::Done).then_some(j.deadline).flatten();
        (id.clone(), j.dedup_key.clone(), until)
    };
    let (id, dkey, until) = found;
    if let Some(until) = until {
        if latest_block(state).await.is_some_and(|latest| latest > until) {
            let mut reg = state.registry.lock().unwrap();
            if reg.dedup.get(&dkey) == Some(&id) {
                reg.dedup.remove(&dkey);
                reg.refusals.remove(&dkey);
            }
            return None;
        }
    }
    let reg = state.registry.lock().unwrap();
    let position = reg.order.iter().position(|x| *x == id);
    Some((StatusCode::ACCEPTED, Json(json!({"id": id, "position": position}))))
}

/// The latest block number, read from the node at most every 10 seconds (SDK-IP19).
async fn latest_block(state: &Arc<AppState>) -> Option<u64> {
    if let Some((at, n)) = *state.latest.lock().unwrap() {
        if at.elapsed() < Duration::from_secs(10) {
            return Some(n);
        }
    }
    let n = state.rpc.block_number().await.ok()?;
    *state.latest.lock().unwrap() = Some((Instant::now(), n));
    Some(n)
}

/// Creates the state, the worker pool and the retention sweeper.
pub fn start(config: Config, rpc: Rpc, info: Value, tickets: Option<Arc<Tickets>>) -> Arc<AppState> {
    let (tx, rx) = mpsc::channel::<String>(config.server.queue_capacity.max(1) * 4);
    let free_capacity = tickets.as_ref().map_or(1, |t| t.config.free.queue_capacity.max(1));
    let (ftx, frx) = mpsc::channel::<String>(free_capacity);
    let state = Arc::new(AppState {
        info, rpc, tickets, registry: Mutex::new(Registry::default()), buckets: Mutex::new(HashMap::new()),
        checks: Arc::new(Semaphore::new(config.server.max_concurrent_checks)), queue: tx, free_queue: ftx,
        free: Mutex::new(FreeState::default()), config, latest: Mutex::new(None),
    });
    let queues = Arc::new(tokio::sync::Mutex::new((rx, frx)));
    for _ in 0..state.config.server.max_concurrent_jobs {
        let (state, queues) = (state.clone(), queues.clone());
        tokio::spawn(async move {
            loop {
                // Paid jobs first: a free job runs only when no paid job waits (spec §7.2), and only
                // while free jobs are within their share of the prover (AB-SP3).
                let free_ok = free_budget_left(&state);
                let id = {
                    let mut q = queues.lock().await;
                    let (paid, free) = &mut *q;
                    if free_ok {
                        tokio::select! {
                            biased;
                            Some(id) = paid.recv() => id,
                            Some(id) = free.recv() => id,
                            else => return,
                        }
                    } else {
                        tokio::select! {
                            biased;
                            Some(id) = paid.recv() => id,
                            _ = tokio::time::sleep(Duration::from_secs(30)) => continue,
                        }
                    }
                };
                let is_free = state.registry.lock().unwrap().jobs.get(&id).is_some_and(|j| j.free);
                let started = Instant::now();
                work(&state, &id).await;
                if is_free {
                    state.free.lock().unwrap().ran.push_back((Instant::now(), started.elapsed().as_secs_f64()));
                }
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
    let stage = move |s: &str| -> anyhow::Result<()> {
        let spend = {
            let mut reg = st.registry.lock().unwrap();
            let Some(j) = reg.jobs.get_mut(&idc) else { return Ok(()) };
            j.stage = s.to_string();
            // The job-start checks passed: the tickets are spent now (spec §9). A later OS revert,
            // abort or cap violation keeps them spent.
            if s == "os" && !j.spent { j.reservation.clone() } else { None }
        };
        if let (Some(t), Some(r)) = (&st.tickets, spend) {
            // Fail-closed (AB-SM5): the job is spent only once the log is synced; otherwise it fails
            // here, before the virtual OS runs, and its tickets are released.
            if let Err(e) = t.spend(&r) {
                tracing::error!("spending a job's tickets: {e:#}");
                anyhow::bail!("the server could not record the payment; retry later");
            }
            if let Some(j) = st.registry.lock().unwrap().jobs.get_mut(&idc) {
                j.spent = true;
            }
        }
        Ok(())
    };
    let outcome = pipeline::run(&state.config, &state.rpc, &rel, &sub, &bridge, &dir, id, &stage).await;
    let mut reg = state.registry.lock().unwrap();
    // Every R0 V5 result this server proves goes to the relayer, if it relays (spec §7.4), except
    // invokes, which wait for tight minimums (F06): those are refused at once, so the client
    // submits them itself without waiting.
    let invoke = sub.v5.as_ref().is_some_and(|j| j.pool_call.intent.is_some());
    let relay = match (&outcome, &sub.v5, &state.config.relay) {
        (Ok(r), Some(j), Some(_)) if !invoke => r.value.get("send_deadline").and_then(Value::as_u64).map(|deadline| RelayItem {
            result: r.value.clone(),
            nullifiers: j.statement.nullifiers.iter().map(|n| n.iter().map(crate::rpc::hex).collect()).collect(),
            root: j.statement.root.iter().map(crate::rpc::hex).collect(),
            deadline,
            claimed: false,
        }),
        _ => None,
    };
    if let Some(item) = relay {
        reg.relay.insert(id.to_string(), item);
    }
    let relayed = reg.relay.contains_key(id);
    let refused_invoke = invoke && outcome.is_ok() && state.config.relay.is_some();
    let Some(j) = reg.jobs.get_mut(id) else { return };
    j.finished = Some(Instant::now());
    j.submission = None;
    match outcome {
        Ok(r) => {
            j.status = Status::Done;
            j.stage = "done".into();
            j.deadline = r.value.get("send_deadline").or_else(|| r.value.get("valid_until")).and_then(Value::as_u64);
            if relayed {
                j.relay = Some(json!({"status": "pending"}));
            }
            if refused_invoke {
                j.relay = Some(json!({"status": "refused", "reason": "invokes are not relayed until tight minimums exist (F06)"}));
            }
            j.result = Some(r.value);
            tracing::info!(job = %id, "done");
        }
        Err(e) => {
            j.status = Status::Failed;
            j.error = Some(format!("{e:#}"));
            let client = pipeline::is_client_fault(&e);
            tracing::info!(job = %id, stage = %j.stage, client, "failed");
            // Ticket states at failure (spec §9), by cause (AB-SP5): before job start, released;
            // after it, the client's fault (a revert, a failed execution, a message mismatch, a cap
            // violation) keeps them spent, and the server's own is refunded, blind. A job reaches
            // proving only inside the caps, so a proving failure is the server's.
            if let (Some(t), Some(r)) = (&state.tickets, j.reservation.clone()) {
                if !j.spent {
                    t.release(&r);
                } else if !client {
                    j.refund = Some(t.refund(&r).unwrap_or_else(|e| json!({"owed": r.len(), "error": format!("{e:#}")})));
                }
            }
            // A failed job releases its note, which then backs off, doubling per failure, whatever
            // the cause (AB-SP4): one note cannot keep the prover busy.
            let key = j.dedup_key.clone();
            reg.dedup.remove(&key);
            back_off(&mut reg, &key, state.config.limits.duplicate_backoff_secs);
        }
    }
}

/// The relayer's side of the handoff (P4b): its own listener, never the public one.
pub struct RelayState {
    pub app: Arc<AppState>,
    /// The bearer token, always required (AB-RL10).
    pub token: String,
}

impl RelayState {
    fn authorized(&self, headers: &HeaderMap) -> bool {
        !self.token.is_empty()
            && headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|given| constant_time_eq(given.as_bytes(), self.token.as_bytes()))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn relay_router(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/relay/v1/jobs", get(relay_list))
        .route("/relay/v1/jobs/{id}", post(relay_report))
        .route("/relay/v1/jobs/{id}/claim", post(relay_claim))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

/// Ends relay items that can no longer be relayed at `latest`: an unclaimed one once its deadline
/// is within `relay_margin_blocks` (the relayer did not take it in time: the client may fall back
/// at once, AB-RL9), a claimed one when its deadline passed.
fn expire_relay(reg: &mut Registry, latest: u64, margin: u64) {
    let ended: Vec<(String, bool)> = reg
        .relay
        .iter()
        .filter(|(_, i)| i.deadline < latest || !i.claimed && i.deadline < latest + margin)
        .map(|(id, i)| (id.clone(), i.claimed))
        .collect();
    for (id, claimed) in ended {
        reg.relay.remove(&id);
        if let Some(j) = reg.jobs.get_mut(&id) {
            j.relay = Some(if claimed {
                json!({"status": "expired"})
            } else {
                json!({"status": "refused", "reason": "the relayer did not take it in time"})
            });
        }
    }
}

/// The results waiting for the relayer, earliest deadline first, with the server's relay margin
/// (the relayer's own must not exceed it).
async fn relay_list(State(rs): State<Arc<RelayState>>, headers: HeaderMap) -> Reply {
    if !rs.authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "relay token");
    }
    let latest = latest_block(&rs.app).await;
    let margin = rs.app.config.server.relay_margin_blocks;
    let mut reg = rs.app.registry.lock().unwrap();
    if let Some(latest) = latest {
        expire_relay(&mut reg, latest, margin);
    }
    let mut jobs: Vec<(u64, Value)> = reg
        .relay
        .iter()
        // Each item names its relation and route key (pool-v3-spec §7.3, §9.5), so a relayer serving
        // both generations checks the verifier and the route per item.
        .map(|(id, i)| (i.deadline, json!({"id": id, "relation": i.result.get("relation"), "statement": i.result.get("statement"),
                                           "result": i.result, "nullifiers": i.nullifiers, "root": i.root, "send_deadline": i.deadline})))
        .collect();
    jobs.sort_by_key(|(d, _)| *d);
    (StatusCode::OK, Json(json!({"jobs": jobs.into_iter().map(|(_, j)| j).collect::<Vec<_>>(), "relay_margin_blocks": margin})))
}

/// The relayer claims an item just before sending it: 200 once, 409 when already claimed, 404 when
/// it is gone (answered, or refused for lateness). It must not send without a 200.
async fn relay_claim(State(rs): State<Arc<RelayState>>, headers: HeaderMap, Path(id): Path<String>) -> Reply {
    if !rs.authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "relay token");
    }
    let latest = latest_block(&rs.app).await;
    let margin = rs.app.config.server.relay_margin_blocks;
    let mut reg = rs.app.registry.lock().unwrap();
    if let Some(latest) = latest {
        expire_relay(&mut reg, latest, margin);
    }
    match reg.relay.get_mut(&id) {
        None => err(StatusCode::NOT_FOUND, "no such relay item"),
        Some(i) if i.claimed => err(StatusCode::CONFLICT, "already claimed"),
        Some(i) => {
            i.claimed = true;
            (StatusCode::OK, Json(json!({"id": id})))
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayReport {
    transaction_hash: Option<String>,
    refused: Option<String>,
}

/// The relayer's answer for one job: its transaction hash, or a refusal and its reason (AB-P31).
/// The item then goes: the relayer keeps only the nullifiers, the server nothing.
async fn relay_report(State(rs): State<Arc<RelayState>>, headers: HeaderMap, Path(id): Path<String>, body: axum::body::Bytes) -> Reply {
    if !rs.authorized(&headers) {
        return err(StatusCode::UNAUTHORIZED, "relay token");
    }
    let Ok(r) = serde_json::from_slice::<RelayReport>(&body) else {
        return err(StatusCode::BAD_REQUEST, "malformed report");
    };
    let status = match (r.transaction_hash, r.refused) {
        (Some(h), None) => match crate::rpc::felt(&h) {
            Ok(f) if f != Felt::ZERO => json!({"status": "submitted", "transaction_hash": crate::rpc::hex(&f)}),
            _ => return err(StatusCode::BAD_REQUEST, "transaction_hash"),
        },
        (None, Some(reason)) => json!({"status": "refused", "reason": reason.chars().take(300).collect::<String>()}),
        _ => return err(StatusCode::BAD_REQUEST, "a report is {transaction_hash} or {refused}"),
    };
    let mut reg = rs.app.registry.lock().unwrap();
    if reg.relay.remove(&id).is_none() {
        return err(StatusCode::NOT_FOUND, "no such relay item");
    }
    if let Some(j) = reg.jobs.get_mut(&id) {
        j.relay = Some(status);
    }
    tracing::info!(job = %id, "relay reported");
    (StatusCode::OK, Json(json!({"id": id})))
}

/// Deletes finished jobs past retention with their directories, and expired refusals and buckets.
fn sweep(state: &Arc<AppState>) {
    let retention = Duration::from_secs(state.config.server.retention_secs);
    let now = Instant::now();
    let latest = state.latest.lock().unwrap().map(|(_, n)| n);
    let dirs: Vec<PathBuf> = {
        let mut reg = state.registry.lock().unwrap();
        // Relay items that can no longer be relayed, when the relayer has not polled.
        if let Some(latest) = latest {
            expire_relay(&mut reg, latest, state.config.server.relay_margin_blocks);
        }
        let past = |j: &Job| j.finished.map(|f| now.duration_since(f) > retention).unwrap_or(false);
        // A relayed job outlives retention until its deadline (AB-RL5): while its item waits, and
        // then so the client can still read the relayer's answer. Only its result goes.
        let relayed: Vec<String> = reg.relay.keys().cloned().collect();
        let keep = |id: &String, j: &Job| relayed.contains(id) || j.relay.is_some() && j.deadline.is_some_and(|d| latest.is_none_or(|l| d >= l));
        for (id, j) in reg.jobs.iter_mut() {
            if !matches!(j.status, Status::Running | Status::Queued) && past(j) && keep(id, j) {
                j.result = None;
            }
        }
        let expired: Vec<String> = reg
            .jobs
            .iter()
            .filter(|(_, j)| !matches!(j.status, Status::Running | Status::Queued))
            .filter(|(id, j)| past(j) && !keep(id, j))
            .map(|(id, _)| id.clone())
            .collect();
        let mut dirs = vec![];
        for id in expired {
            if let Some(j) = reg.jobs.remove(&id) {
                if reg.by_body.get(&j.body_hash) == Some(&id) {
                    reg.by_body.remove(&j.body_hash);
                }
                if reg.dedup.get(&j.dedup_key) == Some(&id) {
                    reg.dedup.remove(&j.dedup_key);
                }
                dirs.push(j.dir);
            }
        }
        // A refusal keeps its count for the retention period after its wait ends, so repeated
        // duplicates or failures of one note keep doubling (AB-SP4).
        reg.refusals.retain(|_, r| r.until > now || now.duration_since(r.until) < retention);
        dirs
    };
    for d in dirs {
        let _ = std::fs::remove_dir_all(d);
    }
    state.buckets.lock().unwrap().retain(|_, b| now.duration_since(b.updated) < Duration::from_secs(3600));
    let mut f = state.free.lock().unwrap();
    f.addresses.retain(|_, b| now.duration_since(b.updated) < Duration::from_secs(3600));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// A state with one job holding `body` for note key `dkey`, and an RPC stub at `latest`.
    async fn state_with_job(status: Status, valid_until: u64, latest: u64) -> (Arc<AppState>, String, [u8; 32]) {
        let rpc = axum::Router::new().route("/", axum::routing::post(move || async move {
            Json(json!({"jsonrpc": "2.0", "id": 1, "result": latest}))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, rpc).await.unwrap() });
        let cfg = Config::load(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/prover.example.toml"))).unwrap();
        let state = start(cfg, Rpc::new(&url), json!({}), None);
        let body_hash = [7u8; 32];
        let id = "0123456789abcdef0123456789abcdef".to_string();
        let mut reg = state.registry.lock().unwrap();
        reg.jobs.insert(id.clone(), Job {
            status, stage: "done".into(), finished: None, submission: None, bridge: None,
            result: Some(json!({"valid_until": valid_until})), error: None, dedup_key: "note".into(), body_hash,
            address_key: "1.2.3.4".into(), dir: std::env::temp_dir(), deadline: Some(valid_until),
            reservation: None, spent: false, refund: None, free: false, relay: None,
        });
        reg.dedup.insert("note".into(), id.clone());
        reg.by_body.insert(body_hash, id.clone());
        // The note is in backoff.
        reg.refusals.insert("note".into(), Refusal { count: 3, until: Instant::now() + Duration::from_secs(600) });
        drop(reg);
        (state, id, body_hash)
    }

    /// An identical resubmission gets its job back even in backoff (SDK-P3, SDK-IP15).
    #[tokio::test]
    async fn identical_resubmission_gets_its_job() {
        let (state, id, body) = state_with_job(Status::Queued, 0, 10).await;
        let (code, Json(v)) = existing_job(&state, &body).await.expect("its job");
        assert_eq!(code, StatusCode::ACCEPTED);
        assert_eq!(v["id"], id);
        assert!(existing_job(&state, &[8u8; 32]).await.is_none(), "another body is not matched");
        let (state, id, body) = state_with_job(Status::Done, 100, 100).await;
        assert_eq!(existing_job(&state, &body).await.expect("still valid").1 .0["id"], id);
    }

    /// A finished job past `valid_until` releases its note and its backoff (SDK-P3).
    #[tokio::test]
    async fn finished_job_past_its_window_releases_the_note() {
        let (state, _, body) = state_with_job(Status::Done, 100, 101).await;
        assert!(existing_job(&state, &body).await.is_none());
        let reg = state.registry.lock().unwrap();
        assert!(!reg.dedup.contains_key("note") && !reg.refusals.contains_key("note"));
    }

    /// The relayer's handoff (P4b): its own token, a copy the client's acknowledgement does not take,
    /// claims, one report per job shown to the client, lateness and expiry, and retention.
    #[tokio::test]
    async fn relay_handoff() {
        let (state, id, _) = state_with_job(Status::Done, 200, 100).await;
        let item = |deadline| RelayItem { result: json!({"proof": "AAAA", "send_deadline": deadline}), nullifiers: vec![vec!["0x1".into(); 9]], root: vec!["0x2".into(); 9], deadline, claimed: false };
        {
            let mut reg = state.registry.lock().unwrap();
            reg.relay.insert(id.clone(), item(200));
            reg.jobs.get_mut(&id).unwrap().relay = Some(json!({"status": "pending"}));
            let mut old = Job { relay: None, ..clone_job(&reg.jobs[&id]) };
            old.deadline = Some(50);
            reg.jobs.insert("old".into(), old);
            reg.relay.insert("old".into(), item(50));
        }
        let app = relay_router(Arc::new(RelayState { app: state.clone(), token: "s3cret".into() }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let http = reqwest::Client::new();
        let list = || http.get(format!("{url}/relay/v1/jobs")).bearer_auth("s3cret").send();
        assert_eq!(http.get(format!("{url}/relay/v1/jobs")).send().await.unwrap().status(), 401);
        assert_eq!(http.get(format!("{url}/relay/v1/jobs")).bearer_auth("wrong!").send().await.unwrap().status(), 401);
        // The latest block is 100 and the relay margin 60: the unclaimed item with deadline 50 was
        // not taken in time (refused, so its client falls back at once); the other is listed.
        let v: Value = list().await.unwrap().json().await.unwrap();
        assert_eq!(v["jobs"].as_array().unwrap().len(), 1);
        assert_eq!(v["jobs"][0]["id"], id.as_str());
        assert_eq!(v["jobs"][0]["nullifiers"][0][0], "0x1");
        assert_eq!(v["relay_margin_blocks"], 60);
        assert_eq!(state.registry.lock().unwrap().jobs["old"].relay.as_ref().unwrap()["status"], "refused");
        // A claim once; a second claim conflicts. A claimed item is no longer refused for lateness,
        // only expired after its deadline.
        let claim = |id: &str| http.post(format!("{url}/relay/v1/jobs/{id}/claim")).bearer_auth("s3cret").send();
        assert_eq!(claim(&id).await.unwrap().status(), 200);
        assert_eq!(claim(&id).await.unwrap().status(), 409);
        assert_eq!(claim("old").await.unwrap().status(), 404);
        {
            let mut reg = state.registry.lock().unwrap();
            reg.relay.insert("late".into(), RelayItem { claimed: true, ..item(120) });
            reg.relay.insert("late2".into(), item(120));
            expire_relay(&mut reg, 100, 60);
            assert!(reg.relay.contains_key("late") && !reg.relay.contains_key("late2"));
            expire_relay(&mut reg, 121, 60);
            assert!(!reg.relay.contains_key("late"));
        }
        // The client's acknowledgement drops its own copy, not the relayer's.
        let (code, _) = acknowledge(State(state.clone()), Path(id.clone())).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(list().await.unwrap().json::<Value>().await.unwrap()["jobs"].as_array().unwrap().len(), 1);
        // Reports: malformed ones refused; one report per job, shown to the client.
        let post = |b: Value| http.post(format!("{url}/relay/v1/jobs/{id}")).bearer_auth("s3cret").json(&b).send();
        assert_eq!(post(json!({"transaction_hash": "0x1", "refused": "x"})).await.unwrap().status(), 400);
        assert_eq!(post(json!({"transaction_hash": "0x0"})).await.unwrap().status(), 400);
        assert_eq!(post(json!({"hash": "0x1"})).await.unwrap().status(), 400);
        assert_eq!(post(json!({"transaction_hash": "0x00abc"})).await.unwrap().status(), 200);
        assert_eq!(post(json!({"refused": "late"})).await.unwrap().status(), 404);
        let (_, Json(s)) = status(State(state.clone()), Path(id.clone())).await;
        assert_eq!(s["relay"], json!({"status": "submitted", "transaction_hash": "0xabc"}));
        assert!(list().await.unwrap().json::<Value>().await.unwrap()["jobs"].as_array().unwrap().is_empty());
        // Retention (AB-RL5): past it, a job whose relay item waits, or whose answer is still
        // within its deadline, keeps its status and note, and loses only its result.
        {
            let mut reg = state.registry.lock().unwrap();
            let j = reg.jobs.get_mut(&id).unwrap();
            j.finished = Some(Instant::now() - Duration::from_secs(100_000));
            j.result = Some(json!({"proof": "AAAA"}));
            let mut w = clone_job(j);
            w.relay = Some(json!({"status": "pending"}));
            w.deadline = Some(90);
            reg.jobs.insert("waiting".into(), w);
            reg.relay.insert("waiting".into(), RelayItem { claimed: true, ..item(150) });
        }
        *state.latest.lock().unwrap() = Some((Instant::now(), 100));
        sweep(&state);
        let reg = state.registry.lock().unwrap();
        assert!(reg.jobs[&id].result.is_none() && reg.jobs[&id].relay.is_some(), "kept until its deadline 200");
        assert!(reg.jobs.contains_key("waiting") && reg.dedup.values().any(|v| v == &id));
    }

    fn clone_job(j: &Job) -> Job {
        Job {
            status: j.status, stage: j.stage.clone(), finished: j.finished, submission: None, bridge: None, result: j.result.clone(),
            error: None, dedup_key: format!("{}-2", j.dedup_key), body_hash: [9; 32], address_key: j.address_key.clone(), dir: j.dir.clone(),
            deadline: j.deadline, reservation: None, spent: false, refund: None, free: false, relay: j.relay.clone(),
        }
    }

    /// Free allowances (AB-SP2): looking takes nothing; a debit takes the global and the address's
    /// (never a relay's).
    #[tokio::test]
    async fn free_allowances() {
        let (state0, _, _) = state_with_job(Status::Done, 0, 0).await;
        let payment = crate::tickets::PaymentConfig {
            required: false, issuer_keys: vec![], refund_key: None, costs: Default::default(), priced_assets: vec![],
            free: crate::tickets::FreeLimits { per_hour: 5, per_address_per_hour: 2, ..Default::default() },
            spent_dir: None,
        };
        let dir = std::env::temp_dir().join(format!("templar-free-{}", rand::random::<u32>()));
        let t = Arc::new(Tickets::load(payment, &dir, 0).unwrap());
        let state = start(state0.config.clone(), state0.rpc.clone(), json!({}), Some(t.clone()));
        for _ in 0..5 {
            free_allowance(&state, &t, "1.2.3.4", false, false).unwrap();
        }
        free_allowance(&state, &t, "1.2.3.4", false, true).unwrap();
        free_allowance(&state, &t, "1.2.3.4", false, true).unwrap();
        assert_eq!(free_allowance(&state, &t, "1.2.3.4", false, false).unwrap_err().0, StatusCode::TOO_MANY_REQUESTS, "address");
        // A relay is bound by the global bucket only; another address has its own.
        free_allowance(&state, &t, "relay:5.6.7.8", true, true).unwrap();
        free_allowance(&state, &t, "9.9.9.9", false, true).unwrap();
        free_allowance(&state, &t, "9.9.9.8", false, true).unwrap();
        // Five taken of five: the global bucket is empty for everyone.
        assert!(free_allowance(&state, &t, "relay:5.6.7.8", true, false).is_err(), "global");
        assert!(free_allowance(&state, &t, "9.9.9.7", false, false).is_err(), "global, a fresh address");
    }

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
    fn relay_blocks() {
        assert!(in_block("10.1.2.3".parse().unwrap(), "10.1.0.0/16"));
        assert!(!in_block("10.2.2.3".parse().unwrap(), "10.1.0.0/16"));
        assert!(in_block("::ffff:10.1.2.3".parse().unwrap(), "10.1.2.3"));
        assert!(in_block("2001:db8::5".parse().unwrap(), "2001:db8::/32"));
        assert!(!in_block("2001:db9::5".parse().unwrap(), "2001:db8::/32"));
        assert!(!in_block("1.2.3.4".parse().unwrap(), "not-an-ip"));
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

/// Admission end to end (spec §9, ticket states) with the real R5 bridge and a stub node:
/// `TEMPLAR_R5_BRIDGE=<built bridge> TEMPLAR_SDK_PROOFS=<sdk-proofs dir> TEMPLAR_CGROUP=<delegated cgroup>
/// cargo test --release -- --ignored admission_r5`. `TEMPLAR_TEST_DIR` roots the scratch
/// directories (default: the system's temporary directory).
#[cfg(test)]
mod admission {
    use super::*;
    use crate::config::PoolParameters;
    use crate::rpc::{felt, hex, sn_keccak};
    use crate::tickets::{issuer, IssuerKeyConfig, PaymentConfig, PricedAsset, RefundKeyConfig};

    type Calls = Arc<Mutex<HashMap<Felt, Vec<Felt>>>>;

    /// The tests' scratch root: `TEMPLAR_TEST_DIR` when set (keep runtime directories out of
    /// /tmp), else the system's temporary directory.
    fn scratch_root() -> std::path::PathBuf {
        std::env::var_os("TEMPLAR_TEST_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir)
    }

    async fn stub(calls: Calls, block: Arc<std::sync::atomic::AtomicU64>) -> String {
        let app = axum::Router::new().route("/", axum::routing::post(move |Json(req): Json<Value>| {
            let (calls, block) = (calls.clone(), block.clone());
            async move {
                let result = match req["method"].as_str().unwrap_or("") {
                    "starknet_blockNumber" => json!(block.load(std::sync::atomic::Ordering::SeqCst)),
                    "starknet_getClassHashAt" => json!("0xc1a55"),
                    "starknet_chainId" => json!("0x534e5f5345504f4c4941"),
                    "starknet_getNonce" => json!("0x0"),
                    "starknet_getBlockWithTxHashes" => json!({"block_hash": "0x1234", "timestamp": 1_000_000}),
                    "starknet_call" => {
                        let sel = felt(req["params"][0]["entry_point_selector"].as_str().unwrap()).unwrap();
                        match calls.lock().unwrap().get(&sel) {
                            Some(r) => json!(r.iter().map(hex).collect::<Vec<_>>()),
                            None => return Json(json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 40, "message": "no"}})),
                        }
                    }
                    _ => json!(null),
                };
                Json(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    #[tokio::test]
    #[ignore]
    async fn admission_r5_with_tickets() {
        let (Ok(bridge), Ok(proofs), Ok(cgroup)) =
            (std::env::var("TEMPLAR_R5_BRIDGE"), std::env::var("TEMPLAR_SDK_PROOFS"), std::env::var("TEMPLAR_CGROUP"))
        else {
            panic!("set TEMPLAR_R5_BRIDGE, TEMPLAR_SDK_PROOFS and TEMPLAR_CGROUP");
        };
        let tmp = scratch_root().join(format!("templar-admission-{}", rand::random::<u32>()));
        issuer::keygen(&tmp.join("keys"), "test").unwrap();
        let sk = issuer::load_secret(&tmp.join("keys/test.key.pem")).unwrap();
        let pk = issuer::load_public(&tmp.join("keys/test.pub.pem")).unwrap();
        // Configuration: pool V3 at the SDK proofs' pool, the r5 bridge, tickets required.
        let mut cfg = Config::load(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/prover.example.toml"))).unwrap();
        cfg.server.data_dir = tmp.join("data");
        std::fs::create_dir_all(&cfg.server.data_dir).unwrap();
        cfg.network.pool = "0x7e57b301".into();
        cfg.network.pool_version = 3;
        cfg.network.max_proof_age = 1024;
        cfg.network.parameters = Some(PoolParameters { expiry_window: 1500, quantum: 100, root_window: 4096, timelock: 86400 });
        let b = std::path::PathBuf::from(&bridge);
        let sha = |p: &std::path::Path| format!("{:x}", sha2::Sha256::digest(std::fs::read(p).unwrap()));
        let mut rel = cfg.relations[0].clone();
        rel.name = "r5".into();
        rel.account_tag = "TMPZR0_PAYMENT_V5".into();
        rel.adapter = "0xada".into();
        rel.statement_account = "0xacc".into();
        rel.statement_class = "0x5a7e".into();
        rel.bridge_dir = b.clone();
        rel.bridge_record_sha256 = sha(&b.join("build-record.json"));
        rel.bridge_executable_sha256 = sha(&b.join("target/dev/templar_membership_bridge.executable.json"));
        cfg.relations = vec![rel];
        // As `serve` does: the pre-check runs on a staged copy of the bridge build.
        crate::stage_bridges(&mut cfg, &tmp.join("bridges")).unwrap();
        cfg.binaries.scarb = "/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb".into();
        // A stand-in OS run that emits the statement account's message for the transfer only: that
        // job reaches proving, where `/bin/false` is the server's own failure (a refund). The
        // transfer and the withdrawal spend the same note.
        let binding = std::fs::read_to_string(format!("{proofs}/v5-transfer/binding.txt")).unwrap();
        let runner = tmp.join("os-runner.sh");
        std::fs::write(&runner, format!(
            "#!/bin/sh\ncat > \"$2/os-result.json\" <<EOF\n{}\nEOF\n",
            json!({"os_seconds": 0.1, "resources": {"n_steps": 1}, "l2_to_l1_messages": [{"from_address": "0xacc", "to_address": "0x0",
                   "payload": ["0x5a7e", hex(&short_string("TMPZR0_PAYMENT_V5").unwrap()), "0x534e5f5345504f4c4941", "0x7e57b301", binding.trim()]}]})
        )).unwrap();
        std::fs::set_permissions(&runner, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        cfg.binaries.os_runner = runner;
        cfg.binaries.prove = "/bin/false".into();
        cfg.sandbox.cgroup_root = cgroup.into();
        cfg.payment = Some(PaymentConfig {
            required: true,
            issuer_keys: vec![IssuerKeyConfig { id: "test".into(), public_key: tmp.join("keys/test.pub.pem"), not_after: u64::MAX }],
            refund_key: Some(RefundKeyConfig { id: "test".into(), secret_key: tmp.join("keys/test.key.pem") }),
            costs: Default::default(),
            priced_assets: vec![PricedAsset { asset: "0x7e57b3a1".into(), minimum: "100".into() }],
            free: Default::default(),
            spent_dir: None,
        });
        // The node: every chain check passes.
        let calls: Calls = Arc::new(Mutex::new(HashMap::from([
            (sn_keccak("root_is_known"), vec![Felt::ONE]),
            (sn_keccak("get_nullifier_spent"), vec![Felt::ZERO]),
            (sn_keccak("get_root_superseded_at"), vec![Felt::ZERO]),
            (sn_keccak("get_verifier"), vec![felt("0xada").unwrap()]),
            (sn_keccak("get_proposal"), vec![Felt::ZERO, Felt::ZERO]),
        ])));
        // The proofs expire at 125000.
        let block = Arc::new(std::sync::atomic::AtomicU64::new(123_000));
        let rpc = Rpc::new(&stub(calls.clone(), block.clone()).await);
        let tickets = Arc::new(Tickets::load(cfg.payment.clone().unwrap(), &cfg.server.data_dir, unix_now()).unwrap());
        let state = start(cfg, rpc, json!({}), Some(tickets));
        let app = router(state.clone(), None).into_make_service_with_connect_info::<SocketAddr>();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let http = reqwest::Client::new();
        let body = |name: &str, file: &str| -> Value {
            serde_json::from_str(&std::fs::read_to_string(format!("{proofs}/{name}/{file}")).unwrap()).unwrap()
        };
        let pay = |body: &mut Value, ts: &[tickets::TicketJson]| {
            let blinded: Vec<_> = ts.iter().map(|_| issuer::refund_request(&pk).unwrap()).collect();
            let requests: Vec<String> = blinded.iter().map(|b| hex::encode(&b.0)).collect();
            body["payment"] = json!({"tickets": ts, "refund_requests": requests});
            blinded
        };
        let post = |b: Value| {
            let (http, url) = (http.clone(), url.clone());
            async move {
                let r = http.post(format!("{url}/v1/jobs")).json(&b).send().await.unwrap();
                (r.status().as_u16(), r.json::<Value>().await.unwrap())
            }
        };
        let wait_failed = |id: String| {
            let (http, url) = (http.clone(), url.clone());
            async move {
                for _ in 0..600 {
                    let s: Value = http.get(format!("{url}/v1/jobs/{id}")).send().await.unwrap().json().await.unwrap();
                    if s["status"] == "failed" || s["status"] == "done" {
                        return s;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                panic!("job {id} did not finish");
            }
        };
        let minted = issuer::mint("test", &sk, 4).unwrap();

        // No payment: refused before any check.
        let (code, v) = post(body("v5-withdrawal", "submission.json")).await;
        assert_eq!(code, 402, "{v}");
        // Paid: admitted; job start spends the ticket; the OS run (no message for the withdrawal)
        // fails, which is the client's side, so the ticket stays spent and there is no refund.
        let mut b1 = body("v5-withdrawal", "submission.json");
        pay(&mut b1, &minted[0..1]);
        let (code, v) = post(b1).await;
        assert_eq!(code, 202, "{v}");
        let s = wait_failed(v["id"].as_str().unwrap().to_string()).await;
        assert_eq!(s["stage"], "os", "{s}");
        assert!(s["refund"].is_null());
        // The failed job's note backs off (AB-SP4); the refusal releases the fresh ticket.
        let mut retry = body("v5-withdrawal", "submission.json");
        pay(&mut retry, &minted[3..4]);
        let (code, v) = post(retry).await;
        assert!(code == 429 && v["error"].as_str().unwrap().contains("recently"), "{code} {v}");
        // The transfer spends the same note: its back-off is let expire.
        state.registry.lock().unwrap().refusals.clear();
        let mut again = body("v5-transfer", "submission.json");
        pay(&mut again, &minted[0..1]);
        let (code, v) = post(again).await;
        assert!(code == 402 && v["error"].as_str().unwrap().contains("spent"), "{code} {v}");
        // A calldata mismatch consumes its ticket.
        let mut bad = body("v5-transfer", "submission.json");
        let w = bad["pool_call"]["calldata"][50].as_str().unwrap().to_string();
        bad["pool_call"]["calldata"][50] = json!(hex(&(felt(&w).unwrap() + Felt::ONE)));
        pay(&mut bad, &minted[1..2]);
        let (code, v) = post(bad).await;
        assert!(code == 400 && v["error"].as_str().unwrap().contains("pool call"), "{code} {v}");
        // A failed pre-check backs the note off too (recheck N9); the back-off is let expire.
        assert!(state.registry.lock().unwrap().refusals.values().any(|r| r.until > Instant::now()));
        state.registry.lock().unwrap().refusals.clear();
        let mut reuse = body("v5-transfer", "submission.json");
        pay(&mut reuse, &minted[1..2]);
        assert_eq!(post(reuse).await.0, 402, "a consumed ticket");
        // Bound spends are no longer served (ADR-0027): a statement naming an account, or a body
        // with a salt or a signature, is refused at parse, before its ticket is looked at.
        let mut bound = body("bound-transfer", "submission.json");
        pay(&mut bound, &minted[2..3]);
        let (code, v) = post(bound).await;
        assert!(code == 400 && v["error"].as_str().unwrap().contains("no longer served"), "{code} {v}");
        let mut salted = body("v5-transfer", "submission.json");
        salted["salt"] = json!("0x5");
        pay(&mut salted, &minted[2..3]);
        let (code, v) = post(salted).await;
        assert!(code == 400 && v["error"].as_str().unwrap().contains("no longer served"), "{code} {v}");
        let mut ok = body("v5-transfer", "submission.json");
        let blinded = pay(&mut ok, &minted[2..3]);
        let (code, v) = post(ok).await;
        assert_eq!(code, 202, "the untouched ticket pays: {v}");
        // This job passes the OS run and fails in proving, the server's fault: a blind refund on
        // the job's own request, which finalizes into a fresh ticket that pays for another job.
        let s = wait_failed(v["id"].as_str().unwrap().to_string()).await;
        assert_eq!(s["stage"], "prove", "{s}");
        let bs = hex::decode(s["refund"]["blind_signatures"][0].as_str().unwrap()).unwrap();
        let (_, nonce, blinding) = &blinded[0];
        let sig = pk.finalize(&blind_rsa_signatures::BlindSignature(bs), blinding, tickets::Ticket::message(nonce)).unwrap();
        let refunded = tickets::TicketJson {
            key_id: "test".into(), nonce: hex::encode(nonce), randomizer: hex::encode(blinding.msg_randomizer.unwrap().0),
            signature: hex::encode(&sig.0),
        };
        state.registry.lock().unwrap().refusals.clear();
        let mut next = body("v5-withdrawal", "submission.json");
        pay(&mut next, std::slice::from_ref(&refunded));
        let (code, v) = post(next).await;
        assert_eq!(code, 202, "the refunded ticket pays: {v}");
        wait_failed(v["id"].as_str().unwrap().to_string()).await;
        // A free full withdrawal needs no ticket and goes to the free queue. Its note's back-off is
        // let expire.
        state.registry.lock().unwrap().refusals.clear();
        // A forged proof for the same note is refused, and backs off only its own body, never the
        // note, so it cannot lock out the note's owner (recheck N10).
        let mut forged = body("v5-withdrawal", "free-submission.json");
        let w = forged["proof"][10].as_str().unwrap().to_string();
        forged["proof"][10] = json!(hex(&(felt(&w).unwrap() + Felt::ONE)));
        let (code, v) = post(forged.clone()).await;
        assert!(code == 400 && v["error"].as_str().unwrap().contains("Panicked with"), "{code} {v}");
        let (code, v) = post(forged).await;
        assert!(code == 429 && v["error"].as_str().unwrap().contains("pre-check"), "{code} {v}");
        // A client that disconnects during the pre-check gets no job and takes no allowance (N1).
        let quick = reqwest::Client::builder().timeout(Duration::from_millis(100)).build().unwrap();
        assert!(quick.post(format!("{url}/v1/jobs")).json(&body("v5-withdrawal", "free-submission.json")).send().await.is_err());
        for _ in 0..600 {
            if state.checks.available_permits() == state.config.server.max_concurrent_checks {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(state.registry.lock().unwrap().jobs.values().all(|j| !j.free), "no job for the abandoned submission");
        let (code, v) = post(body("v5-withdrawal", "free-submission.json")).await;
        assert_eq!(code, 202, "{v}");
        let id = v["id"].as_str().unwrap().to_string();
        assert!(state.registry.lock().unwrap().jobs[&id].free);
        wait_failed(id).await;
        // Its allowances were taken once it passed the checks (AB-SP2): one from the global bucket.
        let tokens = state.free.lock().unwrap().bucket.as_ref().unwrap().tokens;
        assert!((29.0..29.1).contains(&tokens), "{tokens}");
        // A transfer cannot take the free route.
        let mut not_free = body("v5-transfer", "submission.json");
        not_free["payment"] = json!({"free_full_withdrawal": {"openings": [[1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 5, 6, 7, 8, 9]]}});
        assert_eq!(post(not_free).await.0, 402);
        // The back-off refusal released the ticket it had reserved.
        let t = state.tickets.clone().unwrap();
        let r = t.reserve(&[Ticket::parse(&minted[3]).unwrap()], vec![issuer::refund_request(&pk).unwrap().0], unix_now()).unwrap();
        t.release(&r);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// R0 V6 through a routing adapter (pool-v3-spec §9.2, §9.5) with the real V6 bridge and a stub
    /// node: `TEMPLAR_R6_BRIDGE=<built bridge> TEMPLAR_R6_PROOFS=<sdk-proofs dir with v6-*>
    /// TEMPLAR_CGROUP=<delegated cgroup> cargo test --release -- --ignored admission_r6`. A V6
    /// transfer passes the route pins and the bridge pre-check and reaches proving; a V5 body, a
    /// changed route, a route set that is not pinned, a due change of the own route and another
    /// verifier (dormancy) are each refused before the pre-check.
    #[tokio::test]
    #[ignore]
    async fn admission_r6_routed() {
        let (Ok(bridge), Ok(proofs), Ok(cgroup)) =
            (std::env::var("TEMPLAR_R6_BRIDGE"), std::env::var("TEMPLAR_R6_PROOFS"), std::env::var("TEMPLAR_CGROUP"))
        else {
            panic!("set TEMPLAR_R6_BRIDGE, TEMPLAR_R6_PROOFS and TEMPLAR_CGROUP");
        };
        let tmp = scratch_root().join(format!("templar-admission-r6-{}", rand::random::<u32>()));
        let mut cfg = Config::load(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/prover.example.toml"))).unwrap();
        cfg.server.data_dir = tmp.join("data");
        std::fs::create_dir_all(&cfg.server.data_dir).unwrap();
        cfg.network.pool = "0x7e57b301".into();
        cfg.network.pool_version = 3;
        cfg.network.max_proof_age = 1024;
        cfg.network.parameters = Some(PoolParameters { expiry_window: 1500, quantum: 100, root_window: 4096, timelock: 7200 });
        let b = std::path::PathBuf::from(&bridge);
        let sha = |p: &std::path::Path| format!("{:x}", sha2::Sha256::digest(std::fs::read(p).unwrap()));
        // The stub node gives every address class 0xc1a55: the adapter's pin and the route's class.
        let own = crate::config::RoutePin {
            statement: "0xacc6".into(), statement_class: "0xc1a55".into(), account_tag: "TMPZR0_PAYMENT_V6".into(),
            os_program: cfg.network.os_program.clone(), proof_version: "PROOF2".into(), proof_variant: "VIRTUAL_SNOS".into(),
            output_version: "VIRTUAL_SNOS0".into(), max_proof_age: 1024,
        };
        let planned = crate::config::RoutePin { statement: "0xacc7".into(), ..own.clone() };
        let mut rel = cfg.relations[0].clone();
        rel.name = "r6".into();
        rel.account_tag = "TMPZR0_PAYMENT_V6".into();
        rel.adapter = "0xada6".into();
        rel.adapter_class = Some("0xc1a55".into());
        rel.statement_account = "0xacc6".into();
        rel.statement_class = "0xc1a55".into();
        rel.routes = vec![own.clone(), planned.clone()];
        rel.route_states = vec![vec!["0xacc6".into()], vec!["0xacc6".into(), "0xacc7".into()]];
        rel.bridge_dir = b.clone();
        rel.bridge_record_sha256 = sha(&b.join("build-record.json"));
        rel.bridge_executable_sha256 = sha(&b.join("target/dev/templar_membership_bridge.executable.json"));
        cfg.relations = vec![rel];
        crate::config::check_relation(&cfg.network, &cfg.relations[0]).unwrap();
        crate::stage_bridges(&mut cfg, &tmp.join("bridges")).unwrap();
        cfg.binaries.scarb = "/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb".into();
        // A stand-in OS run emitting the V6 statement account's message for the transfer; proving
        // is `/bin/false`.
        let binding = std::fs::read_to_string(format!("{proofs}/v6-transfer/binding.txt")).unwrap();
        let runner = tmp.join("os-runner.sh");
        std::fs::write(&runner, format!(
            "#!/bin/sh\ncat > \"$2/os-result.json\" <<EOF\n{}\nEOF\n",
            json!({"os_seconds": 0.1, "resources": {"n_steps": 1}, "l2_to_l1_messages": [{"from_address": "0xacc6", "to_address": "0x0",
                   "payload": ["0xc1a55", hex(&short_string("TMPZR0_PAYMENT_V6").unwrap()), "0x534e5f5345504f4c4941", "0x7e57b301", binding.trim()]}]})
        )).unwrap();
        std::fs::set_permissions(&runner, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        cfg.binaries.os_runner = runner;
        // A stand-in prove binary: `bucket` lands in the pinned bucket, `prove` fails (the server's
        // fault). The r6 relation is routed, so its jobs pass the bucket stage first.
        // A file next to it switches the stand-in to a bucket miss (2^26).
        let prove = tmp.join("prove.sh");
        let miss = tmp.join("bucket-miss");
        std::fs::write(&prove, format!(
            "#!/bin/sh\n[ \"$1\" = bucket ] || exit 1\nsize=25\n[ -e {} ] && size=26\necho \"{{\\\"trace_log_size\\\": $size, \\\"largest_component_log_size\\\": $size}}\" > \"$2/bucket.json\"\n",
            miss.display()
        )).unwrap();
        std::fs::set_permissions(&prove, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        cfg.binaries.prove = prove;
        cfg.sandbox.cgroup_root = cgroup.into();
        cfg.payment = None;
        let route = |p: &crate::config::RoutePin| crate::routes::route_felts(p).unwrap().to_vec();
        let calls: Calls = Arc::new(Mutex::new(HashMap::from([
            (sn_keccak("root_is_known"), vec![Felt::ONE]),
            (sn_keccak("get_nullifier_spent"), vec![Felt::ZERO]),
            (sn_keccak("get_root_superseded_at"), vec![Felt::ZERO]),
            (sn_keccak("get_verifier"), vec![felt("0xada6").unwrap()]),
            (sn_keccak("get_proposal"), vec![Felt::ZERO, Felt::ZERO]),
            (sn_keccak("get_pool"), vec![felt("0x7e57b301").unwrap()]),
            (sn_keccak("get_kind"), vec![short_string("R0").unwrap()]),
            (sn_keccak("get_routes"), [vec![Felt::ONE], route(&own)].concat()),
            (sn_keccak("get_route"), [vec![Felt::ZERO], route(&own)].concat()),
            (sn_keccak("get_route_proposals"), vec![Felt::ZERO]),
        ])));
        let block = Arc::new(std::sync::atomic::AtomicU64::new(123_000));
        let rpc = Rpc::new(&stub(calls.clone(), block.clone()).await);
        let state = start(cfg, rpc, json!({}), None);
        let app = router(state.clone(), None).into_make_service_with_connect_info::<SocketAddr>();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let http = reqwest::Client::new();
        let body = |name: &str| -> Value {
            serde_json::from_str(&std::fs::read_to_string(format!("{proofs}/{name}/submission.json")).unwrap()).unwrap()
        };
        let post = |b: Value| {
            let (http, url) = (http.clone(), url.clone());
            async move {
                let r = http.post(format!("{url}/v1/jobs")).json(&b).send().await.unwrap();
                (r.status().as_u16(), r.json::<Value>().await.unwrap())
            }
        };
        let set = |sel: &str, v: Vec<Felt>| {
            calls.lock().unwrap().insert(sn_keccak(sel), v);
        };
        let refused = |code: u16, v: &Value, what: &str| {
            assert!(code == 503 && v["error"].as_str().unwrap().contains(what), "{code} {v}");
        };

        // A V5 body: the server serves no r5 relation.
        let mut v5 = body("v6-transfer");
        v5["relation"] = json!("r5");
        v5["statement"]["account"] = json!("0x0");
        assert_eq!(post(v5).await.0, 400);
        // Another verifier: the relation is dormant.
        set("get_verifier", vec![felt("0xada5").unwrap()]);
        let (code, v) = post(body("v6-transfer")).await;
        refused(code, &v, "dormant");
        set("get_verifier", vec![felt("0xada6").unwrap()]);
        // The own route changed on chain (one field): refused.
        let changed = crate::config::RoutePin { max_proof_age: 1000, ..own.clone() };
        set("get_routes", [vec![Felt::ONE], route(&changed)].concat());
        let (code, v) = post(body("v6-transfer")).await;
        refused(code, &v, "differs from its pin");
        // A route set that is not a pinned state (the planned route alone).
        set("get_routes", [vec![Felt::ONE], route(&planned)].concat());
        let (code, v) = post(body("v6-transfer")).await;
        refused(code, &v, "not a pinned state");
        // The planned state (own + planned) serves.
        set("get_routes", [vec![Felt::TWO], route(&own), route(&planned)].concat());
        // A removal of the own route due now: refused; a change under another key is not.
        let proposal = |key: &str, eta: u64| vec![Felt::ONE, felt(key).unwrap(), Felt::ONE, Felt::from(eta)];
        set("get_route_proposals", proposal("0xacc6", 1_000_000));
        let (code, v) = post(body("v6-transfer")).await;
        refused(code, &v, "own route");
        set("get_route_proposals", proposal("0xacc8", 1_000_000));
        // The V6 bridge runs: a forged proof word is refused by the pre-check.
        let mut forged = body("v6-transfer");
        let w = forged["proof"][10].as_str().unwrap().to_string();
        forged["proof"][10] = json!(hex(&(felt(&w).unwrap() + Felt::ONE)));
        let (code, v) = post(forged).await;
        assert!(code == 400 && v["error"].as_str().unwrap().contains("Panicked with"), "{code} {v}");
        let finished = |id: String| {
            let (http, url) = (http.clone(), url.clone());
            async move {
                for _ in 0..600 {
                    let s: Value = http.get(format!("{url}/v1/jobs/{id}")).send().await.unwrap().json().await.unwrap();
                    if s["status"] == "failed" || s["status"] == "done" {
                        return s;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                panic!("job {id} did not finish");
            }
        };
        // A job that misses the bucket is not proved: it fails at the bucket stage, the server's
        // fault (pool-v3-spec §9.3), and its note backs off.
        std::fs::write(&miss, "").unwrap();
        let (code, v) = post(body("v6-transfer")).await;
        assert_eq!(code, 202, "{v}");
        let s = finished(v["id"].as_str().unwrap().to_string()).await;
        assert!(s["status"] == "failed" && s["stage"] == "bucket", "{s}");
        assert!(state.registry.lock().unwrap().refusals.values().any(|r| r.until > Instant::now()), "the note backs off");
        state.registry.lock().unwrap().refusals.clear();
        std::fs::remove_file(&miss).unwrap();
        // Admitted: the pins hold and the V6 bridge accepts the real proof; the job passes the
        // bucket stage and reaches proving.
        let (code, v) = post(body("v6-transfer")).await;
        assert_eq!(code, 202, "{v}");
        let s = finished(v["id"].as_str().unwrap().to_string()).await;
        assert_eq!(s["stage"], "prove", "{s}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

// The prover-server client (spec §8): info checked against the pins, one submission per job, then
// polling only; with OHTTP every request goes through the relay and none goes to the server.
import { call, wasm, type ServerResult } from './core.js';
import { TemplarError, fail } from './errors.js';
import { sameFelt, versionOf, type NetworkConstants, type PoolConstants } from './network.js';

export interface OhttpConfig {
  /** The relay's URL; it must forward to this server's gateway and carry 4 MB requests. */
  relayUrl: string;
  /** The server's key configuration list (pinned or supplied out of band; never fetched here). */
  keyConfig: Uint8Array;
}

export interface ProverOptions {
  url: string;
  ohttp?: OhttpConfig;
  fetch?: typeof globalThis.fetch;
}

export interface JobStatus {
  status: 'queued' | 'running' | 'done' | 'failed';
  stage?: string;
  position?: number;
  result?: ServerResult & Record<string, unknown>;
  error?: string;
  /** Replacement tickets for a job the server failed: blind signatures on the job's requests. */
  refund?: { key_id: string; blind_signatures: string[] } | { owed: number; error: string };
}

export interface ServerInfo {
  network: { chain_id: string; pool: string; os_program: string; max_proof_age: number };
  relations: { name: string; statement_account: string; statement_class: string; account_tag: string; adapter: string; circuit_hash_u32_le: number[] }[];
  limits: { retention_secs: number; [k: string]: unknown };
  [k: string]: unknown;
}

const hexBytes = (h: string): Uint8Array => new Uint8Array((h.replace(/^0x/, '').match(/../g) ?? []).map((b) => parseInt(b, 16)));

export class ProverClient {
  private f: typeof globalThis.fetch;
  private verified = false;
  constructor(
    private opts: ProverOptions,
    private network: NetworkConstants,
    private pool: PoolConstants,
  ) {
    this.f = opts.fetch ?? globalThis.fetch.bind(globalThis);
    // A pinned server's key configuration must match (spec §8, SDK-M5).
    const pinned = network.provers.find((p) => p.url === opts.url)?.ohttpKeyConfig;
    if (opts.ohttp && pinned) {
      const given = [...opts.ohttp.keyConfig].map((b) => b.toString(16).padStart(2, '0')).join('');
      if (given !== pinned.replace(/^0x/, '').toLowerCase()) fail('ohttp_key', 'the OHTTP key configuration differs from the pinned one');
    }
  }

  /** One HTTP exchange, directly or inside an OHTTP envelope through the relay. */
  private async request(method: 'GET' | 'POST', path: string, body?: string): Promise<{ status: number; text: string }> {
    const bytes = new TextEncoder().encode(body ?? '');
    if (this.opts.ohttp) {
      const req = call(() => new wasm.OhttpRequest(this.opts.ohttp!.keyConfig, method, path, bytes));
      const r = await this.f(this.opts.ohttp.relayUrl, {
        method: 'POST',
        headers: { 'content-type': 'message/ohttp-req' },
        body: req.envelope() as unknown as BodyInit,
      });
      if (!r.ok) fail('ohttp_relay', `the relay answered ${r.status}`);
      const response = new Uint8Array(await r.arrayBuffer());
      const opened = JSON.parse(call(() => req.open(response))) as { status: number; body: number[] };
      return { status: opened.status, text: new TextDecoder().decode(new Uint8Array(opened.body)) };
    }
    const r = await this.f(new URL(path, this.opts.url), {
      method,
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body }),
    });
    return { status: r.status, text: await r.text() };
  }

  /** `GET /v1/info`, which must agree with the pins; otherwise this server is refused. */
  async info(): Promise<ServerInfo> {
    const r = await this.request('GET', '/v1/info');
    if (r.status !== 200) fail('prover_info', `status ${r.status}`);
    const info = JSON.parse(r.text) as ServerInfo;
    // Pool V2 serves R0 V4 (`r4`); pool V3 R0 V5 (`r5`).
    const rel = info.relations?.find((x) => x.name === (versionOf(this.pool) === 'v5' ? 'r5' : 'r4'));
    const p = this.pool;
    const agree =
      rel &&
      sameFelt(info.network.chain_id.startsWith('0x') ? info.network.chain_id : '0x' + [...new TextEncoder().encode(info.network.chain_id)].map((b) => b.toString(16).padStart(2, '0')).join(''), this.network.chainId) &&
      sameFelt(info.network.pool, p.pool) &&
      sameFelt(info.network.os_program, p.osProgram) &&
      info.network.max_proof_age === p.maxProofAge &&
      sameFelt(rel.statement_account, p.statement) &&
      sameFelt(rel.statement_class, p.statementClass) &&
      sameFelt(rel.adapter, p.adapter) &&
      rel.account_tag === p.accountTag &&
      JSON.stringify(rel.circuit_hash_u32_le) === JSON.stringify(p.circuitHash);
    if (!agree) fail('prover_mismatch', 'the server serves another pool, statement account or circuit than the pinned one');
    if (versionOf(p) === 'v5') {
      // R0 V5 (account-bound spec §9, Info): the spend message's hashes are the core's, and the pool
      // parameters are the pinned ones (AB-SP19).
      const r5 = info.r5 as { spend_message?: { domain_type_hash?: string; spend_type_hash?: string }; pool_parameters?: Record<string, number> } | undefined;
      const d = JSON.parse(call(() => wasm.spend_domain())) as { domain_type_hash: string; spend_type_hash: string };
      const pp = r5?.pool_parameters;
      const want = p.parameters;
      const ok =
        r5?.spend_message?.domain_type_hash !== undefined &&
        sameFelt(r5.spend_message.domain_type_hash, d.domain_type_hash) &&
        r5.spend_message.spend_type_hash !== undefined &&
        sameFelt(r5.spend_message.spend_type_hash, d.spend_type_hash) &&
        want !== undefined &&
        pp?.expiry_window === want.expiryWindow &&
        pp?.quantum === want.quantum &&
        pp?.root_window === want.rootWindow &&
        pp?.timelock === want.timelock;
      if (!ok) fail('prover_mismatch', 'the server publishes another spend message or pool parameters than the pinned ones');
    }
    this.verified = true;
    return info;
  }

  /**
   * Submits once (`body` is stored in the in-flight record before this call). 409 and 429 are
   * reported, never retried (spec §8, SDK-P3).
   */
  async submit(body: string): Promise<string> {
    if (!this.verified) await this.info();
    const r = await this.request('POST', '/v1/jobs', body);
    if (r.status === 202) return (JSON.parse(r.text) as { id: string }).id;
    const parsed = (() => {
      try {
        return JSON.parse(r.text) as { error?: string; reason?: string };
      } catch {
        return {};
      }
    })();
    const reason = parsed.error ?? r.text;
    const code =
      r.status === 409 ? 'prover_conflict'
      : r.status === 429 ? 'prover_rate_limited'
      : r.status === 400 ? 'prover_rejected'
      : r.status === 402 ? 'prover_payment'
      // 403: the account refused the signature (authorize again), or its class is not served.
      : r.status === 403 ? (parsed.reason === 'account_class' ? 'prover_account_class' : 'prover_forbidden')
      : 'prover_error';
    throw new TemplarError(code, `${r.status}: ${reason}`);
  }

  async status(id: string): Promise<JobStatus> {
    const r = await this.request('GET', `/v1/jobs/${id}`);
    if (r.status !== 200) fail('prover_job', `status ${r.status}`);
    return JSON.parse(r.text) as JobStatus;
  }

  /** Polls until the job is done or failed. */
  async wait(id: string, opts: { intervalMs?: number; timeoutMs?: number; onStatus?: (s: JobStatus) => void } = {}): Promise<ServerResult> {
    const deadline = Date.now() + (opts.timeoutMs ?? 30 * 60_000);
    let interval = opts.intervalMs ?? 5_000;
    for (;;) {
      const s = await this.status(id);
      opts.onStatus?.(s);
      if (s.status === 'done' && s.result) return s.result;
      if (s.status === 'failed') fail('prover_failed', `${s.stage ?? ''} ${s.error ?? ''}`.trim());
      if (Date.now() > deadline) fail('prover_timeout', `job ${id} not done`);
      await new Promise((r) => setTimeout(r, interval));
      interval = Math.min(interval * 1.5, 30_000);
    }
  }
}

export { hexBytes };

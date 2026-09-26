// The prover-server client (spec §8): info checked against the pins, one submission per job, then
// polling only; with OHTTP every request goes through the relay and none goes to the server.
import { call, wasm, type ServerResult } from './core.js';
import { TemplarError, fail } from './errors.js';
import { r0Generations, routeOf, sameFelt, versionOf, type Generation, type NetworkConstants, type PoolConstants } from './network.js';

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
  /** The relayer's answer for an R0 V5 job (account-bound spec §7.3, AB-P31). */
  relay?: RelayStatus | null;
}

/** What the service's relayer did with a proved spend. */
export type RelayStatus =
  | { status: 'pending' }
  | { status: 'submitted'; transaction_hash: string }
  | { status: 'refused'; reason: string }
  | { status: 'expired' };

export interface ServerInfo {
  network: { chain_id: string; pool: string; os_program: string; max_proof_age: number };
  relations: {
    name: string; statement_account: string; statement_class: string; account_tag: string; adapter: string; circuit_hash_u32_le: number[];
    /** A routed relation (docs/pool-v3-spec.md §9.5): its adapter's class and the server's own route. */
    adapter_class?: string | null;
    route?: { statement: string; statement_class: string; account_tag: string; os_program: string; proof_version: string; proof_variant: string; output_version: string; max_proof_age: number } | null;
    max_proof_age?: number;
  }[];
  limits: { retention_secs: number; [k: string]: unknown };
  /** Whether the service submits the spends it proves (§7.4); absent or false for a self-hosted server. */
  relay?: { enabled: boolean };
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

  private cached?: ServerInfo;

  /**
   * `GET /v1/info`, which must agree with the pins; otherwise this server is refused. Every R0
   * relation it serves must match a pinned generation (docs/pool-v3-spec.md §10.2): the flat fields'
   * pre-cutover relation, or a routing generation with the server's own route.
   */
  async info(): Promise<ServerInfo> {
    const r = await this.request('GET', '/v1/info');
    if (r.status !== 200) fail('prover_info', `status ${r.status}`);
    const info = JSON.parse(r.text) as ServerInfo;
    const p = this.pool;
    const chain = info.network.chain_id.startsWith('0x') ? info.network.chain_id : '0x' + [...new TextEncoder().encode(info.network.chain_id)].map((b) => b.toString(16).padStart(2, '0')).join('');
    if (!sameFelt(chain, this.network.chainId) || !sameFelt(info.network.pool, p.pool)) fail('prover_mismatch', 'the server serves another chain or pool');
    const r0 = (info.relations ?? []).filter((x) => ['r4', 'r5', 'r6'].includes(x.name));
    if (r0.length === 0) fail('prover_mismatch', 'the server serves no R0 relation');
    for (const rel of r0) {
      const g = r0Generations(p).find((x) => x.relation === rel.name && sameFelt(x.adapter, rel.adapter));
      if (!g || !relationAgrees(info, rel, g)) fail('prover_mismatch', `the server serves another pool, statement account or circuit than the pinned one (${rel.name})`);
    }
    if (versionOf(p) === 'v5') {
      // R0 V5 and V6 (account-bound spec §9, pool-v3-spec §9.5, Info): the pool parameters are the
      // pinned ones (AB-SP19).
      const section = (info.r6 ?? info.r5) as { pool_parameters?: Record<string, number> } | undefined;
      const pp = section?.pool_parameters;
      const want = p.parameters;
      const ok =
        want !== undefined &&
        pp?.expiry_window === want.expiryWindow &&
        pp?.quantum === want.quantum &&
        pp?.root_window === want.rootWindow &&
        pp?.timelock === want.timelock;
      if (!ok) fail('prover_mismatch', 'the server publishes other pool parameters than the pinned ones');
    }
    this.verified = true;
    this.cached = info;
    return info;
  }

  /** The server serves the generation's relation for its primary route (the spends it proves). */
  async checkRelation(g: Generation): Promise<ServerInfo> {
    const info = this.cached ?? (await this.info());
    const rel = info.relations.find((x) => x.name === g.relation && sameFelt(x.adapter, g.adapter));
    if (!rel || !relationAgrees(info, rel, g) || !sameFelt(rel.statement_account, g.primary)) {
      fail('prover_mismatch', `the server does not serve ${g.relation} for the pinned route`);
    }
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
      : 'prover_error';
    throw new TemplarError(code, `${r.status}: ${reason}`);
  }

  async status(id: string): Promise<JobStatus> {
    const r = await this.request('GET', `/v1/jobs/${id}`);
    // A job gone at retention (404) is told apart from a server that did not answer (AB-RL3).
    if (r.status === 404) fail('prover_job_gone', 'no such job');
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

/** A served relation equals a pinned generation: its route (statement, class, tag), adapter and circuit. */
function relationAgrees(info: ServerInfo, rel: ServerInfo['relations'][number], g: Generation): boolean {
  const route = routeOf(g, rel.statement_account);
  if (!route || !sameFelt(rel.statement_class, route.statementClass) || rel.account_tag !== route.accountTag) return false;
  if (JSON.stringify(rel.circuit_hash_u32_le) !== JSON.stringify(g.circuitHash)) return false;
  if (!g.routing) return sameFelt(info.network.os_program, route.osProgram) && info.network.max_proof_age === route.maxProofAge;
  const r = rel.route;
  return (
    rel.adapter_class != null &&
    sameFelt(rel.adapter_class, g.adapterClass) &&
    r != null &&
    sameFelt(r.statement, route.statement) &&
    sameFelt(r.os_program, route.osProgram) &&
    r.proof_version === (route.proofVersion ?? 'PROOF2') &&
    r.proof_variant === (route.proofVariant ?? 'VIRTUAL_SNOS') &&
    r.output_version === (route.outputVersion ?? 'VIRTUAL_SNOS0') &&
    r.max_proof_age === route.maxProofAge
  );
}

export { hexBytes };

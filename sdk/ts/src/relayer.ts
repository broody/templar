// The relayer (docs/account-bound-note-spec.md §7.3, §7.4; P4b). It takes each finished R0 V5
// result from the prover server that proved it, runs the acceptance checks, submits the spend from
// the service's own account, and answers the job with the transaction hash or a refusal and its
// reason. It keeps only the nullifiers of what it submitted (with the transaction hash), until each
// deadline, and the notes whose relayed transaction reverted.
//
// The one harm it must never cause is a second transaction beside the wallet's fallback (AB-P31).
// So it answers a job with a refusal only when nothing was sent: a send whose outcome is unknown,
// or a second job for notes it already sent, is answered with the transaction hash, which the
// wallet then watches.
import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import { Account, RpcProvider, Signer } from 'starknet';

import { checkSpecVersion, checkVerifier } from './chain.js';
import type { Hex, ServerResult } from './core.js';
import { TemplarError, fail } from './errors.js';
import { canon, sameFelt, versionOf, type PoolConstants } from './network.js';
import { prepare, send, type Prepared } from './submit.js';
import { FALLBACK_MARGIN } from './wallet.js';

/** One result waiting at the prover server's handoff (`GET /relay/v1/jobs`). */
export interface RelayItem {
  id: string;
  result: ServerResult;
  nullifiers: Hex[][];
  root: Hex[];
  send_deadline: number;
}

export type Outcome = { transaction_hash: Hex } | { refused: string };

/** What the relayer keeps across restarts (AB-RL6). */
export interface RelayerState {
  /** Nullifier → the spend's deadline and the relayer's transaction for it. */
  submitted: Record<string, { deadline: number; tx: Hex }>;
  /** Nullifiers of spends whose relayed transaction reverted: never relayed again (AB-RL7). */
  denied: Record<string, true>;
  /** The relayer's own transactions not yet final: hash → nonce, nullifiers, deadline, send block. */
  inflight: Record<Hex, { nonce: string; keys: string[]; deadline: number; sentAt: number }>;
  /** The next nonce to use, when known locally. */
  nextNonce?: string;
}

export interface StateStore {
  load(): RelayerState | undefined;
  save(s: RelayerState): void;
}

/** A JSON file, replaced atomically. */
export function fileStore(path: string): StateStore {
  return {
    load: () => {
      try {
        return JSON.parse(readFileSync(path, 'utf8')) as RelayerState;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
        throw e;
      }
    },
    save: (s) => {
      writeFileSync(`${path}.tmp`, JSON.stringify(s));
      renameSync(`${path}.tmp`, path);
    },
  };
}

export interface RelayerOptions {
  /** The pool it relays for: a pool V3 (R0 V5). */
  pool: PoolConstants;
  /** The relayer's own node. */
  provider: RpcProvider;
  /** The service's submitting account, the same for every spend (§7.4). */
  account: Account;
  /** The hash of the transaction `prepare` signed (`CapturingSigner.lastHash` in production). */
  hashOf: (p: Prepared) => Hex;
  /** The prover server's handoff listener and its bearer token. */
  handoff: { url: string; token: string; fetch?: typeof globalThis.fetch };
  /**
   * §7.3: a spend is relayed only while `send_deadline ≥ latest + marginBlocks`. At least
   * `FALLBACK_MARGIN + 20` (the default): once a wallet may fall back, the relayer never submits
   * anew, with room for its node's lag and inclusion (AB-P31, AB-RL8).
   */
  marginBlocks?: number;
  /** The largest maximum fee (fri) it pays for one spend. */
  maxFee: bigint;
  /** Exit assets it relays (an exit calls the asset; others could revert once included, AB-RL7). */
  assets: Hex[];
  state?: StateStore;
  /** Blocks after which its own pending transaction counts as stuck (new jobs then wait). */
  stuckBlocks?: number;
  /**
   * Seconds after which the node's latest block counts as stale (nothing is sent then). Default
   * 30, below the 20 blocks between its margin and the wallet's (AB-RL8b).
   */
  staleSecs?: number;
  /** Where outcomes are logged: job ids and outcome kinds only, never nullifiers or amounts. */
  log?: (line: string) => void;
}

/** Blocks after the base block before the sequencer accepts a proof (as `check_result`). */
const SUBMIT_DELAY = 11;

const key = (nf: Hex[]) => nf.map((x) => BigInt(x).toString(16)).join(',');
const span = (xs: Hex[]) => [String(xs.length), ...xs];

/** A starknet.js signer that remembers the last hash it signed: the transaction hash. */
export class CapturingSigner extends Signer {
  lastHash?: Hex;
  protected override async signRaw(msgHash: string): Promise<import('starknet').Signature> {
    this.lastHash = canon(msgHash);
    return super.signRaw(msgHash);
  }
}

/** RPC error 29: the node does not know the transaction. */
const notFound = (e: unknown) => (e as { baseError?: { code?: number } }).baseError?.code === 29;

export class Relayer {
  private s: RelayerState;
  /** Jobs already answered, until the server stops listing them. */
  private answered = new Set<string>();
  /** Answers the server has not acknowledged yet: sent again first (AB-RL1). */
  private unreported = new Map<string, Outcome>();
  private margin: number;
  private f: typeof globalThis.fetch;
  private warnedMargin = false;

  constructor(private o: RelayerOptions) {
    if (versionOf(o.pool) !== 'v5' || !o.pool.parameters) fail('wrong_relation', 'the relayer serves a pool V3');
    this.margin = o.marginBlocks ?? FALLBACK_MARGIN + 20;
    if (this.margin < FALLBACK_MARGIN + 20) fail('relay_margin', `marginBlocks must be at least the wallet's fallback margin plus 20 (${FALLBACK_MARGIN + 20})`);
    if (!o.handoff.token) fail('relay_token', 'the handoff needs its bearer token');
    this.f = o.handoff.fetch ?? globalThis.fetch.bind(globalThis);
    this.s = o.state?.load() ?? { submitted: {}, denied: {}, inflight: {} };
  }

  private save(): void {
    this.o.state?.save(this.s);
  }

  private async handoff(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.o.handoff.token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) };
    return this.f(new URL(path, this.o.handoff.url), { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  }

  private async report(id: string, outcome: Outcome): Promise<void> {
    try {
      const r = await this.handoff('POST', `/relay/v1/jobs/${encodeURIComponent(id)}`, outcome);
      if (r.status === 200 || r.status === 404) {
        this.unreported.delete(id);
        return;
      }
    } catch {
      /* kept for the next pass */
    }
    this.unreported.set(id, outcome);
  }

  /** The latest block, or `undefined` when the node lags (its latest block is older than `staleSecs`). */
  private async fresh(): Promise<number | undefined> {
    const latest = (await this.o.provider.getBlockLatestAccepted()).block_number;
    const b = (await this.o.provider.getBlockWithTxHashes(latest)) as { timestamp?: number };
    if (b.timestamp === undefined || Date.now() / 1000 - b.timestamp > (this.o.staleSecs ?? 30)) return undefined;
    return latest;
  }

  /**
   * Its own transactions not yet final: a revert denies those notes for good (AB-RL7); a
   * rejection or a transaction the node lost resets the nonce; one pending past `stuckBlocks`
   * makes new jobs wait (AB-RL4). Returns whether one is stuck.
   */
  private async track(latest: number): Promise<boolean> {
    let stuck = false;
    for (const [tx, t] of Object.entries(this.s.inflight)) {
      let st: { finality_status?: string; execution_status?: string } | undefined;
      try {
        st = (await this.o.provider.getTransactionStatus(tx)) as typeof st;
      } catch (e) {
        if (!notFound(e)) throw e;
      }
      const old = latest - t.sentAt > (this.o.stuckBlocks ?? 20);
      if (st?.execution_status === 'REVERTED') {
        for (const k of t.keys) this.s.denied[k] = true;
        delete this.s.inflight[tx];
      } else if (st?.finality_status === 'ACCEPTED_ON_L2' || st?.finality_status === 'ACCEPTED_ON_L1') {
        delete this.s.inflight[tx];
      } else if (st?.finality_status === 'REJECTED' || (!st && old)) {
        delete this.s.inflight[tx];
        delete this.s.nextNonce;
      } else if (old) {
        stuck = true;
      }
    }
    for (const [k, v] of Object.entries(this.s.submitted)) if (v.deadline < latest) delete this.s.submitted[k];
    this.save();
    return stuck;
  }

  /**
   * One pass: answers not yet acknowledged are sent again, the relayer's own transactions are
   * tracked, then the waiting results are taken earliest deadline first, one at a time (one nonce
   * sequence). A result whose base block is too recent waits.
   */
  async tick(): Promise<{ id: string; outcome: Outcome }[]> {
    const r = await this.handoff('GET', '/relay/v1/jobs');
    if (r.status !== 200) fail('relay_handoff', `the handoff answered ${r.status}`);
    const listing = (await r.json()) as { jobs: RelayItem[]; relay_margin_blocks?: number };
    if (!this.warnedMargin && listing.relay_margin_blocks !== undefined && listing.relay_margin_blocks < this.margin) {
      this.warnedMargin = true;
      this.o.log?.(`the server's relay_margin_blocks (${listing.relay_margin_blocks}) is below this relayer's margin (${this.margin}): some admitted jobs will be refused`);
    }
    const listed = new Set(listing.jobs.map((i) => i.id));
    for (const id of this.answered) if (!listed.has(id)) this.answered.delete(id);
    for (const [id, outcome] of [...this.unreported]) await this.report(id, outcome);
    const done: { id: string; outcome: Outcome }[] = [];
    const latest = await this.fresh();
    if (latest === undefined) {
      this.o.log?.('the node lags: nothing is sent this pass');
      return done;
    }
    if (await this.track(latest)) {
      this.o.log?.('a relayer transaction is stuck: new jobs wait');
      return done;
    }
    for (const item of listing.jobs) {
      if (this.answered.has(item.id) || this.unreported.has(item.id)) continue;
      let outcome: Outcome | { skip: true } | undefined;
      try {
        outcome = await this.decide(item);
      } catch (e) {
        outcome = { refused: e instanceof TemplarError ? e.message : `relayer error: ${(e as Error).message ?? e}` };
      }
      if (!outcome) continue;
      this.answered.add(item.id);
      if ('skip' in outcome) continue;
      await this.report(item.id, outcome);
      this.o.log?.(`job ${item.id}: ${'transaction_hash' in outcome ? 'submitted' : 'refused'}`);
      done.push({ id: item.id, outcome });
    }
    return done;
  }

  /** Polls until `signal` aborts. */
  async run(opts: { intervalMs?: number; signal?: AbortSignal } = {}): Promise<void> {
    while (!opts.signal?.aborted) {
      try {
        await this.tick();
      } catch (e) {
        this.o.log?.(`pass failed: ${(e as Error).message ?? e}`);
      }
      await new Promise((r) => setTimeout(r, opts.intervalMs ?? 2_000));
    }
  }

  /**
   * §7.3 acceptance, then the claim and the submission. `undefined` while the base block is too
   * recent; `{skip}` when the server already answered the job (it refused it for lateness).
   */
  async decide(item: RelayItem): Promise<Outcome | { skip: true } | undefined> {
    const refuse = (reason: string): Outcome => ({ refused: reason });
    const { pool, provider } = this.o;
    const res = item.result;
    const call = res.pool_call;
    const latest = (await provider.getBlockLatestAccepted()).block_number;
    // Invokes need the SDK's tight minimums before a relayer may see them first (F06).
    if (!call || call.entry_point !== 'apply_spend') return refuse('invoke spends are not relayed yet: they need tight minimums (F06)');
    if (item.nullifiers.length !== 2 || item.nullifiers.some((n) => n.length !== 9) || item.root.length !== 9 || call.calldata.length < 3) return refuse('malformed relay item');
    const keys = item.nullifiers.map(key);
    // Notes it already sent: the answer is that transaction, for the wallet to watch (AB-RL1).
    const earlier = keys.map((k) => this.s.submitted[k]).find((x) => x !== undefined);
    if (earlier) return { transaction_hash: earlier.tx };
    if (keys.some((k) => this.s.denied[k])) return refuse('a relayed spend of these notes reverted before');
    // An exit calls its asset: only allowlisted assets are relayed (AB-RL7).
    const asset = call.calldata[2]!;
    if (BigInt(asset) !== 0n && !this.o.assets.some((a) => sameFelt(a, asset))) return refuse('exits of this asset are not relayed');
    if (item.send_deadline < latest + this.margin) return refuse(`the deadline ${item.send_deadline} is too close to the latest block ${latest}`);
    if (latest < res.base_block + SUBMIT_DELAY) return undefined;
    try {
      await checkVerifier(provider, pool);
    } catch (e) {
      return refuse((e as Error).message);
    }
    // The root the pool still accepts in the blocks the spend can land in (§8.3).
    const [known] = await provider.callContract({ contractAddress: pool.pool, entrypoint: 'root_is_known', calldata: span(item.root) });
    const [superseded] = await provider.callContract({ contractAddress: pool.pool, entrypoint: 'get_root_superseded_at', calldata: span(item.root) });
    const s = Number(BigInt(superseded ?? 0));
    if (BigInt(known ?? 0) !== 1n || (s !== 0 && s - 1 + pool.parameters!.rootWindow < latest + this.margin)) return refuse('the root is unknown or expiring');
    for (const nf of item.nullifiers) {
      const [spent] = await provider.callContract({ contractAddress: pool.pool, entrypoint: 'get_nullifier_spent', calldata: span(nf) });
      if (BigInt(spent ?? 1) !== 0n) return refuse('a nullifier is already spent');
    }
    // The next nonce: its own counter, never below the chain's at pre_confirmed (AB-RL4).
    const chainNonce = BigInt(await provider.getNonceForAddress(this.o.account.address, 'pre_confirmed'));
    const nonce = this.s.nextNonce !== undefined && BigInt(this.s.nextNonce) > chainNonce ? BigInt(this.s.nextNonce) : chainNonce;
    let prepared: Prepared;
    try {
      prepared = await prepare(this.o.account, { contractAddress: pool.pool, entrypoint: 'apply_spend', calldata: call.calldata }, res.proof, res.proof_facts, { nonce });
    } catch (e) {
      return refuse(e instanceof TemplarError ? e.message : `simulation: ${(e as Error).message ?? e}`);
    }
    if (prepared.maxFee > this.o.maxFee) return refuse(`the maximum fee ${prepared.maxFee} is above this relayer's cap`);
    // The margin again, just before sending (preparing takes time, AB-RL8).
    const now = (await provider.getBlockLatestAccepted()).block_number;
    if (item.send_deadline < now + this.margin) return refuse(`the deadline ${item.send_deadline} is too close to the latest block ${now}`);
    // The claim: the server has not refused it for lateness, and nobody else took it (AB-RL9).
    const claim = await this.handoff('POST', `/relay/v1/jobs/${encodeURIComponent(item.id)}/claim`);
    if (claim.status !== 200) return { skip: true };
    const tx = this.o.hashOf(prepared);
    // Recorded before sending: from here on, this job and any other for these notes are answered
    // with this hash, whatever the send returns.
    for (const k of keys) this.s.submitted[k] = { deadline: item.send_deadline, tx };
    this.s.inflight[tx] = { nonce: nonce.toString(), keys, deadline: item.send_deadline, sentAt: now };
    this.s.nextNonce = (nonce + 1n).toString();
    this.save();
    try {
      const sent = canon(await send(this.o.account, prepared));
      if (sent !== tx) this.o.log?.(`job ${item.id}: the node returned another transaction hash than the one signed`);
    } catch (e) {
      // The outcome is unknown: the transaction may have left. The wallet watches the hash and
      // falls back only if it never lands; the nonce is read from the chain again. Nothing here
      // may turn the answer into a refusal.
      delete this.s.nextNonce;
      try {
        this.save();
      } catch (s) {
        this.o.log?.(`saving the state failed: ${(s as Error).message ?? s}`);
      }
      this.o.log?.(`job ${item.id}: send failed (${(e as Error).message ?? e}); answered with the signed hash`);
    }
    return { transaction_hash: tx };
  }
}

/** The service's configuration file (`server/relayer/relayer.example.json`). */
export interface RelayerConfig {
  /** The pool constants, as in the SDK's network constants. */
  pool: PoolConstants;
  chainId: Hex;
  nodeUrl: string;
  account: { address: Hex; keyFile: string };
  handoff: { url: string; tokenFile: string };
  /** Where its nullifiers, denials and nonce survive restarts. */
  stateFile: string;
  /** Exit assets it relays. */
  assets: Hex[];
  marginBlocks?: number;
  staleSecs?: number;
  stuckBlocks?: number;
  /** Decimal fri. */
  maxFee: string;
}

/** Builds a relayer from its configuration: the node checked, the key read from its file. */
export async function createRelayer(config: RelayerConfig, log?: (line: string) => void): Promise<Relayer> {
  const provider = new RpcProvider({ nodeUrl: config.nodeUrl, blockIdentifier: 'pre_confirmed' });
  await checkSpecVersion(provider);
  if (BigInt(await provider.getChainId()) !== BigInt(config.chainId)) fail('wrong_chain', 'the node is on another chain');
  const signer = new CapturingSigner(readFileSync(config.account.keyFile, 'utf8').trim());
  const account = new Account({ provider, address: config.account.address, signer });
  const token = readFileSync(config.handoff.tokenFile, 'utf8').trim();
  return new Relayer({
    pool: config.pool,
    provider,
    account,
    hashOf: () => signer.lastHash ?? fail('relay_hash', 'no signed transaction'),
    handoff: { url: config.handoff.url, token },
    maxFee: BigInt(config.maxFee),
    assets: config.assets,
    state: fileStore(config.stateFile),
    ...(config.marginBlocks !== undefined ? { marginBlocks: config.marginBlocks } : {}),
    ...(config.staleSecs !== undefined ? { staleSecs: config.staleSecs } : {}),
    ...(config.stuckBlocks !== undefined ? { stuckBlocks: config.stuckBlocks } : {}),
    ...(log ? { log } : {}),
  });
}

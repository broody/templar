// The wallet (spec §6, §7, §9): sync with completeness and reorg rollback, balances, deposits,
// spends and their in-flight records. Protocol values come from the core; this layer moves data,
// persists state and talks to starknet.js and the prover server.
import type { Account, Call, RpcProvider } from 'starknet';

import { SELECTORS, checkSpecVersion, checkVerifier, fetchPoolEvents, leafCountAndRoot, verifyPins, type PoolEvent } from './chain.js';
import {
  call,
  json,
  loadCore,
  wasm,
  type AccountInfo,
  type AssetKind,
  type Companion,
  type Digest,
  type Hex,
  type NoteRef,
  type OwnedNote,
  type Plan,
  type Proved,
  type ServerResult,
  type SpendRequest,
  type Window,
} from './core.js';
import { TemplarError, fail } from './errors.js';
import { activePool, canon, pinsOf, sameFelt, type NetworkConstants, type PoolConstants } from './network.js';
import { proveInWorker, type ProveOptions } from './prove.js';
import { ProverClient, type ProverOptions } from './prover.js';
import { WalletStore, type KV } from './store.js';
import { prepare, send, type Prepared } from './submit.js';

/** Blocks a note must be buried before it is spent, and after which a record's eviction counts. */
export const DEPTH = 10;
/** Checkpoint spacing in blocks (spec §6). */
export const CHECKPOINT_EVERY = 1000;
/** Account indexes above the highest used one that are scanned (the gap limit, spec §3.2). */
export const GAP = 3;
/** A root taken at leaf count m is evicted once the leaf count reaches m + 512 (spec §9.1). */
export const EVICTION_LEAVES = 512;
/** Blocks before `valid_until` after which a result is not sent. */
export const WINDOW_MARGIN = 20;
const CHUNK = 1024;

const ISRC6_ID = '0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd';
const IERC1155_RECEIVER_ID = '0x15e8665b5af20040c3af1670509df02eb916375cdf7d8cbaf7bd553a257515e';

const key = (d: Digest) => d.join(',');

interface Checkpoint {
  block: number;
  hash: string;
  leaves: number;
  nullifiers: number;
  registry: number;
  settlements: number;
  deposited: number;
}

interface Registered {
  asset: Hex;
  standard: number;
  contract: Hex;
  idLow: string;
  idHigh: string;
}

interface StoredNote extends OwnedNote {
  block: number;
}

interface SyncState {
  /** The last complete-or-not synced block, -1 before the first sync. */
  block: number;
  leaves: number;
  checkpoints: Checkpoint[];
  nullifiers: string[];
  notes: StoredNote[];
  registry: Registered[];
  settlements: { firstIndex: number; x: string }[];
  deposited: Hex[];
  /** Highest account index handed out. */
  created: number;
  complete: boolean;
  problems: string[];
}

interface LeafChunk {
  commitments: Digest[];
  digests: Hex[];
  words: Hex[][];
  blocks: number[];
}

export type RecordStage = 'planned' | 'proved' | 'sent_to_server' | 'wrapped' | 'sent_to_chain' | 'settled' | 'dead';

/** An in-flight spend (spec §9.1). */
export interface SpendRecord {
  id: string;
  stage: RecordStage;
  /** Whether its statement has ever left the wallet (then only root eviction ends it). */
  left: boolean;
  request: SpendRequest;
  plan: Plan;
  inputs: number[];
  proved?: Proved;
  server?: { url: string; jobId?: string; body: string };
  result?: ServerResult;
  window?: Window;
  tx?: { hash: string; nonce: string; maxFee: string; expectedFee: string };
  /** Why a record was closed. */
  closed?: string;
}

export interface Balance {
  asset: Hex;
  kind: AssetKind;
  /** Unspent received value. */
  unspent: bigint;
  /** Of which spendable now (buried, not in a live record). */
  spendable: bigint;
  notes: number;
  /** A pinned token, or `undefined` for an unverified asset (spec §6). */
  token?: { symbol: string; decimals: number };
}

export interface SyncResult {
  complete: boolean;
  block: number;
  problems: string[];
  balances: Balance[];
}

export interface AssetSpec {
  standard: 20 | 721 | 1155;
  contract: Hex;
  /** ERC721/ERC1155 token id. */
  id?: bigint;
}

export class Templar {
  private constructor(
    public readonly provider: RpcProvider,
    public readonly network: NetworkConstants,
    public readonly pool: PoolConstants,
    private kv: KV,
  ) {}

  /** Loads the core and checks the RPC node and the chain against the pinned constants. */
  static async connect(opts: { provider: RpcProvider; network: NetworkConstants; kv: KV; wasm?: BufferSource | string }): Promise<Templar> {
    await loadCore(opts.wasm);
    await checkSpecVersion(opts.provider);
    const pool = activePool(opts.network);
    await verifyPins(opts.provider, opts.network, pool);
    return new Templar(opts.provider, opts.network, pool, opts.kv);
  }

  static generateSeed(): Uint8Array {
    return call(() => wasm.seed_generate());
  }
  static seedFromMnemonic(words: string): Uint8Array {
    return call(() => wasm.seed_from_mnemonic(words));
  }
  static mnemonic(seed: Uint8Array): string {
    return call(() => wasm.mnemonic_from_seed(seed));
  }

  async wallet(seed: Uint8Array): Promise<Wallet> {
    const store = new WalletStore(this.kv, seed, this.network.chainId, this.pool.pool);
    await store.open();
    const w = new Wallet(this, seed, store);
    await w.load();
    return w;
  }

  prover(opts: ProverOptions): ProverClient {
    return new ProverClient(opts, this.network, this.pool);
  }
}

export class Wallet {
  private state!: SyncState;
  private tree = new wasm.Tree();
  private chain: Hex;
  private pool: Hex;

  constructor(
    private t: Templar,
    private seed: Uint8Array,
    private store: WalletStore,
  ) {
    this.chain = t.network.chainId;
    this.pool = t.pool.pool;
  }

  // ------------------------------------------------------------------ state

  async load(): Promise<void> {
    this.state = (await this.store.get<SyncState>('state', 'sync')) ?? {
      block: -1,
      leaves: 0,
      checkpoints: [],
      nullifiers: [],
      notes: [],
      registry: [],
      settlements: [],
      deposited: [],
      created: 0,
      complete: false,
      problems: [],
    };
    this.tree = new wasm.Tree();
    for (let c = 0; c * CHUNK < this.state.leaves; c++) {
      const chunk = await this.chunk(c);
      call(() => this.tree.append(JSON.stringify(chunk.commitments)));
    }
  }

  private async chunk(c: number): Promise<LeafChunk> {
    return (await this.store.get<LeafChunk>('leaves', String(c))) ?? { commitments: [], digests: [], words: [], blocks: [] };
  }

  private async save(): Promise<void> {
    await this.store.put('state', 'sync', this.state);
  }

  private highestUsed(): number {
    return this.state.notes.filter((n) => this.state.block - n.block >= DEPTH).reduce((m, n) => Math.max(m, n.account), 0);
  }

  private scanned(): number[] {
    const top = Math.max(this.highestUsed(), this.state.created) + GAP;
    return Array.from({ length: top + 1 }, (_, i) => i);
  }

  // ------------------------------------------------------------------ addresses

  /** The receiving address of account `i` (refused past the gap limit). */
  async address(i = 0): Promise<AccountInfo> {
    const info = json<AccountInfo>(() => wasm.account(this.seed, this.chain, this.pool, i, Math.max(this.highestUsed(), this.state.created)));
    if (i > this.state.created) {
      this.state.created = i;
      await this.save();
    }
    return info;
  }

  exportViewingKey(i: number, full: boolean): string {
    return call(() => wasm.viewing_key_export(this.seed, this.chain, this.pool, i, full));
  }

  // ------------------------------------------------------------------ sync

  /** Syncs to the latest block (spec §6); holds the store lock throughout. */
  sync(): Promise<SyncResult> {
    return this.store.lock(() => this.syncLocked());
  }

  private async syncLocked(): Promise<SyncResult> {
    const provider = this.t.provider;
    const latest = await provider.getBlockLatestAccepted();
    const N = latest.block_number;
    // Roll back to the newest checkpoint whose block hash still matches (reorgs of any depth).
    let keep = -1;
    for (let i = this.state.checkpoints.length - 1; i >= 0; i--) {
      const cp = this.state.checkpoints[i]!;
      const b = await provider.getBlockWithTxHashes(cp.block);
      if ('block_hash' in b && b.block_hash && sameFelt(b.block_hash, cp.hash)) {
        keep = i;
        break;
      }
    }
    await this.rollback(keep);
    const from = keep >= 0 ? this.state.checkpoints[keep]!.block + 1 : this.t.pool.deploymentBlock;
    const problems: string[] = [];
    const { events, malformed } = from <= N ? await fetchPoolEvents(provider, this.pool, from, N) : { events: [], malformed: 0 };
    if (malformed) problems.push(`${malformed} malformed pool events`);

    const newNotes: Extract<PoolEvent, { kind: 'note' }>[] = [];
    let nextCp = (Math.floor(from / CHECKPOINT_EVERY) + 1) * CHECKPOINT_EVERY - 1;
    const cpBlocks: number[] = [];
    const addCheckpointsUpTo = async (block: number) => {
      while (nextCp < block && nextCp <= N) {
        cpBlocks.push(nextCp);
        this.state.checkpoints.push(await this.checkpointAt(nextCp));
        nextCp += CHECKPOINT_EVERY;
      }
    };
    for (const e of events) {
      await addCheckpointsUpTo(e.block);
      switch (e.kind) {
        case 'note': {
          if (e.index < this.state.leaves) {
            const c = await this.chunk(Math.floor(e.index / CHUNK));
            const at = e.index % CHUNK;
            const same = key(c.commitments[at]!) === key(e.commitment) && c.digests[at] === e.digest && JSON.stringify(c.words[at]) === JSON.stringify(e.words);
            if (!same) problems.push(`conflicting events for leaf ${e.index}`);
            break;
          }
          if (e.index > this.state.leaves) {
            problems.push(`missing leaves before ${e.index}`);
            break;
          }
          await this.appendLeaf(e);
          newNotes.push(e);
          break;
        }
        case 'nullifier':
          this.state.nullifiers.push(key(e.nullifier));
          break;
        case 'asset':
          this.state.registry.push({ asset: e.asset, standard: e.standard, contract: e.contract, idLow: e.idLow, idHigh: e.idHigh });
          break;
        case 'settled':
          this.state.settlements.push({ firstIndex: e.firstIndex, x: e.x });
          break;
        case 'deposited':
          if (!this.state.deposited.includes(e.asset)) this.state.deposited.push(e.asset);
          break;
      }
    }
    await addCheckpointsUpTo(N + 1);
    this.state.block = N;

    // Receive: scan the new leaves, then rescan everything for indexes the gap limit newly opens.
    let accounts = this.scanned();
    this.addOwned(await this.scan(accounts, newNotes, problems));
    for (;;) {
      const now = this.scanned();
      const added = now.filter((i) => !accounts.includes(i));
      if (!added.length) break;
      this.addOwned(await this.scan(added, await this.allLeaves(), problems));
      accounts = now;
    }

    // Completeness at N (spec §6).
    const chainState = await leafCountAndRoot(provider, this.pool, N);
    if (chainState.count !== this.state.leaves) problems.push(`leaf count ${this.state.leaves}, the pool has ${chainState.count}`);
    const root = json<Digest>(() => this.tree.root());
    if (key(root) !== key(chainState.root)) problems.push('the local root differs from the pool root');
    this.state.problems = problems;
    this.state.complete = problems.length === 0;
    await this.updateRecords();
    await this.save();
    return { complete: this.state.complete, block: N, problems, balances: this.balances() };
  }

  private async checkpointAt(block: number): Promise<Checkpoint> {
    const b = await this.t.provider.getBlockWithTxHashes(block);
    if (!('block_hash' in b) || !b.block_hash) fail('bad_rpc', `block ${block} has no hash`);
    const s = this.state;
    return {
      block,
      hash: canon(b.block_hash),
      leaves: s.leaves,
      nullifiers: s.nullifiers.length,
      registry: s.registry.length,
      settlements: s.settlements.length,
      deposited: s.deposited.length,
    };
  }

  /** Undoes everything after checkpoint `keep` (-1: everything). */
  private async rollback(keep: number): Promise<void> {
    const s = this.state;
    const cp = keep >= 0 ? s.checkpoints[keep]! : undefined;
    const leaves = cp?.leaves ?? 0;
    if (leaves < s.leaves) {
      for (let c = Math.floor(leaves / CHUNK); c * CHUNK < s.leaves; c++) {
        const chunk = await this.chunk(c);
        const n = Math.max(0, leaves - c * CHUNK);
        if (n === 0) await this.store.delete('leaves', String(c));
        else await this.store.put('leaves', String(c), { commitments: chunk.commitments.slice(0, n), digests: chunk.digests.slice(0, n), words: chunk.words.slice(0, n), blocks: chunk.blocks.slice(0, n) });
      }
      this.tree.truncate(BigInt(leaves));
      s.leaves = leaves;
    }
    s.nullifiers.length = cp?.nullifiers ?? 0;
    // Owned notes derive from leaves (found by the scan after the event loop), so they are cut by
    // leaf index, not by a count taken mid-batch.
    s.notes = s.notes.filter((n) => n.index < leaves);
    s.registry.length = cp?.registry ?? 0;
    s.settlements.length = cp?.settlements ?? 0;
    s.deposited.length = cp?.deposited ?? 0;
    s.checkpoints.length = keep + 1;
  }

  private async appendLeaf(e: Extract<PoolEvent, { kind: 'note' }>): Promise<void> {
    const c = Math.floor(e.index / CHUNK);
    const chunk = await this.chunk(c);
    chunk.commitments.push(e.commitment);
    chunk.digests.push(e.digest);
    chunk.words.push(e.words);
    chunk.blocks.push(e.block);
    await this.store.put('leaves', String(c), chunk);
    call(() => this.tree.append(JSON.stringify([e.commitment])));
    this.state.leaves += 1;
  }

  private async allLeaves(): Promise<Extract<PoolEvent, { kind: 'note' }>[]> {
    const out: Extract<PoolEvent, { kind: 'note' }>[] = [];
    for (let c = 0; c * CHUNK < this.state.leaves; c++) {
      const chunk = await this.chunk(c);
      chunk.commitments.forEach((cm, i) =>
        out.push({ kind: 'note', block: chunk.blocks[i]!, index: c * CHUNK + i, commitment: cm, digest: chunk.digests[i]!, words: chunk.words[i]! }),
      );
    }
    return out;
  }

  private async scan(accounts: number[], notes: Extract<PoolEvent, { kind: 'note' }>[], problems: string[]): Promise<StoredNote[]> {
    if (!notes.length) return [];
    const blocks = new Map(notes.map((n) => [n.index, n.block]));
    const request = {
      chain: this.chain,
      pool: this.pool,
      accounts,
      notes: notes.map((n) => ({ index: n.index, commitment: n.commitment, digest: n.digest, words: n.words })),
      registry: this.state.registry.map((r) => ({ asset: r.asset, standard: r.standard, contract: r.contract, id_low: r.idLow, id_high: r.idHigh })),
      registry_complete: true,
      settlements: this.state.settlements.map((s) => ({ first_index: s.firstIndex, x: s.x })),
    };
    const out = json<{ owned: OwnedNote[]; bad_digests: number[] }>(() => wasm.scan(this.seed, JSON.stringify(request)));
    if (out.bad_digests.length) problems.push(`delivery digest mismatch at ${out.bad_digests.join(',')}`);
    return out.owned.map((o) => ({ ...o, block: blocks.get(o.index) ?? -1 }));
  }

  private addOwned(found: StoredNote[]): void {
    for (const n of found) if (!this.state.notes.some((m) => m.index === n.index)) this.state.notes.push(n);
  }

  // ------------------------------------------------------------------ balances

  private spentSet(): Set<string> {
    return new Set(this.state.nullifiers);
  }

  private async liveInputs(): Promise<Set<number>> {
    const s = new Set<number>();
    // Only records whose statement left the wallet can settle, so only they lock notes.
    for (const r of await this.records()) if (r.left && r.stage !== 'settled' && r.stage !== 'dead') r.inputs.forEach((i) => s.add(i));
    return s;
  }

  balances(): Balance[] {
    const spent = this.spentSet();
    const by = new Map<string, Balance>();
    for (const n of this.state.notes) {
      if (n.nullifier && spent.has(key(n.nullifier))) continue;
      const b = by.get(n.asset) ?? { asset: n.asset, kind: n.kind, unspent: 0n, spendable: 0n, notes: 0, token: this.token(n.asset, n.kind) };
      b.unspent += BigInt(n.amount);
      b.notes += 1;
      if (this.state.complete && this.state.block - n.block >= DEPTH) b.spendable += BigInt(n.amount);
      by.set(n.asset, b);
    }
    return [...by.values()];
  }

  private token(asset: Hex, kind: AssetKind): { symbol: string; decimals: number } | undefined {
    if (kind !== 'Erc20') return undefined;
    const t = this.t.network.tokens.find((x) => sameFelt(x.address, asset));
    return t && { symbol: t.symbol, decimals: t.decimals };
  }

  /** Notes that can be selected now (spec §6 "Spendable"). */
  private async spendable(): Promise<NoteRef[]> {
    if (!this.state.complete) fail('incomplete_sync', `the last sync is incomplete: ${this.state.problems.join('; ')}`);
    const spent = this.spentSet();
    const live = await this.liveInputs();
    return this.state.notes
      .filter((n) => n.nullifier && !spent.has(key(n.nullifier)) && this.state.block - n.block >= DEPTH && !live.has(n.index))
      .map((n) => ({ index: n.index, account: n.account, asset: n.asset, amount: n.amount, rho: n.rho, commitment: n.commitment }));
  }

  // ------------------------------------------------------------------ deposits

  /**
   * Deposits into the pool as a note for `to` (a receiving address; default this wallet's
   * account 0). Public: depositor, asset and amount (spec §7.1).
   */
  async deposit(account: Account, spec: { asset: AssetSpec; amount: bigint; to?: string }): Promise<{ transactionHash: string; commitment: Digest }> {
    await checkVerifier(this.t.provider, this.t.pool);
    const to = spec.to ?? (await this.address(0)).address;
    const { standard, contract, id = 0n } = spec.asset;
    const low = (x: bigint) => (x & ((1n << 128n) - 1n)).toString();
    const high = (x: bigint) => (x >> 128n).toString();
    const asset = call(() => wasm.asset_id(standard, contract, low(id), high(id)));
    const amount = standard === 721 ? 1n : spec.amount;
    const note = json<{ inner: Digest; ciphertext: Hex[]; commitment: Digest }>(() => wasm.note_for(to, asset, amount.toString()));
    const data = [...note.inner.map(String), ...note.ciphertext];
    const calls: Call[] =
      standard === 20
        ? [
            { contractAddress: contract, entrypoint: 'approve', calldata: [this.pool, low(amount), high(amount)] },
            { contractAddress: this.pool, entrypoint: 'deposit', calldata: [contract, amount.toString(), '9', ...note.inner.map(String), '10', ...note.ciphertext] },
          ]
        : standard === 721
          ? [{ contractAddress: contract, entrypoint: 'safe_transfer_from', calldata: [account.address, this.pool, low(id), high(id), '19', ...data] }]
          : [{ contractAddress: contract, entrypoint: 'safe_transfer_from', calldata: [account.address, this.pool, low(id), high(id), low(amount), high(amount), '19', ...data] }];
    const r = await account.execute(calls, { tip: 0 });
    return { transactionHash: r.transaction_hash, commitment: note.commitment };
  }

  // ------------------------------------------------------------------ spends

  transfer(asset: Hex, amount: bigint, to: string): Promise<Spend> {
    return this.plan({ kind: 'transfer', asset: canon(asset), amount: amount.toString(), to });
  }

  async withdraw(asset: Hex, amount: bigint, recipient: Hex, opts: { kind?: AssetKind; force?: boolean } = {}): Promise<Spend> {
    await this.checkRecipient(asset, recipient, opts.kind, opts.force ?? false);
    return this.plan({ kind: 'withdraw', asset: canon(asset), amount: amount.toString(), recipient: canon(recipient) });
  }

  consolidate(asset: Hex): Promise<Spend> {
    return this.plan({ kind: 'consolidate', asset: canon(asset) });
  }

  /** ERC1155 recipients must accept the transfer; ERC721 ones should be accounts (HA-P7, SDK-P14). */
  private async checkRecipient(asset: Hex, recipient: Hex, kind: AssetKind | undefined, force: boolean): Promise<void> {
    const k = kind ?? this.state.notes.find((n) => sameFelt(n.asset, asset))?.kind;
    if (!k || k === 'Erc20' || k === 'Unknown') return;
    const supports = async (id: string) => {
      try {
        const [r] = await this.t.provider.callContract({ contractAddress: recipient, entrypoint: 'supports_interface', calldata: [id] });
        return r !== undefined && BigInt(r) === 1n;
      } catch {
        return false;
      }
    };
    if ('Erc1155' in k && !(await supports(IERC1155_RECEIVER_ID)) && !(await supports(ISRC6_ID))) {
      fail('recipient', 'the ERC1155 recipient accepts neither ERC1155 transfers nor is an account');
    }
    if ('Erc721' in k && !force && !(await supports(ISRC6_ID))) {
      fail('recipient_warning', 'the ERC721 recipient is not an account; pass force to withdraw anyway');
    }
  }

  private async plan(request: SpendRequest, replan?: SpendRecord): Promise<Spend> {
    // Records that never left the wallet cannot settle: a new plan supersedes them.
    for (const old of await this.records()) {
      if (!old.left && old.id !== replan?.id && old.stage !== 'settled' && old.stage !== 'dead') await this.putRecord({ ...old, stage: 'dead', closed: 'superseded' });
    }
    const r = await this.sync();
    if (!r.complete) fail('incomplete_sync', r.problems.join('; '));
    const notes = await this.spendable();
    const companions = (await this.store.get<[number, Companion][]>('companions', 'all')) ?? [];
    const pool = replan ? notes.concat(this.state.notes.filter((n) => replan.inputs.includes(n.index)).map((n) => ({ index: n.index, account: n.account, asset: n.asset, amount: n.amount, rho: n.rho, commitment: n.commitment }))) : notes;
    const req = { chain: this.chain, pool: this.pool, request, notes: pool, companions, required_inputs: replan ? replan.inputs : null };
    const plan = json<Plan>(() => wasm.plan_spend(this.seed, JSON.stringify(req), this.tree));
    // A reused companion's nullifier must be unspent (spec §3.3).
    if (plan.companion && !plan.companion_is_new) {
      const nf = json<Digest>(() => wasm.companion_nullifier(JSON.stringify(plan.companion), this.chain, this.pool, plan.asset));
      if (this.spentSet().has(key(nf))) fail('companion_spent', 'the companion dummy was already spent');
    }
    const record: SpendRecord = replan
      ? { ...replan, request, plan, stage: 'planned', proved: undefined, server: undefined, result: undefined, window: undefined, tx: undefined }
      : { id: randomId(), stage: 'planned', left: false, request, plan, inputs: plan.inputs.map((n) => n.index) };
    await this.putRecord(record);
    return new Spend(this, record);
  }

  /** Re-plans a live record with the same inputs (spec §9.1): any outputs, at most one settles. */
  async replan(id: string, request: SpendRequest): Promise<Spend> {
    const rec = await this.record(id);
    if (!rec || rec.stage === 'settled' || rec.stage === 'dead') fail('record', 'no live record');
    return this.plan(request, rec);
  }

  /** Abandons a record whose statement never left the wallet. */
  async cancel(id: string): Promise<void> {
    const rec = await this.record(id);
    if (!rec) return;
    if (rec.left) fail('record_left', 'its statement has left the wallet; it ends only when its root is evicted (spec §9.1)');
    await this.putRecord({ ...rec, stage: 'dead', closed: 'cancelled' });
  }

  // ------------------------------------------------------------------ records

  async records(): Promise<SpendRecord[]> {
    const ids = (await this.store.get<string[]>('records', 'index')) ?? [];
    const out: SpendRecord[] = [];
    for (const id of ids) {
      const r = await this.store.get<SpendRecord>('record', id);
      if (r) out.push(r);
    }
    return out;
  }

  async record(id: string): Promise<SpendRecord | undefined> {
    return this.store.get<SpendRecord>('record', id);
  }

  /** @internal */
  async putRecord(r: SpendRecord): Promise<void> {
    const ids = (await this.store.get<string[]>('records', 'index')) ?? [];
    if (!ids.includes(r.id)) await this.store.put('records', 'index', [...ids, r.id]);
    await this.store.put('record', r.id, r);
  }

  /** @internal The statement leaves the wallet: persist a new companion with its note first. */
  async leaving(r: SpendRecord): Promise<void> {
    if (r.plan.companion && r.plan.companion_is_new) {
      const all = (await this.store.get<[number, Companion][]>('companions', 'all')) ?? [];
      const note = r.plan.inputs[0]!.index;
      if (!all.some(([i]) => i === note)) await this.store.put('companions', 'all', [...all, [note, r.plan.companion]]);
    }
    r.left = true;
    await this.putRecord(r);
  }

  /** Settles records whose nullifiers are spent; ends those whose root is evicted (spec §9.1). */
  private async updateRecords(): Promise<void> {
    const spent = this.spentSet();
    for (const r of await this.records()) {
      if (r.stage === 'settled' || r.stage === 'dead') continue;
      const nfs = r.proved?.nullifiers ?? [];
      if (nfs.some((n) => spent.has(key(n)))) {
        await this.putRecord({ ...r, stage: 'settled', closed: 'nullifiers spent' });
        continue;
      }
      if (!r.left) continue;
      const evictAt = r.plan.leaf_count + EVICTION_LEAVES;
      if (this.state.leaves >= evictAt) {
        const c = await this.chunk(Math.floor((evictAt - 1) / CHUNK));
        const block = c.blocks[(evictAt - 1) % CHUNK];
        if (block !== undefined && this.state.block - block >= DEPTH) await this.putRecord({ ...r, stage: 'dead', closed: 'root evicted' });
      }
    }
  }

  /** @internal */
  get context() {
    return { t: this.t, seed: this.seed, chain: this.chain, pool: this.pool, latest: () => this.t.provider.getBlockLatestAccepted() };
  }
}

function randomId(): string {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/** A spend in flight: prove, wrap at a prover server, submit (spec §7.3, §8, §9). */
export class Spend {
  constructor(
    private w: Wallet,
    public record: SpendRecord,
  ) {}

  get plan(): Plan {
    return this.record.plan;
  }

  /** The client proof, in a worker. */
  async prove(opts: ProveOptions = {}): Promise<Proved> {
    const { seed } = this.w.context;
    const proved = await proveInWorker(seed, JSON.stringify(this.record.plan), opts);
    this.record = { ...this.record, stage: 'proved', proved };
    await this.w.putRecord(this.record);
    return proved;
  }

  /** Sends the statement and proof to a prover server and waits for the large proof. */
  async wrap(prover: ProverClient, opts: { url: string; onStatus?: (s: import('./prover.js').JobStatus) => void }): Promise<Window> {
    const proved = this.record.proved ?? fail('record', 'prove first');
    let server = this.record.server;
    if (!server?.jobId) {
      // The exact body is stored before the statement leaves the wallet (spec §9.1).
      const body = `{"relation":"r4","proof":${JSON.stringify(proved.proof)},"statement":${proved.statement_json}}`;
      server = { url: opts.url, body };
      this.record = { ...this.record, server, stage: 'sent_to_server' };
      await this.w.leaving(this.record);
      const jobId = await prover.submit(body);
      server = { ...server, jobId };
      this.record = { ...this.record, server };
      await this.w.putRecord(this.record);
    }
    const result = await prover.wait(server.jobId!, { onStatus: opts.onStatus });
    const { t } = this.w.context;
    const latest = (await this.w.context.latest()).block_number;
    const window = json<Window>(() => wasm.check_result(JSON.stringify(pinsOf(t.network, t.pool)), proved.binding, JSON.stringify(result), BigInt(latest)));
    this.record = { ...this.record, result, window, stage: 'wrapped' };
    await this.w.putRecord(this.record);
    return window;
  }

  /**
   * Estimates, signs, simulates and sends the exact transaction from `account` (spec §9.2).
   * `linkable` is always true in v1: the account is public and linked to the spend.
   */
  async submit(account: Account, opts: { confirmFee?: (maxFee: bigint, expected: bigint) => boolean | Promise<boolean> } = {}): Promise<{ transactionHash: string; linkable: true; prepared: Prepared }> {
    const { t } = this.w.context;
    const { result, window, proved } = this.record;
    if (!result || !window || !proved) fail('record', 'wrap first');
    const latest = (await this.w.context.latest()).block_number;
    if (latest < window.submit_after) fail('too_early', `wait until block ${window.submit_after}`);
    if (latest > window.valid_until - WINDOW_MARGIN) fail('window_passed', 're-prove this record');
    await checkVerifier(account.provider as RpcProvider, t.pool);
    const call: Call = { contractAddress: t.pool.pool, entrypoint: 'apply_spend', calldata: proved.calldata };
    const prepared = await prepare(account, call, result.proof, result.proof_facts);
    if (opts.confirmFee && !(await opts.confirmFee(prepared.maxFee, prepared.expectedFee))) fail('fee_declined', 'the fee was not confirmed');
    this.record = { ...this.record, stage: 'sent_to_chain', left: true, tx: { hash: '', nonce: prepared.nonce, maxFee: prepared.maxFee.toString(), expectedFee: prepared.expectedFee.toString() } };
    await this.w.putRecord(this.record);
    const transactionHash = await send(account, prepared);
    this.record = { ...this.record, tx: { ...this.record.tx!, hash: transactionHash } };
    await this.w.putRecord(this.record);
    return { transactionHash, linkable: true, prepared };
  }
}

export { SELECTORS, TemplarError };

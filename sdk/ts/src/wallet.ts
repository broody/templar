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
  /** `u` at the last complete sync. */
  usedAtComplete?: number;
  /** Incremented on every save. */
  rev?: number;
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

/** One attempt of a record: a plan, its proof, its server job and its transaction. */
export interface Attempt {
  plan: Plan;
  proved?: Proved;
  server?: { url: string; jobId?: string; body: string };
  result?: ServerResult;
  window?: Window;
  tx?: { hash?: string; nonce: string; maxFee: string; expectedFee: string; signed: unknown };
}

/** An in-flight spend (spec §9.1). */
export interface SpendRecord extends Attempt {
  id: string;
  /** Incremented on every write; a step refuses a record that changed under it (SDK-IP5). */
  version: number;
  stage: RecordStage;
  /** Whether its statement has ever left the wallet (then only root eviction ends it). */
  left: boolean;
  request: SpendRequest;
  inputs: number[];
  /** Every nullifier the record's attempts publish (inputs and companion), fixed at plan time. */
  nullifiers: Digest[];
  /** Earlier attempts (re-plans), for reconciliation and the sent history. */
  attempts: Attempt[];
  /** Why a record was closed. */
  closed?: string;
}

const LIVE = (r: SpendRecord) => r.stage !== 'settled' && r.stage !== 'dead';

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
  /** Notes to this wallet in `pre_confirmed` data, not yet in the tree (spec §6). */
  pending: { asset: Hex; amount: string; account: number }[];
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
    // Exactly `state.leaves` entries: a chunk may hold leaves written by a sync that never
    // committed its state (SDK-IP10).
    this.tree = new wasm.Tree();
    for (let c = 0; c * CHUNK < this.state.leaves; c++) {
      const chunk = await this.chunk(c);
      call(() => this.tree.append(JSON.stringify(chunk.commitments.slice(0, this.state.leaves - c * CHUNK))));
    }
    this.live = await this.liveInputs();
  }

  private async chunk(c: number): Promise<LeafChunk> {
    return (await this.store.get<LeafChunk>('leaves', String(c))) ?? { commitments: [], digests: [], words: [], blocks: [] };
  }

  private async save(): Promise<void> {
    this.state.rev = (this.state.rev ?? 0) + 1;
    await this.store.put('state', 'sync', this.state);
  }

  /** The highest account with a credited note at least `DEPTH` deep, in the current state. */
  private usedNow(): number {
    return this.state.notes.filter((n) => this.state.block - n.block >= DEPTH).reduce((m, n) => Math.max(m, n.account), 0);
  }

  /** `u` for issuing addresses: from complete syncs only (SDK-IP1). */
  private highestUsed(): number {
    return this.state.complete ? this.usedNow() : (this.state.usedAtComplete ?? 0);
  }

  /** Accounts to scan: the gap past what the current sync has found, and past what was issued. */
  private scanned(): number[] {
    const top = Math.max(this.usedNow(), this.state.created) + GAP;
    return Array.from({ length: top + 1 }, (_, i) => i);
  }

  // ------------------------------------------------------------------ addresses

  /** The receiving address of account `i` (refused past the gap limit). */
  async address(i = 0): Promise<AccountInfo> {
    // The gap limit counts from `u` only; `created` widens the scan, never the limit (SDK-IP1).
    const info = json<AccountInfo>(() => wasm.account(this.seed, this.chain, this.pool, i, this.highestUsed()));
    if (i > this.state.created) {
      // Under the lock, on the stored state (SDK-IP16).
      await this.store.lock(async () => {
        const stored = await this.store.get<SyncState>('state', 'sync');
        if (stored && (stored.rev ?? 0) !== (this.state.rev ?? 0)) await this.load();
        this.state.created = Math.max(this.state.created, i);
        await this.save();
      });
    }
    return info;
  }

  exportViewingKey(i: number, full: boolean): string {
    return call(() => wasm.viewing_key_export(this.seed, this.chain, this.pool, i, full));
  }

  // ------------------------------------------------------------------ sync

  /** Syncs to the latest block (spec §6); holds the store lock throughout. */
  sync(): Promise<SyncResult> {
    return this.store.lock(async () => {
      // Another instance (tab) may have saved since this one loaded (SDK-IP16, SDK-IP17).
      const stored = await this.store.get<SyncState>('state', 'sync');
      if ((stored?.rev ?? 0) !== (this.state.rev ?? 0)) await this.load();
      try {
        return await this.syncLocked();
      } catch (e) {
        // A sync that fails part-way leaves nothing unchecked behind: back to the saved state.
        await this.load();
        throw e;
      }
    });
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
    const kept = this.state.checkpoints.length;
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
    // The registry is complete through N only if every event was read (spec §6 rule 7).
    const registryComplete = problems.length === 0;
    let accounts = this.scanned();
    this.addOwned(await this.scan(accounts, newNotes, problems, registryComplete));
    for (;;) {
      const now = this.scanned();
      const added = now.filter((i) => !accounts.includes(i));
      if (!added.length) break;
      this.addOwned(await this.scan(added, await this.allLeaves(), problems, registryComplete));
      accounts = now;
    }

    // Completeness at N (spec §6).
    const chainState = await leafCountAndRoot(provider, this.pool, N);
    if (chainState.count !== this.state.leaves) problems.push(`leaf count ${this.state.leaves}, the pool has ${chainState.count}`);
    const root = json<Digest>(() => this.tree.root());
    if (key(root) !== key(chainState.root)) problems.push('the local root differs from the pool root');
    this.state.problems = problems;
    this.state.complete = problems.length === 0;
    if (this.state.complete) {
      this.state.usedAtComplete = this.highestUsed();
    } else {
      // Only a complete sync may leave checkpoints: the next sync re-reads this range, so a leaf the
      // provider dropped or a bad digest is not frozen behind a checkpoint (SDK-IP2).
      this.state.checkpoints.length = kept;
    }
    await this.updateRecords();
    await this.save();
    const pending = N >= 0 ? await this.pending(N, accounts) : [];
    return { complete: this.state.complete, block: N, problems, balances: this.balances(), pending };
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
    const at = e.index % CHUNK;
    // Overwrite anything past the committed count (left by a sync that did not finish).
    for (const a of [chunk.commitments, chunk.digests, chunk.words, chunk.blocks]) a.length = at;
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

  private async scan(accounts: number[], notes: Extract<PoolEvent, { kind: 'note' }>[], problems: string[], registryComplete = true): Promise<StoredNote[]> {
    if (!notes.length) return [];
    const blocks = new Map(notes.map((n) => [n.index, n.block]));
    const request = {
      chain: this.chain,
      pool: this.pool,
      accounts,
      notes: notes.map((n) => ({ index: n.index, commitment: n.commitment, digest: n.digest, words: n.words })),
      registry: this.state.registry.map((r) => ({ asset: r.asset, standard: r.standard, contract: r.contract, id_low: r.idLow, id_high: r.idHigh })),
      registry_complete: registryComplete,
      settlements: this.state.settlements.map((s) => ({ first_index: s.firstIndex, x: s.x })),
    };
    const out = json<{ owned: OwnedNote[]; bad_digests: number[] }>(() => wasm.scan(this.seed, JSON.stringify(request)));
    if (out.bad_digests.length) problems.push(`delivery digest mismatch at ${out.bad_digests.join(',')}`);
    return out.owned.map((o) => ({ ...o, block: blocks.get(o.index) ?? -1 }));
  }

  /** Notes in `pre_confirmed` data (scanned, never appended; spec §6). */
  private async pending(N: number, accounts: number[]): Promise<SyncResult['pending']> {
    try {
      const { events } = await fetchPoolEvents(this.t.provider, this.pool, N + 1, 'pre_confirmed');
      const notes = events.filter((e): e is Extract<PoolEvent, { kind: 'note' }> => e.kind === 'note');
      const found = await this.scan(accounts, notes, [], false);
      return found.map((n) => ({ asset: n.asset, amount: n.amount, account: n.account }));
    } catch {
      return [];
    }
  }

  private addOwned(found: StoredNote[]): void {
    for (const n of found) if (!this.state.notes.some((m) => m.index === n.index)) this.state.notes.push(n);
  }

  // ------------------------------------------------------------------ balances

  private spentSet(): Set<string> {
    return new Set(this.state.nullifiers);
  }

  private spentList(): Digest[] {
    return this.state.nullifiers.map((k) => k.split(',').map(Number));
  }

  /** Inputs of live records that left the wallet (only those can settle, so only they lock). */
  private live = new Set<number>();

  private async liveInputs(): Promise<Set<number>> {
    const s = new Set<number>();
    for (const r of await this.records()) if (r.left && LIVE(r)) r.inputs.forEach((i) => s.add(i));
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
      // Buried, from a complete sync, and not held by a live record (SDK-IP12).
      if (this.state.complete && this.state.block - n.block >= DEPTH && !this.live.has(n.index)) b.spendable += BigInt(n.amount);
      by.set(n.asset, b);
    }
    return [...by.values()];
  }

  private token(asset: Hex, kind: AssetKind): { symbol: string; decimals: number } | undefined {
    if (kind !== 'Erc20') return undefined;
    const t = this.t.network.tokens.find((x) => sameFelt(x.address, asset));
    return t && { symbol: t.symbol, decimals: t.decimals };
  }

  private toRef(n: StoredNote): NoteRef {
    return { index: n.index, account: n.account, asset: n.asset, amount: n.amount, rho: n.rho, commitment: n.commitment };
  }

  /** Notes that can be selected now (spec §6 "Spendable"). */
  private spendable(): NoteRef[] {
    if (!this.state.complete) fail('incomplete_sync', `the last sync is incomplete: ${this.state.problems.join('; ')}`);
    const spent = this.spentSet();
    return this.state.notes
      .filter((n) => n.nullifier && !spent.has(key(n.nullifier)) && this.state.block - n.block >= DEPTH && !this.live.has(n.index))
      .map((n) => this.toRef(n));
  }

  // ------------------------------------------------------------------ deposits

  /**
   * Deposits into the pool as a note for `to` (a receiving address of this pool; default this
   * wallet's account 0), waits for it, and confirms the pool published exactly that commitment
   * (spec §7.1). Public: depositor, asset and amount.
   */
  async deposit(account: Account, spec: { asset: AssetSpec; amount: bigint; to?: string }): Promise<{ transactionHash: string; commitment: Digest; confirmed: boolean }> {
    await checkVerifier(this.t.provider, this.t.pool);
    const to = spec.to ?? (await this.address(0)).address;
    const { standard, contract, id = 0n } = spec.asset;
    const low = (x: bigint) => (x & ((1n << 128n) - 1n)).toString();
    const high = (x: bigint) => (x >> 128n).toString();
    const asset = call(() => wasm.asset_id(standard, contract, low(id), high(id)));
    const amount = standard === 721 ? 1n : spec.amount;
    // `note_for` refuses an address of another chain or pool (SDK-IM2, SDK-IP4).
    const note = json<{ inner: Digest; ciphertext: Hex[]; commitment: Digest }>(() => wasm.note_for(to, asset, amount.toString(), this.chain, this.pool));
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
    await account.provider.waitForTransaction(r.transaction_hash);
    await this.sync();
    return { transactionHash: r.transaction_hash, commitment: note.commitment, confirmed: await this.hasLeaf(note.commitment) };
  }

  private async hasLeaf(cm: Digest): Promise<boolean> {
    for (let c = 0; c * CHUNK < this.state.leaves; c++) {
      if ((await this.chunk(c)).commitments.slice(0, this.state.leaves - c * CHUNK).some((x) => key(x) === key(cm))) return true;
    }
    return false;
  }

  // ------------------------------------------------------------------ spends

  transfer(asset: Hex, amount: bigint, to: string): Promise<Spend> {
    return this.plan({ kind: 'transfer', asset: canon(asset), amount: amount.toString(), to });
  }

  async withdraw(asset: Hex, amount: bigint, recipient: Hex, opts: { force?: boolean } = {}): Promise<Spend> {
    await this.checkRecipient(asset, recipient, opts.force ?? false);
    return this.plan({ kind: 'withdraw', asset: canon(asset), amount: amount.toString(), recipient: canon(recipient) });
  }

  consolidate(asset: Hex): Promise<Spend> {
    return this.plan({ kind: 'consolidate', asset: canon(asset) });
  }

  /** ERC1155 recipients must accept the transfer; ERC721 ones should be accounts (HA-P7, SDK-P14). */
  private async checkRecipient(asset: Hex, recipient: Hex, force: boolean): Promise<void> {
    const k = this.state.notes.find((n) => sameFelt(n.asset, asset))?.kind;
    if (!k || k === 'Unknown') fail('unknown_asset', 'the asset is not known from a complete sync; its standard cannot be checked');
    if (k === 'Erc20') return;
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

  /** A plan through the core, with every spent nullifier so it refuses spent inputs (SDK-IM4). */
  private planCore(request: SpendRequest, notes: NoteRef[], required: number[] | null): Plan {
    const companions = this.companions;
    const req = { chain: this.chain, pool: this.pool, request, notes, companions, required_inputs: required, spent: this.spentList() };
    return json<Plan>(() => wasm.plan_spend(this.seed, JSON.stringify(req), this.tree));
  }

  private companions: [number, Companion][] = [];

  private async nullifiersOf(plan: Plan): Promise<Digest[]> {
    const nfs = plan.inputs.map((i) => this.state.notes.find((n) => n.index === i.index)?.nullifier ?? fail('record', `note ${i.index} unknown`));
    if (plan.companion) nfs.push(json<Digest>(() => wasm.companion_nullifier(JSON.stringify(plan.companion), this.chain, this.pool, plan.asset)));
    return nfs;
  }

  private async plan(request: SpendRequest): Promise<Spend> {
    const r = await this.sync();
    if (!r.complete) fail('incomplete_sync', r.problems.join('; '));
    return this.store.lock(async () => {
      this.companions = (await this.store.get<[number, Companion][]>('companions', 'all')) ?? [];
      // Another tab's records count too (SDK-IP17).
      this.live = await this.liveInputs();
      // Records that never left the wallet cannot settle: a new plan supersedes them.
      for (const old of await this.records()) {
        if (!old.left && LIVE(old)) await this.writeRecord({ ...old, stage: 'dead', closed: 'superseded' });
      }
      const plan = this.planCore(request, this.spendable(), null);
      const record: SpendRecord = {
        id: randomId(),
        version: 0,
        stage: 'planned',
        left: false,
        request,
        plan,
        inputs: plan.inputs.map((n) => n.index),
        nullifiers: await this.nullifiersOf(plan),
        attempts: [],
      };
      await this.writeRecord(record);
      return new Spend(this, record.id);
    });
  }

  /**
   * Re-plans a live record with the same inputs and companion (spec §9.1): any outputs; at most
   * one attempt can settle. The current attempt joins the record's history.
   */
  async replan(id: string, request: SpendRequest): Promise<Spend> {
    const r = await this.sync();
    if (!r.complete) fail('incomplete_sync', r.problems.join('; '));
    return this.store.lock(async () => {
      // Re-read after the sync: it may have settled or ended the record (SDK-IP6).
      const rec = await this.record(id);
      if (!rec || !LIVE(rec)) fail('record_closed', 'no live record');
      this.companions = (await this.store.get<[number, Companion][]>('companions', 'all')) ?? [];
      const notes = rec.inputs.map((i) => this.state.notes.find((n) => n.index === i) ?? fail('record', `note ${i} unknown`)).map((n) => this.toRef(n));
      const plan = this.planCore(request, notes, rec.inputs);
      const { plan: p, proved, server, result, window, tx } = rec;
      const next: SpendRecord = {
        ...rec,
        request,
        plan,
        stage: 'planned',
        proved: undefined,
        server: undefined,
        result: undefined,
        window: undefined,
        tx: undefined,
        attempts: [...rec.attempts, { plan: p, proved, server, result, window, tx }],
      };
      await this.writeRecord(next);
      return new Spend(this, id);
    });
  }

  /** Abandons a record whose statement never left the wallet. */
  async cancel(id: string): Promise<void> {
    await this.store.lock(async () => {
      const rec = await this.record(id);
      if (!rec || !LIVE(rec)) return;
      if (rec.left) fail('record_left', 'its statement has left the wallet; it ends only when its root is evicted (spec §9.1)');
      await this.writeRecord({ ...rec, stage: 'dead', closed: 'cancelled' });
    });
  }

  /** A `Spend` for a stored record, to continue it after a restart. */
  async resume(id: string): Promise<Spend> {
    const rec = await this.record(id);
    if (!rec) fail('record', 'no such record');
    return new Spend(this, id);
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

  /** Writes a record (the caller holds the lock) and refreshes the live-input cache. */
  private async writeRecord(r: SpendRecord): Promise<SpendRecord> {
    const ids = (await this.store.get<string[]>('records', 'index')) ?? [];
    if (!ids.includes(r.id)) await this.store.put('records', 'index', [...ids, r.id]);
    const next = { ...r, version: r.version + 1 };
    await this.store.put('record', r.id, next);
    this.live = await this.liveInputs();
    return next;
  }

  /**
   * @internal One step on a record under the store lock: re-read it, refuse it if it is closed or
   * changed since `version`, apply `f` and write the result (SDK-IP5).
   */
  async step(id: string, version: number | undefined, f: (r: SpendRecord) => Promise<SpendRecord> | SpendRecord): Promise<SpendRecord> {
    return this.store.lock(async () => {
      const r = await this.record(id);
      if (!r || !LIVE(r)) fail('record_closed', `record ${id} is ${r?.stage ?? 'missing'}${r?.closed ? ` (${r.closed})` : ''}`);
      if (version !== undefined && r.version !== version) fail('record_changed', `record ${id} changed; resume it`);
      return this.writeRecord(await f(r));
    });
  }

  /**
   * @internal The statement leaves the wallet (the caller holds the record's step). A note's first
   * companion becomes sticky; a different one is refused (SDK-M17, SDK-IP5).
   */
  async leaving(r: SpendRecord): Promise<SpendRecord> {
    const all = (await this.store.get<[number, Companion][]>('companions', 'all')) ?? [];
    if (r.plan.companion) {
      const note = r.plan.inputs[0]!.index;
      const had = all.find(([i]) => i === note)?.[1];
      if (had && JSON.stringify(had) !== JSON.stringify(r.plan.companion)) fail('companion_mismatch', 'the note already has another companion; re-plan');
      if (!had) await this.store.put('companions', 'all', [...all, [note, r.plan.companion]]);
    }
    return { ...r, left: true };
  }

  /** Settles records whose nullifiers are spent; ends those whose root is evicted (spec §9.1). */
  private async updateRecords(): Promise<void> {
    const spent = this.spentSet();
    for (const r of await this.records()) {
      if (!LIVE(r)) continue;
      if (r.nullifiers.some((n) => spent.has(key(n)))) {
        await this.writeRecord({ ...r, stage: 'settled', closed: 'nullifiers spent' });
        continue;
      }
      // Eviction is decided only on a complete sync (SDK-IP6).
      if (!r.left || !this.state.complete) continue;
      const leafCount = Math.max(r.plan.leaf_count, ...r.attempts.map((a) => a.plan.leaf_count));
      const evictAt = leafCount + EVICTION_LEAVES;
      if (this.state.leaves >= evictAt) {
        const c = await this.chunk(Math.floor((evictAt - 1) / CHUNK));
        const block = c.blocks[(evictAt - 1) % CHUNK];
        if (block !== undefined && this.state.block - block >= DEPTH) await this.writeRecord({ ...r, stage: 'dead', closed: 'root evicted' });
      }
    }
  }

  /** @internal */
  get context() {
    return {
      t: this.t,
      seed: this.seed,
      chain: this.chain,
      pool: this.pool,
      latest: () => this.t.provider.getBlockLatestAccepted(),
      spent: () => this.spentSet(),
    };
  }
}

function randomId(): string {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

const STRK = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

/**
 * A spend in flight: prove, wrap at a prover server, submit (spec §7.3, §8, §9). Every step
 * re-reads its record under the store lock and refuses a closed or changed one.
 */
export class Spend {
  private version?: number;
  constructor(
    private w: Wallet,
    public readonly id: string,
  ) {}

  /** The record as stored. */
  async record(): Promise<SpendRecord> {
    const r = await this.w.record(this.id);
    if (!r) fail('record', 'no such record');
    return r;
  }

  async plan(): Promise<Plan> {
    return (await this.record()).plan;
  }

  private async step(f: (r: SpendRecord) => Promise<SpendRecord> | SpendRecord): Promise<SpendRecord> {
    const r = await this.w.step(this.id, this.version, f);
    this.version = r.version;
    return r;
  }

  /** The client proof, in a worker; checked against the pinned circuit before anything leaves. */
  async prove(opts: ProveOptions = {}): Promise<Proved> {
    const rec = await this.record();
    if (!LIVE(rec)) fail('record_closed', `record ${this.id} is ${rec.stage}${rec.closed ? ` (${rec.closed})` : ''}`);
    this.version ??= rec.version;
    if (rec.proved) return rec.proved;
    const { seed, t, chain, pool, spent } = this.w.context;
    // The companion must still be unspent (spec §3.3).
    if (rec.plan.companion) {
      const nf = json<Digest>(() => wasm.companion_nullifier(JSON.stringify(rec.plan.companion), chain, pool, rec.plan.asset));
      if (spent().has(key(nf))) fail('companion_spent', 'the companion dummy was already spent');
    }
    const proved = await proveInWorker(seed, JSON.stringify(rec.plan), opts);
    // The client circuit must be the one the deployed bridge pins (spec §8, SDK-IM5, SDK-IP8).
    if (JSON.stringify(proved.circuit_hash) !== JSON.stringify(t.pool.circuitHash)) fail('circuit_mismatch', 'the client circuit differs from the pinned one');
    await this.step((r) => ({ ...r, stage: 'proved', proved }));
    return proved;
  }

  /**
   * Sends the statement and proof to a prover server and waits for the large proof. The server is
   * checked first; a finished job past its window, a failed job or a dropped job is re-wrapped
   * with the identical body (spec §8, SDK-IP7).
   */
  async wrap(prover: ProverClient, opts: { url: string; onStatus?: (s: import('./prover.js').JobStatus) => void }): Promise<Window> {
    const { t } = this.w.context;
    const rec = await this.record();
    this.version ??= rec.version;
    const proved = rec.proved ?? fail('record', 'prove first');
    // The server must agree with the pins before the statement leaves (SDK-IP8).
    await prover.info();
    const latestBlock = async () => (await this.w.context.latest()).block_number;
    let current = rec;
    let jobId = current.server?.url === opts.url ? current.server.jobId : undefined;
    if (jobId && current.window && (await latestBlock()) > current.window.valid_until - WINDOW_MARGIN) jobId = undefined;
    for (let round = 0; ; round++) {
      if (!jobId) {
        const body = current.server?.body ?? `{"relation":"r4","proof":${JSON.stringify(proved.proof)},"statement":${proved.statement_json}}`;
        // The exact body is stored, and the record marked as left, before it is sent (spec §9.1).
        current = await this.step(async (r) => ({
          ...(await this.w.leaving(r)),
          // An earlier job (another server, or an expired one) joins the history.
          attempts: r.server?.jobId ? [...r.attempts, { plan: r.plan, server: r.server, result: r.result, window: r.window }] : r.attempts,
          server: { url: opts.url, body },
          result: undefined,
          window: undefined,
          stage: 'sent_to_server',
        }));
        jobId = await prover.submit(body);
        current = await this.step((r) => ({ ...r, server: { ...r.server!, jobId } }));
      }
      let result: ServerResult;
      try {
        result = await prover.wait(jobId, { onStatus: opts.onStatus });
      } catch (e) {
        const code = (e as TemplarError).code;
        if (round < 2 && (code === 'prover_failed' || code === 'prover_job')) {
          jobId = undefined; // failed or dropped at retention: resubmit the same body
          continue;
        }
        throw e;
      }
      const latest = await latestBlock();
      const window = json<Window>(() => wasm.check_result(JSON.stringify(pinsOf(t.network, t.pool)), proved.binding, JSON.stringify(result), BigInt(latest)));
      if (latest > window.valid_until - WINDOW_MARGIN) {
        if (round < 2) {
          jobId = undefined; // a stale result: re-wrap
          continue;
        }
        fail('window_passed', 'the server returned an expired result');
      }
      await this.step((r) => ({ ...r, result, window, stage: 'wrapped' }));
      return window;
    }
  }

  /**
   * Estimates, signs, simulates and sends the exact transaction from `account` (spec §9.2). The
   * maximum fee must be confirmed; `linkable` is always true in v1: the account is public.
   */
  async submit(
    account: Account,
    opts: { confirmFee: (maxFee: bigint, expected: bigint, warnings: string[]) => boolean | Promise<boolean> },
  ): Promise<{ transactionHash: string; linkable: true; prepared: Prepared; warnings: string[] }> {
    const { t } = this.w.context;
    const rec = await this.record();
    this.version ??= rec.version;
    const { result, window, proved } = rec;
    if (!result || !window || !proved) fail('record', 'wrap first');
    const provider = account.provider as RpcProvider;
    await checkSpecVersion(provider);
    const latest = (await provider.getBlockLatestAccepted()).block_number;
    if (latest < window.submit_after) fail('too_early', `wait until block ${window.submit_after}`);
    if (latest > window.valid_until - WINDOW_MARGIN) fail('window_passed', 'wrap again');
    await checkVerifier(provider, t.pool);
    const warnings = await accountWarnings(provider, account.address);
    const call: Call = { contractAddress: t.pool.pool, entrypoint: 'apply_spend', calldata: proved.calldata };
    const prepared = await prepare(account, call, result.proof, result.proof_facts);
    const [low, high] = await provider.callContract({ contractAddress: STRK, entrypoint: 'balance_of', calldata: [account.address] });
    if (BigInt(low ?? 0) + (BigInt(high ?? 0) << 128n) < prepared.maxFee) fail('insufficient_fee_balance', `the account holds less STRK than the maximum fee ${prepared.maxFee}`);
    if (!(await opts.confirmFee(prepared.maxFee, prepared.expectedFee, warnings))) fail('fee_declined', 'the fee was not confirmed');
    // The signed transaction, bounds and nonce are stored before sending (SDK-IP11).
    await this.step((r) => ({
      ...r,
      attempts: r.tx ? [...r.attempts, { plan: r.plan, server: r.server, result: r.result, window: r.window, tx: r.tx }] : r.attempts,
      left: true,
      stage: 'sent_to_chain',
      tx: { nonce: prepared.nonce, maxFee: prepared.maxFee.toString(), expectedFee: prepared.expectedFee.toString(), signed: JSON.parse(JSON.stringify(prepared.signed, (_, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v))) },
    }));
    const transactionHash = await send(account, prepared);
    await this.step((r) => ({ ...r, tx: { ...r.tx!, hash: transactionHash } }));
    return { transactionHash, linkable: true, prepared, warnings };
  }
}

/** Accounts compiled with Sierra older than 1.7 pay Cairo-steps fees, about 2.7× (spec §9.2). */
async function accountWarnings(provider: RpcProvider, address: string): Promise<string[]> {
  try {
    const cls = (await provider.getClassAt(address)) as { sierra_program?: string[] };
    const v = cls.sierra_program?.slice(0, 2).map((x) => Number(BigInt(x)));
    if (v && v.length === 2 && (v[0]! < 1 || (v[0] === 1 && v[1]! < 7))) return [`the submitting account's class uses Sierra ${v.join('.')}, billed in Cairo steps (about 2.7x the fee)`];
  } catch {
    /* no class information: no warning */
  }
  return [];
}

export { SELECTORS, TemplarError };

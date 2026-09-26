// A mock RPC node serving a pool V2 or V3 (spec §12.5, §12.6): blocks of pool events, the leaf
// count and root at any block (computed with the core's own tree), the adapter's pinned storage,
// pool V3's views (verifier by kind, proposals, parameters), reorgs, and a trace of every call the
// SDK makes.
import { RpcError, hash } from 'starknet';

import * as wasm from '../wasm/templar.js';
import { SEPOLIA, activePool, canon } from '../dist/index.js';

/** Sepolia with only pool V2 (R0 V4): the network the V4 wallet tests run against. */
export const SEPOLIA_V2 = { ...SEPOLIA, pools: [SEPOLIA.pools[0]!] };
import type { Plan, PoolConstants, Proved, Route } from '../dist/index.js';

/** A routing adapter on the mock chain (docs/pool-v3-spec.md §6): its class, pool, kind, routes and proposals. */
export interface MockAdapter {
  class: string;
  pool: string;
  kind: 'R0' | 'P1';
  routes: Route[];
  proposals: { statement: string; route: Route | null; eta: number }[];
}

const short = (x: string) => BigInt('0x' + Buffer.from(x).toString('hex'));
/** A route's eight felts in the adapter's Serde order. */
export const routeFelts = (r: Route): string[] =>
  [BigInt(r.statement), BigInt(r.statementClass), short(r.accountTag), BigInt(r.osProgram), short(r.proofVersion ?? 'PROOF2'),
   short(r.proofVariant ?? 'VIRTUAL_SNOS'), short(r.outputVersion ?? 'VIRTUAL_SNOS0'), BigInt(r.maxProofAge)].map((x) => '0x' + x.toString(16));

const SEL = {
  NotePublished: hash.getSelectorFromName('NotePublished'),
  NullifierSpent: hash.getSelectorFromName('NullifierSpent'),
  Deposited: hash.getSelectorFromName('Deposited'),
  AssetRegistered: hash.getSelectorFromName('AssetRegistered'),
  PolicySettled: hash.getSelectorFromName('PolicySettled'),
};

interface Ev {
  from_address: string;
  keys: string[];
  data: string[];
}

interface Block {
  hash: string;
  events: Ev[];
}

const hx = (x: number | bigint | string) => canon(x);

export class MockChain {
  readonly pool: PoolConstants;
  readonly base: number;
  /** Pool V3: `get_parameters` (E, Q, W, T) and pending proposals by key (value, eta). */
  parameters = ['0x5dc', '0x64', '0x1000', '0x15180'];
  proposals = new Map<string, [string, number]>();
  /** Pool V3: the verifier by kind (`R0`, `P1` as short strings); R0 defaults to the pinned adapter. */
  verifiers = new Map<string, string>();
  /** Routing adapters by address. */
  adapters = new Map<string, MockAdapter>();
  /** Class hashes of other deployed contracts (route statements, routing adapters). */
  classes = new Map<string, string>();
  /** Every block's timestamp (proposals lapse by it). */
  timestamp = 1_800_000_000;
  /** Overrides the timestamp blocks report (a lagging node). */
  blockTime?: number;
  /** `getTransactionStatus` answers by hash; an unknown hash is RPC error 29 ("not found"). */
  txStatus = new Map<string, { finality_status: string; execution_status?: string }>();
  /** `getTransactionReceipt`'s revert reason by hash (a reverted transaction's). */
  txRevert = new Map<string, string>();
  /** The next `getTransactionStatus` fails like a transport error. */
  statusFailNext = false;
  /** The chain's nonce for every account at `pre_confirmed`. */
  nonce = 7n;
  /** The next send throws after the transaction left (an ambiguous failure). */
  sendFailNext = false;
  /** Nonces of the transactions signed by the mock accounts, in order. */
  signedNonces: string[] = [];
  /** Pool V3: `get_root_superseded_at` by root (the digest's words joined), 0 when absent. */
  superseded = new Map<string, number>();
  blocks: Block[] = [];
  fork = 0;
  calls: { method: string; args: unknown[] }[] = [];
  /** Rewrites the next `getEvents` page once (drops or tampers events; SDK-IP2 tests). */
  onceEvents?: (events: (Ev & { block_number: number })[]) => (Ev & { block_number: number })[];
  /** `supports_interface` answers for recipients (withdrawal checks). */
  supports = new Map<string, boolean>();
  /** Sent transactions (mock account). */
  sent: { calls?: unknown; signed?: unknown }[] = [];
  registered = new Set<string>();
  /** The account's STRK balance for fee checks. */
  strk = 10n ** 20n;
  /** Leaves in order with the block they were published in. */
  constructor(pool: PoolConstants = activePool(SEPOLIA_V2)) {
    this.pool = pool;
    this.base = pool.deploymentBlock;
    this.mine(1);
  }

  get latest(): number {
    return this.base + this.blocks.length - 1;
  }

  private newBlock(events: Ev[] = []): number {
    const n = this.base + this.blocks.length;
    this.blocks.push({ hash: hx(BigInt(n) * 1_000_003n + BigInt(this.fork) * 7n + 1n), events });
    return n;
  }

  mine(k: number): void {
    for (let i = 0; i < k; i++) this.newBlock();
  }

  leafCount(upTo = this.latest): number {
    let n = 0;
    for (let b = 0; b <= upTo - this.base && b < this.blocks.length; b++) n += this.blocks[b]!.events.filter((e) => e.keys[0] === SEL.NotePublished && BigInt(e.from_address) === BigInt(this.pool.pool)).length;
    return n;
  }

  private noteEvent(index: number, commitment: number[], delivery: string, words: string[]): Ev {
    return { from_address: this.pool.pool, keys: [SEL.NotePublished], data: [hx(index), '0x9', ...commitment.map(hx), delivery, '0xa', ...words] };
  }

  deposit(note: { commitment: number[]; ciphertext: string[]; delivery: string }, asset: string, amount: bigint): number {
    const index = this.leafCount();
    return this.newBlock([
      { from_address: this.pool.pool, keys: [SEL.Deposited], data: [asset, hx(amount)] },
      this.noteEvent(index, note.commitment, note.delivery, note.ciphertext),
    ]);
  }

  applySpend(proved: Proved, plan: Plan): number {
    const index = this.leafCount();
    const events: Ev[] = proved.nullifiers.map((nf) => ({ from_address: this.pool.pool, keys: [SEL.NullifierSpent], data: ['0x9', ...nf.map(hx)] }));
    proved.statement.commitments.forEach((cm, j) => events.push(this.noteEvent(index + j, cm, plan.outputs[j]!.delivery, plan.outputs[j]!.ciphertext)));
    return this.newBlock(events);
  }

  /** `k` insertions of two leaves each (as spends append), one block each. */
  noise2(k: number): void {
    for (let i = 0; i < k; i++) {
      const evs: Ev[] = [];
      for (let j = 0; j < 2; j++) {
        const n = this.leafCount() + j;
        const words = Array.from({ length: 10 }, (_, w) => hx(BigInt(n * 16 + w + 1)));
        const cm = Array.from({ length: 9 }, (_, w) => (n * 9 + w + 7) % 2147483647);
        evs.push(this.noteEvent(n, cm, wasm.delivery_digest(JSON.stringify(words)), words));
      }
      this.newBlock(evs);
    }
  }

  registerAsset(asset: string, standard: number, contract: string, idLow: bigint): void {
    this.newBlock([{ from_address: this.pool.pool, keys: [SEL.AssetRegistered], data: [asset, hx(standard), contract, hx(idLow), '0x0'] }]);
  }

  /** A signer-backed account stub: deposits land on this chain; proof transactions are recorded. */
  account(address = '0xacc'): any {
    const provider = this.provider();
    return {
      address,
      provider,
      execute: async (calls: { contractAddress: string; entrypoint: string; calldata: string[] }[]) => {
        this.sent.push({ calls });
        const dep = calls.find((c) => c.entrypoint === 'deposit' || c.entrypoint === 'safe_transfer_from');
        if (dep) {
          const d = dep.calldata;
          const at = dep.entrypoint === 'deposit' ? 3 : d.length - 19;
          const inner = d.slice(at, at + 9).map((x) => Number(BigInt(x)));
          const words = d.slice(at + (dep.entrypoint === 'deposit' ? 10 : 9), at + (dep.entrypoint === 'deposit' ? 20 : 19)).map((x) => hx(x));
          const erc1155 = dep.entrypoint === 'safe_transfer_from' && d.length === 26;
          const asset =
            dep.entrypoint === 'deposit' ? hx(d[0]!) : wasm.asset_id(erc1155 ? 1155 : 721, dep.contractAddress, BigInt(d[2]!).toString(), BigInt(d[3]!).toString());
          const amount = dep.entrypoint === 'deposit' ? d[1]! : erc1155 ? BigInt(d[4]!).toString() : '1';
          if (dep.entrypoint !== 'deposit' && !this.registered.has(asset)) {
            this.registered.add(asset);
            this.registerAsset(asset, erc1155 ? 1155 : 721, dep.contractAddress, BigInt(d[2]!));
          }
          const cm = JSON.parse(wasm.pool_commitment(SEPOLIA.chainId, pool(this), asset, amount, JSON.stringify(inner)));
          this.deposit({ commitment: cm, ciphertext: words, delivery: wasm.delivery_digest(JSON.stringify(words)) }, asset, BigInt(amount));
        }
        return { transaction_hash: hx(this.sent.length) };
      },
      accountInvocationsFactory: async (inv: unknown, details: unknown) => (this.sent.push({ calls: { factory: details } }), [{ inv, details }]),
      getSignedTransaction: async (calls: unknown, details: { nonce?: bigint }) => {
        const nonce = details?.nonce !== undefined ? hx(details.nonce) : hx(this.nonce);
        this.signedNonces.push(nonce);
        return { type: 'INVOKE', version: '0x3', nonce, calls, details };
      },
    };
  }
  noise(k: number): void {
    for (let i = 0; i < k; i++) {
      const words = Array.from({ length: 10 }, (_, w) => hx(BigInt(this.leafCount() * 16 + w + 1)));
      const digest = wasm.delivery_digest(JSON.stringify(words));
      const cm = Array.from({ length: 9 }, (_, w) => (this.leafCount() * 9 + w + 1) % 2147483647);
      this.newBlock([this.noteEvent(this.leafCount(), cm, digest, words)]);
    }
  }

  /** Injects a raw event into a new block. */
  inject(ev: Ev): number {
    return this.newBlock([ev]);
  }

  /** Replaces the last `depth` blocks with `depth` empty ones on a new fork. */
  reorg(depth: number): void {
    this.blocks.length -= depth;
    this.fork += 1;
    this.mine(depth);
  }

  private root(upTo: number): string[] {
    const t = new wasm.Tree();
    for (let b = 0; b <= upTo - this.base; b++) {
      for (const e of this.blocks[b]!.events) if (e.keys[0] === SEL.NotePublished && BigInt(e.from_address) === BigInt(this.pool.pool)) t.append(JSON.stringify([e.data.slice(2, 11).map((x) => Number(BigInt(x)))]));
    }
    const r = JSON.parse(t.root()) as number[];
    t.free();
    return ['0x9', ...r.map(hx)];
  }

  provider(): any {
    const trace = (method: string, args: unknown[]) => this.calls.push({ method, args });
    const pool = this.pool;
    const storage = new Map<bigint, bigint>([
      [BigInt(hash.starknetKeccak('pool')), BigInt(pool.pool)],
      [BigInt(hash.starknetKeccak('statement')), BigInt(pool.statement)],
      [BigInt(hash.starknetKeccak('statement_class')), BigInt(pool.statementClass)],
      [BigInt(hash.starknetKeccak('os_program')), BigInt(pool.osProgram)],
      [BigInt(hash.starknetKeccak('max_proof_age')), BigInt(pool.maxProofAge)],
      [BigInt(hash.starknetKeccak('account_tag')), BigInt('0x' + Buffer.from(pool.accountTag).toString('hex'))],
    ]);
    const blockOf = (id: unknown): number => (typeof id === 'number' ? id : id === undefined || id === 'latest' ? this.latest : Number(id));
    return {
      channel: {
        getSpecVersion: async () => (trace('specVersion', []), '0.10.1'),
        getEstimateFee: async (inv: unknown, opts: unknown) => (
          trace('estimate', [inv, opts]),
          [{ l1_gas_consumed: '0x0', l1_gas_price: '0x10', l1_data_gas_consumed: '0x80', l1_data_gas_price: '0x3', l2_gas_consumed: '0x8000000', l2_gas_price: '0x2', overall_fee: '0x10000000' }]
        ),
        fetch: async (method: string, params: unknown) => (
          trace('fetch', [method, params]),
          { json: async () => ({ result: [{ transaction_trace: { execute_invocation: {} } }] }) }
        ),
      },
      getChainId: async () => (trace('getChainId', []), SEPOLIA.chainId),
      getClassHashAt: async (a: string, id?: unknown) => {
        trace('getClassHashAt', [a, id]);
        if (BigInt(a) === BigInt(pool.adapter)) return pool.adapterClass;
        if (BigInt(a) === BigInt(pool.statement)) return pool.statementClass;
        const ad = this.adapters.get(hx(a));
        if (ad) return ad.class;
        const cls = this.classes.get(hx(a));
        if (cls) return cls;
        if (pool.p1Adapter && BigInt(a) === BigInt(pool.p1Adapter.adapter)) return pool.p1Adapter.adapterClass;
        throw new Error('no contract');
      },
      getStorageAt: async (a: string, k: string) => {
        trace('getStorageAt', [a, k]);
        return BigInt(a) === BigInt(pool.adapter) ? hx(storage.get(BigInt(k)) ?? 0n) : '0x0';
      },
      callContract: async (c: { contractAddress: string; entrypoint: string; calldata: string[] }, id?: unknown) => {
        trace('callContract', [c.contractAddress, c.entrypoint, c.calldata, id]);
        if (c.entrypoint === 'balance_of') return [hx(this.strk & ((1n << 128n) - 1n)), hx(this.strk >> 128n)];
        if (c.entrypoint === 'supports_interface') return [this.supports.get(hx(c.contractAddress)) === false ? '0x0' : '0x1'];
        const ad = this.adapters.get(hx(c.contractAddress));
        if (ad) {
          switch (c.entrypoint) {
            case 'get_pool':
              return [ad.pool];
            case 'get_kind':
              return [hx(short(ad.kind))];
            case 'get_routes':
              return [hx(ad.routes.length), ...ad.routes.flatMap(routeFelts)];
            case 'get_route': {
              const r = ad.routes.find((x) => BigInt(x.statement) === BigInt(c.calldata[0]!));
              return r ? ['0x0', ...routeFelts(r)] : ['0x1'];
            }
            case 'get_route_proposals':
              return [hx(ad.proposals.length), ...ad.proposals.flatMap((x) => [hx(BigInt(x.statement)), ...(x.route ? ['0x0', ...routeFelts(x.route)] : ['0x1']), hx(x.eta)])];
          }
          throw new Error(`unexpected adapter entrypoint ${c.entrypoint}`);
        }
        if (BigInt(c.contractAddress) !== BigInt(pool.pool)) return ['0x1'];
        switch (c.entrypoint) {
          case 'get_verifier': {
            // Pool V3 takes the verifier kind; pool V2 takes nothing.
            if ((pool.version === 'v5') !== (c.calldata.length === 1)) throw new Error('get_verifier: wrong arguments for this pool');
            const kind = c.calldata[0] === undefined ? undefined : hx(c.calldata[0]);
            const set = kind === undefined ? undefined : this.verifiers.get(kind);
            if (set) return [set];
            if (kind !== undefined && kind === hx(short('P1'))) return [pool.p1Adapter?.adapter ?? '0x0'];
            return [pool.adapter];
          }
          case 'get_parameters':
            if (pool.version !== 'v5') throw new Error('no get_parameters on pool V2');
            return this.parameters;
          case 'get_proposal': {
            const p = this.proposals.get(hx(c.calldata[0]!));
            return p ? [p[0], hx(p[1])] : ['0x0', '0x0'];
          }
          case 'root_is_known':
            return ['0x1'];
          case 'get_root_superseded_at':
            return [hx(this.superseded.get(c.calldata.slice(1).map((x) => BigInt(x).toString()).join(',')) ?? 0)];
          case 'get_nullifier_spent': {
            const want = c.calldata.slice(1).map((x) => BigInt(x));
            const spent = this.blocks.some((b) => b.events.some((e) => e.keys[0] === SEL.NullifierSpent && e.data.slice(1).every((x, i) => BigInt(x) === want[i])));
            return [spent ? '0x1' : '0x0'];
          }
          case 'get_leaf_count':
            return [hx(this.leafCount(blockOf(id)))];
          case 'get_root':
            return this.root(blockOf(id));
        }
        throw new Error(`unexpected entrypoint ${c.entrypoint}`);
      },
      waitForTransaction: async () => ({ execution_status: 'SUCCEEDED' }),
      getTransactionStatus: async (h: string) => {
        trace('getTransactionStatus', [h]);
        if (this.statusFailNext) {
          this.statusFailNext = false;
          throw new Error('fetch failed');
        }
        const s = this.txStatus.get(hx(h));
        if (!s) throw new RpcError({ code: 29, message: 'Transaction hash not found' } as never, 'starknet_getTransactionStatus', {});
        return s;
      },
      getTransactionReceipt: async (h: string) => {
        trace('getTransactionReceipt', [h]);
        const s = this.txStatus.get(hx(h));
        if (!s) throw new RpcError({ code: 29, message: 'Transaction hash not found' } as never, 'starknet_getTransactionReceipt', {});
        return { ...s, revert_reason: this.txRevert.get(hx(h)) };
      },
      getNonceForAddress: async (a: string, id?: unknown) => (trace('getNonceForAddress', [a, id]), hx(this.nonce)),
      getClassAt: async () => ({ sierra_program: ['0x1', '0x7', '0x0'] }),
      invokeSignedTx: async (tx: unknown) => {
        trace('invokeSignedTx', [tx]);
        this.sent.push({ signed: tx });
        if (this.sendFailNext) {
          this.sendFailNext = false;
          throw new Error('socket hang up');
        }
        return { transaction_hash: '0xbeef' };
      },
      getBlockLatestAccepted: async () => (trace('getBlockLatestAccepted', []), { block_number: this.latest, block_hash: this.blocks[this.blocks.length - 1]!.hash }),
      getBlockWithTxHashes: async (id: number) => {
        trace('getBlockWithTxHashes', [id]);
        const b = this.blocks[id - this.base];
        if (!b) throw new Error('no block');
        return { block_hash: b.hash, block_number: id, timestamp: this.blockTime ?? this.timestamp, transactions: [] };
      },
      getEvents: async (f: { address: string; from_block: { block_number: number }; to_block: { block_number: number }; keys: string[][]; chunk_size: number; continuation_token?: string }) => {
        trace('getEvents', [f]);
        const all: (Ev & { block_number: number })[] = [];
        for (let n = f.from_block.block_number; n <= f.to_block.block_number; n++) {
          for (const e of this.blocks[n - this.base]?.events ?? []) {
            if (BigInt(e.from_address) === BigInt(f.address) && f.keys[0]!.some((k) => BigInt(k) === BigInt(e.keys[0]!))) all.push({ ...e, block_number: n });
          }
        }
        const start = Number(f.continuation_token ?? 0);
        let page = all.slice(start, start + f.chunk_size);
        if (this.onceEvents) {
          page = this.onceEvents(page);
          this.onceEvents = undefined;
        }
        return { events: page, ...(start + f.chunk_size < all.length ? { continuation_token: String(start + f.chunk_size) } : {}) };
      },
    };
  }
}

const pool = (c: MockChain) => (c as unknown as { pool: { pool: string } }).pool.pool;

/** A prover server stub over `fetch`: info from the pins, jobs that finish at once with honest facts. */
export class MockProver {
  bodies: string[] = [];
  jobs = new Map<string, { status: string; body: string; result?: unknown }>();
  /** What the next status call returns for a job (to simulate failures). */
  failNext = false;
  conflictNext = false;
  base = 0;
  binding = '';
  /** Rewrites the pool call the server returns (a lying server). */
  poolCall?: (c: unknown) => unknown;
  /** Whether this server relays (its info says so, and finished V5 jobs go to the handoff). */
  relayEnabled = false;
  /** The relayer's reports by job id, shown in each job's status. */
  relay = new Map<string, unknown>();
  claimed = new Set<string>();
  /** The next report answers 503 (it did not reach the server). */
  reportFailNext = false;
  /** Every claim answers 409 (someone else took it, or the server refused it for lateness). */
  refuseClaims = false;
  /** Overrides the pool parameters the server publishes (the pinned ones by default). */
  poolParameters?: Record<string, number>;
  /** Overrides the relations `/v1/info` lists (a dual-version server lists r5 and r6). */
  relations?: Record<string, unknown>[];
  /** Results name this route key and use its age (docs/pool-v3-spec.md §9.5); legacy results name none. */
  route?: { statement: string; maxProofAge: number };
  constructor(private chain: MockChain, private facts: (binding: string, base: number, hash: string) => string[]) {}

  fetch = async (url: string | URL, init?: { method?: string; body?: string }): Promise<Response> => {
    const u = new URL(String(url));
    const p = this.chain.pool;
    const reply = (status: number, v: unknown) => new Response(JSON.stringify(v), { status });
    if (u.pathname === '/v1/info') {
      return reply(200, {
        network: { chain_id: 'SN_SEPOLIA', pool: p.pool, os_program: p.osProgram, max_proof_age: p.maxProofAge },
        relations: this.relations ?? [{ name: p.version === 'v5' ? 'r5' : 'r4', statement_account: p.statement, statement_class: p.statementClass, account_tag: p.accountTag, adapter: p.adapter, circuit_hash_u32_le: p.circuitHash }],
        limits: { retention_secs: 3600 },
        relay: { enabled: this.relayEnabled },
        ...(p.version === 'v5'
          ? {
              r5: {
                pool_parameters: this.poolParameters ?? { expiry_window: p.parameters!.expiryWindow, quantum: p.parameters!.quantum, root_window: p.parameters!.rootWindow, timelock: p.parameters!.timelock },
              },
            }
          : {}),
      });
    }
    if (u.pathname === '/v1/jobs' && init?.method === 'POST') {
      this.bodies.push(init.body!);
      if (this.conflictNext) {
        this.conflictNext = false;
        return reply(409, { error: 'a job for this note is already queued, running or done' });
      }
      const id = String(this.jobs.size + 1).padStart(32, '0');
      this.jobs.set(id, { status: 'done', body: init.body! });
      return reply(202, { id, position: 0 });
    }
    const m = /^\/v1\/jobs\/(.+)$/.exec(u.pathname);
    if (m) {
      const j = this.jobs.get(m[1]!);
      if (!j) return reply(404, { error: 'no such job' });
      if (this.failNext) {
        this.failNext = false;
        return reply(200, { status: 'failed', stage: 'os', error: 'boom' });
      }
      const honest = this.resultOf(j);
      const result = this.poolCall && honest.pool_call ? { ...honest, pool_call: this.poolCall(honest.pool_call) } : honest;
      const relay = this.relay.get(m[1]!) ?? (this.relayEnabled && p.version === 'v5' ? { status: 'pending' } : null);
      return reply(200, { status: 'done', result, relay });
    }
    return reply(404, {});
  };

  /** A job's result, fixed at its first read (base block = the latest block then, minus one). */
  private resultOf(j: { body: string; result?: unknown }): Record<string, unknown> {
    if (j.result) return j.result as Record<string, unknown>;
    const p = this.chain.pool;
    const base = this.chain.latest - 1;
    const hash = this.chain.blocks[base - this.chain.base]!.hash;
    const result: Record<string, unknown> = { proof: 'AAAA', proof_facts: this.facts(this.binding, base, hash), base_block: base, binding: this.binding };
    if (p.version === 'v5') {
      // R0 V5: the deadline and the pool call the relayer settles, from the job's own body.
      const body = JSON.parse(j.body) as { statement: { valid_until: number }; pool_call: unknown };
      result.send_deadline = Math.min(body.statement.valid_until, base + (this.route?.maxProofAge ?? p.maxProofAge));
      result.pool_call = body.pool_call;
      result.relation = (JSON.parse(j.body) as { relation: string }).relation;
      if (this.route) result.statement = this.route.statement;
    }
    j.result = result;
    return result;
  }

  /** The relayer's handoff (`/relay/v1/jobs`): every finished V5 job not yet answered. */
  handoff = async (url: string | URL, init?: { method?: string; body?: string }): Promise<Response> => {
    const u = new URL(String(url));
    const reply = (status: number, v: unknown) => new Response(JSON.stringify(v), { status });
    if (u.pathname === '/relay/v1/jobs' && (init?.method ?? 'GET') === 'GET') {
      const jobs = [...this.jobs.entries()]
        .filter(([id]) => !this.relay.has(id))
        .map(([id, j]) => {
          const result = this.resultOf(j);
          const st = (JSON.parse(j.body) as { statement: { nullifiers: number[][]; root: number[] } }).statement;
          return { id, relation: result.relation, statement: result.statement, result, nullifiers: st.nullifiers.map((n) => n.map(hx)), root: st.root.map(hx), send_deadline: result.send_deadline };
        });
      return reply(200, { jobs, relay_margin_blocks: 60 });
    }
    const c = /^\/relay\/v1\/jobs\/(.+)\/claim$/.exec(u.pathname);
    if (c && init?.method === 'POST') {
      if (!this.jobs.has(c[1]!) || this.relay.has(c[1]!)) return reply(404, {});
      if (this.refuseClaims || this.claimed.has(c[1]!)) return reply(409, {});
      this.claimed.add(c[1]!);
      return reply(200, { id: c[1] });
    }
    const m = /^\/relay\/v1\/jobs\/(.+)$/.exec(u.pathname);
    if (m && init?.method === 'POST') {
      if (this.reportFailNext) {
        this.reportFailNext = false;
        return reply(503, {});
      }
      if (!this.jobs.has(m[1]!) || this.relay.has(m[1]!)) return reply(404, {});
      const r = JSON.parse(init.body!) as { transaction_hash?: string; refused?: string };
      this.relay.set(m[1]!, r.transaction_hash ? { status: 'submitted', transaction_hash: r.transaction_hash } : { status: 'refused', reason: r.refused });
      return reply(200, { id: m[1] });
    }
    return reply(404, {});
  };
}

export { SEL };

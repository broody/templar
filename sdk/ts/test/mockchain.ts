// A mock RPC node serving a pool V2 (spec §12.5, §12.6): blocks of pool events, the leaf count and
// root at any block (computed with the core's own tree), the adapter's pinned storage, reorgs, and
// a trace of every call the SDK makes.
import { hash } from 'starknet';

import * as wasm from '../wasm/templar.js';
import { SEPOLIA, activePool, canon } from '../dist/index.js';
import type { Plan, Proved } from '../dist/index.js';

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
  readonly pool = activePool(SEPOLIA);
  readonly base = this.pool.deploymentBlock;
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
  constructor() {
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
      getSignedTransaction: async (calls: unknown, details: unknown) => ({ type: 'INVOKE', version: '0x3', nonce: '0x7', calls, details }),
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
      getClassHashAt: async (a: string) => {
        trace('getClassHashAt', [a]);
        if (BigInt(a) === BigInt(pool.adapter)) return pool.adapterClass;
        if (BigInt(a) === BigInt(pool.statement)) return pool.statementClass;
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
        if (BigInt(c.contractAddress) !== BigInt(pool.pool)) return ['0x1'];
        switch (c.entrypoint) {
          case 'get_verifier':
            return [pool.adapter];
          case 'get_leaf_count':
            return [hx(this.leafCount(blockOf(id)))];
          case 'get_root':
            return this.root(blockOf(id));
        }
        throw new Error(`unexpected entrypoint ${c.entrypoint}`);
      },
      waitForTransaction: async () => ({ execution_status: 'SUCCEEDED' }),
      getClassAt: async () => ({ sierra_program: ['0x1', '0x7', '0x0'] }),
      invokeSignedTx: async (tx: unknown) => (trace('invokeSignedTx', [tx]), this.sent.push({ signed: tx }), { transaction_hash: '0xbeef' }),
      getBlockLatestAccepted: async () => (trace('getBlockLatestAccepted', []), { block_number: this.latest, block_hash: this.blocks[this.blocks.length - 1]!.hash }),
      getBlockWithTxHashes: async (id: number) => {
        trace('getBlockWithTxHashes', [id]);
        const b = this.blocks[id - this.base];
        if (!b) throw new Error('no block');
        return { block_hash: b.hash, block_number: id, transactions: [] };
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
  base = 0;
  binding = '';
  constructor(private chain: MockChain, private facts: (binding: string, base: number, hash: string) => string[]) {}

  fetch = async (url: string | URL, init?: { method?: string; body?: string }): Promise<Response> => {
    const u = new URL(String(url));
    const p = this.chain.pool;
    const reply = (status: number, v: unknown) => new Response(JSON.stringify(v), { status });
    if (u.pathname === '/v1/info') {
      return reply(200, {
        network: { chain_id: 'SN_SEPOLIA', pool: p.pool, os_program: p.osProgram, max_proof_age: p.maxProofAge },
        relations: [{ name: 'r4', statement_account: p.statement, statement_class: p.statementClass, account_tag: p.accountTag, adapter: p.adapter, circuit_hash_u32_le: p.circuitHash }],
        limits: { retention_secs: 3600 },
      });
    }
    if (u.pathname === '/v1/jobs' && init?.method === 'POST') {
      this.bodies.push(init.body!);
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
      const base = this.chain.latest - 1;
      const hash = this.chain.blocks[base - this.chain.base]!.hash;
      return reply(200, { status: 'done', result: { proof: 'AAAA', proof_facts: this.facts(this.binding, base, hash), base_block: base, binding: this.binding } });
    }
    return reply(404, {});
  };
}

export { SEL };

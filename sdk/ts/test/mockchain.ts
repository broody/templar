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

  /** `k` leaves nobody can open (well-formed words, correct digests). */
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
        const page = all.slice(start, start + f.chunk_size);
        return { events: page, ...(start + f.chunk_size < all.length ? { continuation_token: String(start + f.chunk_size) } : {}) };
      },
    };
  }
}

export { SEL };

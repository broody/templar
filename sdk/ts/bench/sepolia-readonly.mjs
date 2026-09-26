// Read-only check against Sepolia (no transactions): pins verified on chain, then a full sync of
// the active pool from its deployment block, complete only if the local root equals the pool's.
import { RpcProvider } from 'starknet';
import { MemoryKV, SEPOLIA, Templar } from '../dist/index.js';

const nodeUrl = process.env.STARKNET_RPC ?? 'http://127.0.0.1:9545/rpc/v0_10';
const provider = new RpcProvider({ nodeUrl });
const calls = [];
for (const m of ['getEvents', 'callContract', 'getStorageAt', 'getClassHashAt', 'getBlockWithTxHashes', 'getBlockLatestAccepted']) {
  const f = provider[m].bind(provider);
  provider[m] = (...a) => (calls.push(m), f(...a));
}
const t0 = Date.now();
const t = await Templar.connect({ provider, network: SEPOLIA, kv: new MemoryKV() });
const connectMs = Date.now() - t0;
const w = await t.wallet(Templar.generateSeed());
const t1 = Date.now();
const r = await w.sync();
const count = (m) => calls.filter((c) => c === m).length;
console.log(JSON.stringify({ connect_ms: connectMs, sync_ms: Date.now() - t1, complete: r.complete, problems: r.problems, block: r.block,
  balances: r.balances.length, calls: Object.fromEntries(['getEvents', 'callContract', 'getStorageAt', 'getClassHashAt', 'getBlockWithTxHashes', 'getBlockLatestAccepted'].map((m) => [m, count(m)])) }, null, 1));

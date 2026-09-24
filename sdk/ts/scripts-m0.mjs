// Milestone 0 (spec §7.3): the WASM core reproduces the native seeded plan and proof byte for byte.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import init, * as t from './wasm-test/templar_test.js';

const vec = JSON.parse(readFileSync(new URL('../vectors/determinism.json', import.meta.url)));
await init({ module_or_path: readFileSync(new URL('./wasm-test/templar_test_bg.wasm', import.meta.url)) });
const chain = '0x534e5f5345504f4c4941';
const pool = '0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9';
const alice = new Uint8Array(32).fill(0xa1);
const bob = JSON.parse(t.account(new Uint8Array(32).fill(0xb0), chain, pool, 0, 0));
const tree = new t.Tree();
tree.append(JSON.stringify([[1, 2, 3, 4, 5, 6, 7, 8, 9], vec.plan.inputs[0].commitment]));
const request = {
  chain, pool,
  request: { kind: 'transfer', asset: vec.plan.asset, amount: '600', to: bob.address },
  notes: [vec.plan.inputs[0]],
};
const sha = (s) => createHash('sha256').update(s).digest('hex');
const t0 = performance.now();
const plan = t.test_plan_spend_seeded(alice, JSON.stringify(request), tree, 7n);
const t1 = performance.now();
const proved = JSON.parse(t.test_prove_spend_seeded(alice, plan, 8n));
const t2 = performance.now();
const got = { plan_sha256: sha(plan), proof_sha256: sha(JSON.stringify(proved.proof)), proof_felts: proved.proof.length - 1,
  binding: proved.binding, circuit_hash_u32_le: proved.circuit_hash };
const canon = (o) => JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k]]));
const ok = canon(got) === canon(vec.expected);
const mem = process.memoryUsage();
console.log(JSON.stringify({ identical: ok, got, plan_ms: t1 - t0, prove_ms: t2 - t1, rss_mib: mem.rss / 2 ** 20 }, null, 1));
if (process.env.TEMPLAR_SDK_OUT) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync(`${process.env.TEMPLAR_SDK_OUT}/wasm-transfer.json`, JSON.stringify({ relation: 'r4', proof: proved.proof, statement: proved.statement }));
}
process.exit(ok ? 0 : 1);

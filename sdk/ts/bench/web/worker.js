// One seeded plan and proof in a fresh module worker (spec §7.3, §12.4).
import init, * as t from '/wasm-test/templar_test.js';

const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));

onmessage = async () => {
  try {
    const exports = await init({ module_or_path: '/wasm-test/templar_test_bg.wasm' });
    const vec = await (await fetch('/vectors/determinism.json')).json();
    const chain = '0x534e5f5345504f4c4941';
    const pool = '0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9';
    const alice = new Uint8Array(32).fill(0xa1);
    const bob = JSON.parse(t.account(new Uint8Array(32).fill(0xb0), chain, pool, 0, 0));
    const tree = new t.Tree();
    tree.append(JSON.stringify([[1, 2, 3, 4, 5, 6, 7, 8, 9], vec.plan.inputs[0].commitment]));
    const request = { chain, pool, request: { kind: 'transfer', asset: vec.plan.asset, amount: '600', to: bob.address }, notes: [vec.plan.inputs[0]] };
    const plan = t.test_plan_spend_seeded(alice, JSON.stringify(request), tree, 7n);
    const t0 = performance.now();
    const proved = JSON.parse(t.test_prove_spend_seeded(alice, plan, 8n));
    const ms = performance.now() - t0;
    postMessage({
      plan_sha256: await sha(plan),
      proof_sha256: await sha(JSON.stringify(proved.proof)),
      identical: (await sha(JSON.stringify(proved.proof))) === vec.expected.proof_sha256 && (await sha(plan)) === vec.expected.plan_sha256,
      prove_ms: ms,
      linear_memory_mib: exports.memory.buffer.byteLength / 2 ** 20,
    });
  } catch (e) {
    postMessage({ error: String(e) });
  }
};

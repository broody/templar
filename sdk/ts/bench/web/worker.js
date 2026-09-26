// One seeded plan and proof in a fresh module worker (spec §7.3, §12.4). Mode `v4`: the ordinary
// R0 V4 determinism vector. Mode `v5`: an ordinary R0 V5 withdrawal (docs/account-bound-note-spec.md
// §15 P5, "WASM proof time"), planned and proved here. P5 measured it with a bound note, which
// ADR-0027 removed; the relation and its cost are the same.
import init, * as t from '/wasm-test/templar_test.js';

const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
const chain = '0x534e5f5345504f4c4941';

async function v4() {
  const vec = await (await fetch('/vectors/determinism.json')).json();
  const pool = '0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9';
  const alice = new Uint8Array(32).fill(0xa1);
  const bob = JSON.parse(t.account(new Uint8Array(32).fill(0xb0), chain, pool, 'v4', 0, 0));
  const tree = new t.Tree();
  tree.append(JSON.stringify([[1, 2, 3, 4, 5, 6, 7, 8, 9], vec.plan.inputs[0].commitment]));
  const request = { chain, pool, request: { kind: 'transfer', asset: vec.plan.asset, amount: '600', to: bob.address }, notes: [vec.plan.inputs[0]] };
  const plan = t.test_plan_spend_seeded(alice, JSON.stringify(request), tree, 7n);
  const t0 = performance.now();
  const proved = JSON.parse(t.test_prove_spend_seeded(alice, plan, 'null', 8n));
  const ms = performance.now() - t0;
  return {
    plan_sha256: await sha(plan),
    proof_sha256: await sha(JSON.stringify(proved.proof)),
    identical: (await sha(JSON.stringify(proved.proof))) === vec.expected.proof_sha256 && (await sha(plan)) === vec.expected.plan_sha256,
    prove_ms: ms,
  };
}

async function v5() {
  const pool = '0x7e57b301';
  const token = '0x39f5916e2110601b44d7ed0f4c033dd684f99b945df2cce8356c73dc0c805b8';
  const keys = new Uint8Array(32).fill(0x5b);
  const address = JSON.parse(t.account(keys, chain, pool, 'v5', 0, 0)).address;
  const note = JSON.parse(t.note_for(address, token, '1000', chain, pool));
  const tree = new t.Tree();
  tree.append(JSON.stringify([note.commitment]));
  const scan = JSON.parse(t.scan(keys, JSON.stringify({
    chain, pool, accounts: [0], version: 'v5', registry: [], registry_complete: true, settlements: [],
    notes: [{ index: 0, commitment: note.commitment, digest: note.delivery, words: note.ciphertext }],
  })));
  const o = scan.owned[0];
  const expiry = { latest_block: 15650000, window: 1500, quantum: 100 };
  const request = {
    chain, pool, version: 'v5', expiry, companions: [], required_inputs: null, spent: [],
    request: { kind: 'withdraw', asset: token, amount: '1000', recipient: '0xb0b' },
    notes: [{ index: o.index, account: o.account, asset: o.asset, amount: o.amount, rho: o.rho, commitment: o.commitment }],
  };
  const plan = t.test_plan_spend_seeded(keys, JSON.stringify(request), tree, 7n);
  const t0 = performance.now();
  const proved = JSON.parse(t.test_prove_spend_seeded(keys, plan, JSON.stringify(expiry), 8n));
  const ms = performance.now() - t0;
  return { account: proved.statement.account, valid_until: JSON.parse(plan).valid_until, circuit_hash: proved.circuit_hash, proof_felts: proved.proof.length, prove_ms: ms };
}

onmessage = async (e) => {
  try {
    const exports = await init({ module_or_path: '/wasm-test/templar_test_bg.wasm' });
    const r = e.data?.mode === 'v5' ? await v5() : await v4();
    postMessage({ mode: e.data?.mode ?? 'v4', ...r, linear_memory_mib: exports.memory.buffer.byteLength / 2 ** 20 });
  } catch (err) {
    postMessage({ error: String(err) });
  }
};

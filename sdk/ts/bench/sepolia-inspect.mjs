// Reads a record of the e2e run, resends its stored signed transaction unchanged (it cannot pay
// twice: same nonce and nullifiers) to capture the gateway's full answer, and re-simulates it.
//   node bench/sepolia-inspect.mjs RUN_DIR
import { readFile, writeFile } from 'node:fs/promises';
import { RpcProvider } from 'starknet';
import { FileKV, SEPOLIA, Templar, loadCore } from '/home/broody/development/templar/sdk/ts/dist/index.js';
await loadCore();
const R = process.argv[2];
const seeds = JSON.parse(await readFile(`${R}/private-seeds.json`, 'utf8'));
const provider = new RpcProvider({ nodeUrl: 'http://127.0.0.1:9545/rpc/v0_10' });
const t = await Templar.connect({ provider, network: SEPOLIA, kv: new FileKV(`${R}/store`) });
const w = await t.wallet(Uint8Array.from(Buffer.from(seeds.alice, 'hex')));
const { id } = JSON.parse(await readFile(`${R}/record-id.json`, 'utf8'));
const rec = await w.record(id);
await writeFile(`${R}/signed-${process.argv[3] ?? "transfer"}.json`, JSON.stringify(rec.tx.signed), { mode: 0o600 });
const rpc = async (method, params) => (await fetch('http://127.0.0.1:9545/rpc/v0_10', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })).json();
const send = await rpc('starknet_addInvokeTransaction', { invoke_transaction: rec.tx.signed });
const sim = await rpc('starknet_simulateTransactions', { block_id: 'latest', transactions: [rec.tx.signed], simulation_flags: [] });
const tr = sim.result?.[0]?.transaction_trace;
const out = {
  gateway: send.error ?? send.result,
  simulation: sim.error ?? {
    reverted: tr.execute_invocation.revert_reason ?? null,
    total_l2_gas: tr.execution_resources.l2_gas, l1_data_gas: tr.execution_resources.l1_data_gas,
    pool_call_l2_gas: tr.execute_invocation.calls?.[0]?.execution_resources?.l2_gas,
    fee_STRK: Number(BigInt(sim.result[0].fee_estimation.overall_fee)) / 1e18,
  },
  proof_facts: rec.tx.signed.proof_facts, proof_bytes: Buffer.from(rec.tx.signed.proof ?? '', 'base64').length,
  window: rec.window, stage: rec.stage, nonce: rec.tx.nonce,
};
await writeFile(`${R}/${process.argv[3] ?? "transfer"}-outcome.json`, JSON.stringify(out, null, 1));
console.log(JSON.stringify(out, null, 1).slice(0, 2500));

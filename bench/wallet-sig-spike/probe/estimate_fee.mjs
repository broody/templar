// P0b spike: READ-ONLY fee estimate for declaring and deploying SigProbe from a given account.
//
// Nothing is signed: the transactions carry an empty signature and are estimated with
// SKIP_VALIDATE (the account's __validate__ is not run, so its validation cost is not included).
// Nothing is sent: only starknet_estimateFee, getNonce, getClass, getBlockWithTxHashes.
//
// 1. Tries the pair [DECLARE_V3 SigProbe, INVOKE_V3 UDC deploy] on the node, in one estimate.
// 2. If the node cannot estimate the declaration (the local node is known to fail on Sierra 1.8
//    classes, bench/m31-sepolia/README.md), falls back to: the declaration from the measured rule
//    (40,960 L2 gas per class felt, Sierra + CASM) at the block's L2 gas price, plus a node estimate
//    of a UDC deploy of an already-declared constructor-less stand-in class (the R4 statement
//    account class), which costs the same as deploying SigProbe (no constructor, same calldata).
//
// Usage: node estimate_fee.mjs --sender ACCOUNT_ADDRESS [--rpc URL] [--sierra F --casm F] [--out F]
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
const require = createRequire(import.meta.url);
const { hash } = require('/home/broody/development/templar/sdk/ts/node_modules/starknet');

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i < 0 ? d : args[i + 1]; };
const RPC = opt('--rpc', 'http://127.0.0.1:9545/rpc/v0_10');
const SENDER = opt('--sender', null);
const T = '/home/broody/development/templar/target/wallet-sig-spike/probe/scarb-target/release';
const SIERRA = opt('--sierra', `${T}/wallet_sig_probe_SigProbe.contract_class.json`);
const CASM = opt('--casm', `${T}/wallet_sig_probe_SigProbe.compiled_contract_class.json`);
const OUT = opt('--out', null);
if (!SENDER) { console.error('--sender ACCOUNT_ADDRESS is required'); process.exit(2); }

const UDC = '0x02ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125';
const STAND_IN_CLASS = '0x003e609d3c89f5c4254b53eab4b11d7543cd7d7e7da7f6027673b12769d61478'; // R4 statement account, no constructor
const SALT = '0x5349475f50524f42455f5350494b45'; // 'SIG_PROBE_SPIKE'

let id = 0;
async function rpc(method, params) {
  const r = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
  const v = await r.json();
  if (v.error) throw new Error(`${method}: ${JSON.stringify(v.error).slice(0, 1500)}`);
  return v.result;
}
const hx = (x) => '0x' + BigInt(x).toString(16);
const ZERO_BOUNDS = { l1_gas: { max_amount: '0x0', max_price_per_unit: '0x0' }, l2_gas: { max_amount: '0x0', max_price_per_unit: '0x0' },
  l1_data_gas: { max_amount: '0x0', max_price_per_unit: '0x0' } };
const common = (nonce) => ({ version: '0x3', sender_address: SENDER, signature: [], nonce: hx(nonce), resource_bounds: ZERO_BOUNDS,
  tip: '0x0', paymaster_data: [], account_deployment_data: [], nonce_data_availability_mode: 'L1', fee_data_availability_mode: 'L1' });

function deployInvoke(classHash, nonce) {
  // Cairo 1 account __execute__(calls: Array<Call>): [n, to, selector, len, calldata...]
  // UDC deploy_contract(class_hash, salt, not_from_zero: bool, calldata: Span<felt252>)
  const inner = [classHash, SALT, '0x1', '0x0'];
  return { type: 'INVOKE', ...common(nonce),
    calldata: ['0x1', UDC, hash.getSelectorFromName('deploy_contract'), hx(inner.length), ...inner] };
}

const sierra = JSON.parse(readFileSync(SIERRA, 'utf8'));
const casm = JSON.parse(readFileSync(CASM, 'utf8'));
const classHash = hash.computeSierraContractClassHash(sierra);
const v2 = hash.computeCompiledClassHashBlake(casm);
const felts = sierra.sierra_program.length + casm.bytecode.length;
const head = await rpc('starknet_getBlockWithTxHashes', ['latest']);
const l2Price = BigInt(head.l2_gas_price.price_in_fri);
const nonce = BigInt(await rpc('starknet_getNonce', ['latest', SENDER]));
const senderClass = await rpc('starknet_getClassHashAt', ['latest', SENDER]);
let declared = true;
try { await rpc('starknet_getClass', ['latest', classHash]); } catch { declared = false; }
const udcAbi = JSON.parse((await rpc('starknet_getClass', ['latest', await rpc('starknet_getClassHashAt', ['latest', UDC])])).abi);
const hasDeployContract = JSON.stringify(udcAbi).includes('"deploy_contract"');

const report = { rpc: RPC, block: head.block_number, starknet_version: head.starknet_version, sender: SENDER, sender_class: senderClass,
  sender_nonce: Number(nonce), class_hash: classHash, compiled_class_hash_v2_blake: v2, already_declared: declared,
  udc: UDC, udc_has_deploy_contract: hasDeployContract, salt: SALT,
  l2_gas_price_fri: l2Price.toString(), l1_gas_price_fri: BigInt(head.l1_gas_price.price_in_fri).toString(),
  l1_data_gas_price_fri: BigInt(head.l1_data_gas_price.price_in_fri).toString(),
  note: 'SKIP_VALIDATE, empty signature: the sender account validation (~0.3M L2 gas for Argent 0.5.0) is not included' };

const declareTx = { type: 'DECLARE', ...common(nonce), compiled_class_hash: v2,
  contract_class: { sierra_program: sierra.sierra_program, contract_class_version: sierra.contract_class_version,
    entry_points_by_type: sierra.entry_points_by_type, abi: JSON.stringify(sierra.abi) } };
try {
  const est = await rpc('starknet_estimateFee', [[declareTx, deployInvoke(classHash, nonce + 1n)], ['SKIP_VALIDATE'], 'latest']);
  report.method = 'node estimate of [declare, deploy]';
  report.declare = est[0];
  report.deploy = est[1];
  report.total_fri = (BigInt(est[0].overall_fee) + BigInt(est[1].overall_fee)).toString();
} catch (e) {
  report.node_declare_estimate_error = e.message.slice(0, 800);
  const declareGas = 40960n * BigInt(felts);
  report.method = 'declaration from the 40,960 L2 gas/felt rule; deploy from a node estimate with a stand-in class';
  report.declare = { l2_gas_rule: declareGas.toString(), class_felts: felts, overall_fee_fri_at_block_price: (declareGas * l2Price).toString() };
  const dep = await rpc('starknet_estimateFee', [[deployInvoke(STAND_IN_CLASS, nonce)], ['SKIP_VALIDATE'], 'latest']);
  report.deploy = { stand_in_class: STAND_IN_CLASS, ...dep[0] };
  report.total_fri = (declareGas * l2Price + BigInt(dep[0].overall_fee)).toString();
}
report.total_strk = Number(BigInt(report.total_fri)) / 1e18;
const text = JSON.stringify(report, null, 2);
if (OUT) writeFileSync(OUT, text + '\n');
console.log(text);

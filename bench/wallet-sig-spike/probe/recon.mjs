// P0b spike: READ-ONLY Sepolia reconnaissance of account classes for the SigProbe.
//
// For each address or class hash: the class hash, Sierra and compiler version, whether the class
// has an `is_valid_signature` (and `isValidSignature`) external entry point, the vendor strings in
// its ABI, and whether its compiled class hash in the classes trie is the Blake (v2) hash the
// virtual OS uses, or still the Poseidon (v1) hash (not migrated). The migration check walks the
// node's `starknet_getStorageProof` classes-trie path to the leaf and compares the leaf with
// Poseidon('CONTRACT_CLASS_LEAF_V0', h) for the v1 and v2 hashes computed from the node's CASM.
//
// Only JSON-RPC reads (getClass, getClassHashAt, getCompiledCasm, getStorageProof, call,
// getBlockWithTxs). Nothing is signed or sent.
//
// Usage: node recon.mjs [--rpc URL] [--scan-blocks N] [--out FILE] [ADDRESS_OR_CLASS ...]
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
const require = createRequire(import.meta.url);
const { hash, shortString } = require('/home/broody/development/templar/sdk/ts/node_modules/starknet');

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  if (i < 0) return dflt;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
};
const RPC = opt('--rpc', 'http://127.0.0.1:9545/rpc/v0_10');
const SCAN = Number(opt('--scan-blocks', '0'));
const OUT = opt('--out', null);

let rpcId = 0;
async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  const v = await res.json();
  if (v.error) throw new Error(`${method}: ${JSON.stringify(v.error)}`);
  return v.result;
}
const norm = (x) => '0x' + BigInt(x).toString(16).padStart(64, '0');

// Public knowledge (labelled as such in the report): class hashes of wallet account classes.
// Existence and vendor are confirmed on chain below; unknown hashes are reported as absent.
const KNOWN = {
  '0x073414441639dcd11d1846f287650a00c60c416b9d3ba45d31c651672125b2c2': 'Argent/Ready 0.5.0 (public knowledge)',
  '0x036078334509b514626504edc9fb252328d1a240e4e948bef8d0c08dff45927f': 'Argent 0.4.0 (public knowledge)',
  '0x029927c8af6bccf3f6fda035981e765a7bdbf18a2dc0d630494f8758aa908e2b': 'Argent 0.3.1 (public knowledge)',
  '0x01a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003': 'Argent 0.3.0 (public knowledge)',
  '0x00816dd0297efc55dc1e7559020a3a825e81ef734b558f03c83325d4da7e6253': 'Braavos 1.0.0 account (public knowledge)',
  '0x013bfe114fb1cf405bfc3a7f8dbe2d91db146c17521d40dcf57e16d6b59fa8e6': 'Braavos base account (public knowledge)',
  '0x03957f9f5a1cbfe918cedc2015c85200ca51a5f7506ecb6de98a5207b759bf8a': 'Braavos (sncast default, public knowledge)',
  '0x061dac032f228abef9c6626f995015233097ae253a7f72d68552db02f2971b8f': 'OpenZeppelin account 0.8.1 (public knowledge)',
  '0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564': 'OpenZeppelin account (sncast default, public knowledge)',
};

const SEL_IVS = hash.getSelectorFromName('is_valid_signature');
const SEL_IVS_CAMEL = hash.getSelectorFromName('isValidSignature');
const LEAF_TAG = BigInt(shortString.encodeShortString('CONTRACT_CLASS_LEAF_V0'));

function classLeaf(compiled) {
  return BigInt(hash.computePoseidonHash(LEAF_TAG, BigInt(compiled)));
}

// Walks the classes trie from the root along the class hash (251 bits, most significant first).
function walkTrie(nodes, root, key) {
  const byHash = new Map(nodes.map((n) => [BigInt(n.node_hash), n.node]));
  let cur = BigInt(root);
  let height = 251;
  const k = BigInt(key);
  while (height > 0) {
    const node = byHash.get(cur);
    if (!node) return { status: 'missing_node', at_height: height };
    // Every node on the path is checked against its hash (classes trie: Poseidon; an edge node
    // hashes to H(child, path) + length).
    const P = 2n ** 251n + 17n * 2n ** 192n + 1n;
    const h = 'left' in node
      ? BigInt(hash.computePoseidonHash(BigInt(node.left), BigInt(node.right)))
      : (BigInt(hash.computePoseidonHash(BigInt(node.child), BigInt(node.path))) + BigInt(node.length)) % P;
    if (h !== cur) return { status: 'bad_node_hash', at_height: height };
    if ('left' in node) {
      const bit = (k >> BigInt(height - 1)) & 1n;
      cur = BigInt(bit ? node.right : node.left);
      height -= 1;
    } else {
      const len = Number(node.length);
      const want = (k >> BigInt(height - len)) & ((1n << BigInt(len)) - 1n);
      if (want !== BigInt(node.path)) return { status: 'absent' };
      cur = BigInt(node.child);
      height -= len;
    }
  }
  return { status: 'leaf', leaf: cur };
}

async function migration(classHash, block) {
  let casm;
  try {
    casm = await rpc('starknet_getCompiledCasm', [classHash]);
  } catch (e) {
    return { error: 'getCompiledCasm: ' + e.message.slice(0, 200) };
  }
  const v1 = hash.computeCompiledClassHashPoseidon(casm);
  const v2 = hash.computeCompiledClassHashBlake(casm);
  const proof = await rpc('starknet_getStorageProof', [block, [classHash], [], []]);
  const w = walkTrie(proof.classes_proof, proof.global_roots.classes_tree_root, classHash);
  // The roots must commit to the block's state root: Poseidon('STARKNET_STATE_V0', contracts, classes).
  const header = await rpc('starknet_getBlockWithTxHashes', [block]);
  const stateRoot = hash.computePoseidonHashOnElements([BigInt(shortString.encodeShortString('STARKNET_STATE_V0')),
    BigInt(proof.global_roots.contracts_tree_root), BigInt(proof.global_roots.classes_tree_root)]);
  const r = { compiled_class_hash_v1_poseidon: v1, compiled_class_hash_v2_blake: v2, casm_bytecode_felts: casm.bytecode.length,
              trie: w.status, roots_match_block_state_root: BigInt(stateRoot) === BigInt(header.new_root)
                && BigInt(proof.global_roots.block_hash) === BigInt(header.block_hash) };
  if (w.status === 'leaf') {
    r.leaf = '0x' + w.leaf.toString(16);
    r.migrated_to_v2 = w.leaf === classLeaf(v2) ? true : w.leaf === classLeaf(v1) ? false : 'unknown (leaf matches neither)';
  }
  return r;
}

async function classInfo(classHash, block) {
  const c = await rpc('starknet_getClass', [block, classHash]);
  if (!c.sierra_program) {
    return { class_hash: norm(classHash), cairo: 0, note: 'Cairo 0 (deprecated) class: the virtual OS classes provider rejects it' };
  }
  const ver = (a) => a.map((x) => BigInt(x).toString()).join('.');
  const ext = c.entry_points_by_type.EXTERNAL.map((e) => BigInt(e.selector));
  const abi = typeof c.abi === 'string' ? c.abi : JSON.stringify(c.abi);
  const vendors = ['argent', 'braavos', 'openzeppelin', 'ready', 'cartridge', 'controller', 'webauthn', 'secp256r1', 'passkey', 'session']
    .filter((v) => abi.toLowerCase().includes(v));
  const out = {
    class_hash: norm(classHash),
    known_as: KNOWN[norm(classHash)] ?? null,
    sierra_version: ver(c.sierra_program.slice(0, 3)),
    compiler_version: ver(c.sierra_program.slice(3, 6)),
    sierra_gas_accounting: null,
    is_valid_signature: ext.includes(BigInt(SEL_IVS)),
    isValidSignature: ext.includes(BigInt(SEL_IVS_CAMEL)),
    abi_vendor_strings: vendors,
    sierra_program_felts: c.sierra_program.length,
  };
  const [maj, min] = c.sierra_program.slice(0, 2).map((x) => Number(BigInt(x)));
  out.sierra_gas_accounting = maj > 1 || (maj === 1 && min >= 7) ? 'sierra_gas (>= 1.7)' : 'cairo_steps on chain (< 1.7); the virtual OS forces sierra gas';
  const ivs = (typeof c.abi === 'string' ? JSON.parse(c.abi) : c.abi)
    .flatMap((it) => (it.type === 'interface' ? it.items : [it]))
    .filter((f) => f.type === 'function' && (f.name === 'is_valid_signature' || f.name === 'isValidSignature'))
    .map((f) => ({ name: f.name, inputs: f.inputs, outputs: f.outputs, state_mutability: f.state_mutability }));
  out.is_valid_signature_abi = ivs;
  out.migration = await migration(classHash, block);
  return out;
}

async function tryCall(address, name, block) {
  try {
    const r = await rpc('starknet_call', [{ contract_address: address, entry_point_selector: hash.getSelectorFromName(name), calldata: [] }, block]);
    return r.map((x) => {
      try { return shortString.decodeShortString(x) || x; } catch { return x; }
    });
  } catch {
    return null;
  }
}

async function main() {
  const head = await rpc('starknet_blockNumber', []);
  const block = { block_number: head };
  const report = { rpc: RPC, block: head, chain: shortString.decodeShortString(await rpc('starknet_chainId', [])), targets: [], known: [], scan: null };

  for (const a of args) {
    let classHash;
    let kind = 'address';
    try {
      classHash = await rpc('starknet_getClassHashAt', [block, a]);
    } catch {
      classHash = a;
      kind = 'class';
    }
    const r = { input: a, kind, ...(await classInfo(classHash, block)) };
    if (kind === 'address') {
      r.get_name = await tryCall(a, 'get_name', block);
      r.get_version = await tryCall(a, 'get_version', block);
    }
    report.targets.push(r);
  }

  for (const [h, label] of Object.entries(KNOWN)) {
    try {
      report.known.push({ label, ...(await classInfo(h, block)) });
    } catch (e) {
      report.known.push({ label, class_hash: h, declared_on_sepolia: false, error: e.message.slice(0, 160) });
    }
  }

  if (SCAN > 0) {
    // Class hashes of recent INVOKE senders (sampled), grouped, with vendor identification.
    const counts = new Map();
    const sample = new Map();
    for (let b = head - SCAN + 1; b <= head; b++) {
      const blk = await rpc('starknet_getBlockWithTxs', [{ block_number: b }]);
      for (const tx of blk.transactions) {
        if (tx.type !== 'INVOKE' || !tx.sender_address) continue;
        let ch;
        try { ch = norm(await rpc('starknet_getClassHashAt', [{ block_number: b }, tx.sender_address])); } catch { continue; }
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
        if (!sample.has(ch)) sample.set(ch, tx.sender_address);
      }
    }
    const rows = [];
    for (const [ch, n] of [...counts].sort((x, y) => y[1] - x[1])) {
      let info;
      try { info = await classInfo(ch, block); } catch (e) { info = { class_hash: ch, error: e.message.slice(0, 160) }; }
      rows.push({ invokes: n, sample_sender: sample.get(ch), sample_get_name: await tryCall(sample.get(ch), 'get_name', block),
                  sample_get_version: await tryCall(sample.get(ch), 'get_version', block), ...info });
    }
    report.scan = { blocks: [head - SCAN + 1, head], classes: rows };
  }

  const text = JSON.stringify(report, null, 2);
  if (OUT) writeFileSync(OUT, text + '\n');
  console.log(text);
}
main().catch((e) => { console.error(e); process.exit(1); });

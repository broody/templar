#!/usr/bin/env node
// Known-answer vectors for the R0 V6 binding (docs/pool-v3-spec.md §4.4, §5.2; re-check F3), with
// starknet.js as the reference (`poseidonHashMany`). The binding is `TMR0_BIND_V5`, unchanged
// from V5, so V5's four anchors (cairo-r5/kat) are reproduced from the same labels and must come
// out byte-identical. Added:
// - `valid_until_1`, the smallest expiry;
// - `ct_*`: statements whose delivery digests are computed from chosen ciphertexts, as pool V3's
//   `spend::delivery_digest` does, so `spend5::compute_binding` can be checked against the same
//   values (at valid_until 1 and 2^56 − 1, with a nonzero identity).
// Writes kat.json beside this script, the bridge's generated tests ../bridge/src/binding_kat.cairo,
// and pool V3's bench/m31-pool/cairo/src/tests/binding_v6_vectors.cairo.
//
// Usage: node cairo-r6/kat/gen_kat.cjs   (deterministic: values derive from sha256 of labels)
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const REPO = path.resolve(__dirname, "../../../../..");
const { ec, num, shortString } = require(path.join(REPO, "sdk/ts/node_modules/starknet"));
const hex = (x) => num.toHex(x);
const poseidon = (xs) => ec.starkCurve.poseidonHashMany(xs.map((x) => BigInt(x)));
const draw = (label, bits) => BigInt("0x" + crypto.createHash("sha256").update(label).digest("hex")) % (1n << BigInt(bits));
const P31 = (1n << 31n) - 1n;
const digest = (label) => Array.from({ length: 9 }, (_, k) => draw(`${label}/${k}`, 64) % P31);

// A synthetic statement: the fields the binding reads (spec §5.2). V5's generator, unchanged.
function statement(label, over = {}) {
  return {
    chain: shortString.encodeShortString("SN_SEPOLIA"),
    pool: draw(`${label}/pool`, 250),
    token_out: draw(`${label}/token`, 250),
    root: digest(`${label}/root`),
    nullifiers: [digest(`${label}/nf0`), digest(`${label}/nf1`)],
    commitments: [digest(`${label}/cm0`), digest(`${label}/cm1`)],
    deliveries: [draw(`${label}/d0`, 251), draw(`${label}/d1`, 251)],
    withdrawal_recipient: draw(`${label}/recipient`, 250),
    withdrawal_amount: draw(`${label}/amount`, 128),
    intent: draw(`${label}/intent`, 251),
    identity: digest(`${label}/identity`),
    valid_until: draw(`${label}/valid_until`, 56) | 1n,
    ...over,
  };
}

function binding(s) {
  const b = [BigInt(shortString.encodeShortString("TMR0_BIND_V5")), BigInt(s.chain), s.pool, s.token_out];
  b.push(...s.root, ...s.nullifiers[0], ...s.nullifiers[1]);
  b.push(...s.commitments[0], s.deliveries[0], ...s.commitments[1], s.deliveries[1]);
  b.push(s.withdrawal_recipient, s.withdrawal_amount, s.intent, ...s.identity, s.valid_until);
  return poseidon(b);
}

/// `spend::delivery_digest`: `Poseidon('CTRL_DELIVERY_V1', 304, words…)`, nine words below
/// 2^248 and the last below 2^200.
function delivery(ct) {
  if (ct.length !== 10 || ct.slice(0, 9).some((w) => w >= 1n << 248n) || ct[9] >= 1n << 200n) throw new Error("ciphertext");
  return poseidon([BigInt(shortString.encodeShortString("CTRL_DELIVERY_V1")), 304n, ...ct]);
}
const ciphertext = (label) => Array.from({ length: 10 }, (_, k) => draw(`${label}/ct${k}`, k === 9 ? 200 : 248));

const zero9 = Array(9).fill(0n);
const vectors = [
  { name: "transfer", s: statement("b-transfer", { token_out: 0n, withdrawal_recipient: 0n, withdrawal_amount: 0n, intent: 0n, identity: zero9 }) },
  { name: "withdrawal", s: statement("b-withdrawal", { intent: 0n, identity: zero9 }) },
  { name: "invoke_with_identity", s: statement("b-invoke") },
  { name: "extremes", s: statement("b-extremes", { withdrawal_amount: (1n << 128n) - 1n, valid_until: (1n << 56n) - 1n, pool: (1n << 251n) - 1n }) },
  { name: "valid_until_1", s: statement("b6-valid-until-1", { intent: 0n, identity: zero9, valid_until: 1n }) },
];
// Ciphertext-derived: the delivery digests are the pool's own, so the pool's binding can be fed the
// same spend.
const withCiphertexts = (name, label, over) => {
  const ct = [ciphertext(`${label}/o0`), ciphertext(`${label}/o1`)];
  return { name, ct, s: statement(label, { ...over, deliveries: [delivery(ct[0]), delivery(ct[1])] }) };
};
vectors.push(
  withCiphertexts("ct_valid_until_1", "b6-ct-1", { intent: 0n, identity: zero9, valid_until: 1n }),
  withCiphertexts("ct_valid_until_max_identity", "b6-ct-max", { valid_until: (1n << 56n) - 1n }),
  withCiphertexts("ct_transfer", "b6-ct-transfer", { token_out: 0n, withdrawal_recipient: 0n, withdrawal_amount: 0n, intent: 0n, identity: zero9 }),
);
for (const v of vectors) v.binding = binding(v.s);

// V5's anchors reproduce byte-identically (re-check F3).
const v5 = JSON.parse(fs.readFileSync(path.join(__dirname, "../../cairo-r5/kat/kat.json"), "utf8"));
for (const a of v5.bindings) {
  const v = vectors.find((x) => x.name === a.name);
  if (!v || hex(v.binding) !== a.binding) throw new Error(`V5 anchor ${a.name} not reproduced`);
}

const jsonValue = (x) => (Array.isArray(x) ? x.map(jsonValue) : typeof x === "bigint" && x < (1n << 31n) ? x.toString() : hex(x));
const out = {
  reference: "starknet.js " + require(path.join(REPO, "sdk/ts/node_modules/starknet/package.json")).version,
  binding_tag: "TMR0_BIND_V5",
  v5_anchors: v5.bindings.map((a) => a.name),
  bindings: vectors.map((v) => ({
    name: v.name,
    statement: Object.fromEntries(Object.entries(v.s).map(([k, x]) => [k, jsonValue(typeof x === "string" ? BigInt(x) : x)])),
    ...(v.ct ? { ciphertexts: v.ct.map((c) => c.map(hex)) } : {}),
    binding: hex(v.binding),
  })),
};
fs.writeFileSync(path.join(__dirname, "kat.json"), JSON.stringify(out, null, 1) + "\n");

// ---------------------------------------------------------------------------------------------
// The bridge's tests: the V6 bridge's `binding()` over each statement.
const span = (xs) => `array![${xs.map(String).join(", ")}].span()`;
let c = `// Generated by cairo-r6/kat/gen_kat.cjs from starknet.js; do not edit.
use super::{Statement, binding};
`;
for (const v of vectors) {
  const s = v.s;
  c += `
fn statement_${v.name}() -> Statement {
    Statement {
        chain: ${hex(BigInt(s.chain))},
        pool: ${hex(s.pool)},
        token_out: ${hex(s.token_out)},
        root: ${span(s.root)},
        nullifiers: [${span(s.nullifiers[0])}, ${span(s.nullifiers[1])}],
        commitments: [${span(s.commitments[0])}, ${span(s.commitments[1])}],
        deliveries: [${hex(s.deliveries[0])}, ${hex(s.deliveries[1])}],
        withdrawal_recipient: ${hex(s.withdrawal_recipient)},
        withdrawal_amount: ${s.withdrawal_amount},
        intent: ${hex(s.intent)},
        identity: ${span(s.identity)},
        valid_until: ${s.valid_until},
    }
}

#[test]
fn binding_${v.name}() {
    assert!(binding(@statement_${v.name}()) == ${hex(v.binding)});
}
`;
}
fs.writeFileSync(path.join(__dirname, "../bridge/src/binding_kat.cairo"), c);

// ---------------------------------------------------------------------------------------------
// Pool V3's `spend5::compute_binding` over the ciphertext-derived vectors.
const hspan = (xs) => `array![${xs.map(hex).join(", ")}].span()`;
let p = `// Generated by bench/m31-private-wrapper/client-port/cairo-r6/kat/gen_kat.cjs from starknet.js:
// R0 V6's binding anchors (\`TMR0_BIND_V5\`) as pool V3 spends, with each delivery digest computed
// from its ciphertext. Do not edit.
use m31_pool::spend::{Output, Withdrawal};
use m31_pool::spend5::Spend;

/// \`(name, spend with its expected binding)\`.
pub fn vectors() -> Array<(felt252, Spend)> {
    array![
`;
for (const v of vectors.filter((x) => x.ct)) {
  const s = v.s;
  const outputs = [0, 1].map((j) => `Output { commitment: ${hspan(s.commitments[j])}, ciphertext: ${hspan(v.ct[j])} }`).join(", ");
  p += `        ('${v.name}', Spend {
            chain: ${hex(BigInt(s.chain))}, pool: ${hex(s.pool)}.try_into().unwrap(), asset: ${hex(s.token_out)},
            root: ${hspan(s.root)},
            nullifiers: ${hspan([...s.nullifiers[0], ...s.nullifiers[1]])},
            outputs: array![${outputs}].span(),
            withdrawal: Withdrawal { recipient: ${hex(s.withdrawal_recipient)}.try_into().unwrap(), amount: ${hex(s.withdrawal_amount)} },
            intent: ${hex(s.intent)}, identity: ${hspan(s.identity)}, valid_until: ${hex(s.valid_until)},
            binding: ${hex(v.binding)},
        }),
`;
}
p += `    ]
}
`;
fs.writeFileSync(path.join(REPO, "bench/m31-pool/cairo/src/tests/binding_v6_vectors.cairo"), p);
console.log(JSON.stringify({ vectors: vectors.length, with_ciphertexts: vectors.filter((x) => x.ct).length, v5_anchors_reproduced: v5.bindings.length }));

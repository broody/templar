#!/usr/bin/env node
// Known-answer vectors for the R0 V5 bridge (docs/account-bound-note-spec.md §5.2, §5.3), with
// starknet.js as the reference: the SNIP-12 spend message (`typedData.getMessageHash`) and the
// binding `TMR0_BIND_V5` (`poseidonHashMany`). Writes `kat.json` beside this script and the
// generated Cairo tests `../bridge/src/snip12_kat.cairo`, which the bridge build runs.
//
// Usage: node cairo-r5/kat/gen_kat.cjs   (deterministic: values derive from sha256 of labels)
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const REPO = path.resolve(__dirname, "../../../../..");
const { typedData, ec, num, shortString } = require(path.join(REPO, "sdk/ts/node_modules/starknet"));
const REV = "1";
const hex = (x) => num.toHex(x);
const poseidon = (xs) => ec.starkCurve.poseidonHashMany(xs.map((x) => BigInt(x)));
const draw = (label, bits) => BigInt("0x" + crypto.createHash("sha256").update(label).digest("hex")) % (1n << BigInt(bits));
const P31 = (1n << 31n) - 1n;

const TYPES = {
  StarknetDomain: [
    { name: "name", type: "shortstring" },
    { name: "version", type: "shortstring" },
    { name: "chainId", type: "shortstring" },
    { name: "revision", type: "shortstring" },
  ],
  TemplarSpend: [
    { name: "pool", type: "ContractAddress" },
    { name: "binding_commitment", type: "felt" },
    { name: "token_out", type: "ContractAddress" },
    { name: "withdrawal_recipient", type: "ContractAddress" },
    { name: "withdrawal_amount", type: "u128" },
    { name: "intent", type: "felt" },
  ],
};

function typed(chain, m) {
  return {
    types: TYPES,
    primaryType: "TemplarSpend",
    domain: { name: "Templar", version: "V5", chainId: chain, revision: "1" },
    message: {
      pool: hex(m.pool),
      binding_commitment: hex(m.binding_commitment),
      token_out: hex(m.token_out),
      withdrawal_recipient: hex(m.withdrawal_recipient),
      withdrawal_amount: m.withdrawal_amount.toString(),
      intent: hex(m.intent),
    },
  };
}

const digest = (label) => Array.from({ length: 9 }, (_, k) => draw(`${label}/${k}`, 64) % P31);

// A synthetic V5 statement: the fields the binding reads (spec §5.2).
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

// ---------------------------------------------------------------------------------------------
// Vectors
const constants = {
  domain_type_hash: hex(typedData.getTypeHash(TYPES, "StarknetDomain", REV)),
  spend_type_hash: hex(typedData.getTypeHash(TYPES, "TemplarSpend", REV)),
  spend_encode_type: typedData.encodeType(TYPES, "TemplarSpend", REV),
};

const bindings = [
  { name: "transfer", s: statement("b-transfer", { token_out: 0n, withdrawal_recipient: 0n, withdrawal_amount: 0n, intent: 0n, identity: Array(9).fill(0n) }) },
  { name: "withdrawal", s: statement("b-withdrawal", { intent: 0n, identity: Array(9).fill(0n) }) },
  { name: "invoke_with_identity", s: statement("b-invoke") },
  { name: "extremes", s: statement("b-extremes", { withdrawal_amount: (1n << 128n) - 1n, valid_until: (1n << 56n) - 1n, pool: (1n << 251n) - 1n }) },
].map(({ name, s }) => ({ name, statement: s, binding: binding(s) }));

const MAX_U128 = (1n << 128n) - 1n;
const spends = [
  { name: "sepolia_transfer", chain: "SN_SEPOLIA", account: draw("s1/account", 250), m: { pool: draw("s1/pool", 250), binding: bindings[0].binding, salt: draw("s1/salt", 251) | 1n, token_out: 0n, withdrawal_recipient: 0n, withdrawal_amount: 0n, intent: 0n } },
  { name: "sepolia_withdrawal", chain: "SN_SEPOLIA", account: draw("s2/account", 250), m: { pool: draw("s2/pool", 250), binding: bindings[1].binding, salt: draw("s2/salt", 251) | 1n, token_out: draw("s2/token", 250), withdrawal_recipient: draw("s2/recipient", 250), withdrawal_amount: MAX_U128, intent: 0n } },
  { name: "mainnet_invoke", chain: "SN_MAIN", account: (1n << 251n) - 1n, m: { pool: draw("s3/pool", 250), binding: bindings[2].binding, salt: 1n, token_out: draw("s3/token", 250), withdrawal_recipient: 0n, withdrawal_amount: 0n, intent: draw("s3/intent", 251) } },
].map((v) => {
  const bc = poseidon([v.m.binding, v.m.salt]);
  const td = typed(v.chain, { ...v.m, binding_commitment: bc });
  return {
    name: v.name,
    chain: shortString.encodeShortString(v.chain),
    account: hex(v.account),
    ...Object.fromEntries(Object.entries(v.m).map(([k, x]) => [k, k === "withdrawal_amount" ? x.toString() : hex(x)])),
    binding_commitment: hex(bc),
    domain_hash: hex(typedData.getStructHash(TYPES, "StarknetDomain", td.domain, REV)),
    struct_hash: hex(typedData.getStructHash(TYPES, "TemplarSpend", td.message, REV)),
    message_hash: typedData.getMessageHash(td, hex(v.account)),
    typed_data: td,
  };
});

const jsonValue = (x) => (Array.isArray(x) ? x.map(jsonValue) : typeof x === "bigint" && x < (1n << 31n) ? x.toString() : hex(x));
const out = {
  reference: "starknet.js " + require(path.join(REPO, "sdk/ts/node_modules/starknet/package.json")).version,
  constants,
  bindings: bindings.map((b) => ({ name: b.name, statement: Object.fromEntries(Object.entries(b.statement).map(([k, x]) => [k, jsonValue(typeof x === "string" ? BigInt(x) : x)])), binding: hex(b.binding) })),
  spends,
};
fs.writeFileSync(path.join(__dirname, "kat.json"), JSON.stringify(out, null, 1) + "\n");

// ---------------------------------------------------------------------------------------------
// Cairo tests
const span = (xs) => `array![${xs.map(String).join(", ")}].span()`;
let c = `// Generated by cairo-r5/kat/gen_kat.cjs from starknet.js; do not edit.
use super::snip12::{
    STARKNET_DOMAIN_TYPE_HASH, TEMPLAR_SPEND_TYPE_HASH, binding_commitment, domain_hash, spend_message_hash,
    spend_struct_hash,
};
use super::{Statement, binding};

#[test]
fn type_hashes_match_starknet_js() {
    assert!(STARKNET_DOMAIN_TYPE_HASH == ${constants.domain_type_hash});
    assert!(TEMPLAR_SPEND_TYPE_HASH == ${constants.spend_type_hash});
}
`;
for (const v of spends) {
  c += `
#[test]
fn spend_${v.name}() {
    let bc = binding_commitment(${v.binding}, ${v.salt});
    assert!(bc == ${v.binding_commitment});
    assert!(domain_hash(${v.chain}) == ${v.domain_hash});
    assert!(spend_struct_hash(${v.pool}, bc, ${v.token_out}, ${v.withdrawal_recipient}, ${v.withdrawal_amount}, ${v.intent}) == ${v.struct_hash});
    let h = spend_message_hash(
        ${v.chain}, ${v.account}, ${v.pool}, ${v.binding}, ${v.salt}, ${v.token_out}, ${v.withdrawal_recipient}, ${v.withdrawal_amount}, ${v.intent},
    );
    assert!(h == ${v.message_hash});
}
`;
}
for (const b of bindings) {
  const s = b.statement;
  c += `
fn statement_${b.name}(account: felt252) -> Statement {
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
        account,
        valid_until: ${s.valid_until},
    }
}

#[test]
fn binding_${b.name}() {
    assert!(binding(@statement_${b.name}(0)) == ${hex(b.binding)});
    // The binding omits the account: a bound statement with the same fields binds identically.
    assert!(binding(@statement_${b.name}(0x1234567)) == ${hex(b.binding)});
}
`;
}
fs.writeFileSync(path.join(__dirname, "../bridge/src/snip12_kat.cairo"), c);
console.log(JSON.stringify({ constants, spends: spends.length, bindings: bindings.length }));

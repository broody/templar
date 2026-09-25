#!/usr/bin/env node
// P0b spike (throwaway): SNIP-12 revision-1 KAT vectors for the Templar spend and key-derivation
// messages, produced with starknet.js `typedData.getMessageHash(td, account)` as the reference.
//
// Writes (all next to this script):
//   kat.json               - inputs, type strings, type hashes, intermediate and final hashes
//   typed-data.json        - the exact typedData objects (fixed KAT) for the signing page
//   tests/test_kat.cairo   - generated snforge tests asserting Cairo == starknet.js
//
// Usage: node bench/wallet-sig-spike/snip12/gen_kat.cjs
// Deterministic: the "random" cases are drawn from sha256(SEED | case | field), so reruns are
// byte-identical.

"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const REPO = path.resolve(__dirname, "../../..");
const starknet = require(path.join(REPO, "sdk/ts/node_modules/starknet"));
const { typedData, ec, shortString, num } = starknet;
const REV = "1"; // TypedDataRevision.ACTIVE

const poseidon = (xs) => ec.starkCurve.poseidonHashMany(xs.map((x) => num.toBigInt(x)));
const hex = (x) => num.toHex(x);
const P = 2n ** 251n + 17n * 2n ** 192n + 1n;

// ---------------------------------------------------------------------------------------------
// Types (SNIP-12 revision 1). Member order is the encoding order.
// ---------------------------------------------------------------------------------------------
const STARKNET_DOMAIN = [
  { name: "name", type: "shortstring" },
  { name: "version", type: "shortstring" },
  { name: "chainId", type: "shortstring" },
  { name: "revision", type: "shortstring" },
];
const TEMPLAR_SPEND = [
  { name: "pool", type: "ContractAddress" },
  { name: "binding_commitment", type: "felt" },
  { name: "token_out", type: "ContractAddress" },
  { name: "withdrawal_recipient", type: "ContractAddress" },
  { name: "withdrawal_amount", type: "u128" },
  { name: "intent", type: "felt" },
  { name: "valid_until", type: "u128" },
];
const TEMPLAR_KEY_DERIVATION = [
  { name: "purpose", type: "shortstring" },
  { name: "chain", type: "shortstring" },
  { name: "account", type: "ContractAddress" },
];
const SPEND_TYPES = { StarknetDomain: STARKNET_DOMAIN, TemplarSpend: TEMPLAR_SPEND };
const DERIVATION_TYPES = { StarknetDomain: STARKNET_DOMAIN, TemplarKeyDerivation: TEMPLAR_KEY_DERIVATION };

const domain = (chainId) => ({ name: "Templar", version: "1", chainId, revision: "1" });

function spendTypedData(c) {
  return {
    types: SPEND_TYPES,
    primaryType: "TemplarSpend",
    domain: domain(c.chain_id),
    message: {
      pool: c.pool,
      binding_commitment: hex(poseidon([c.binding, c.salt])),
      token_out: c.token_out,
      withdrawal_recipient: c.withdrawal_recipient,
      withdrawal_amount: c.withdrawal_amount,
      intent: c.intent,
      valid_until: c.valid_until,
    },
  };
}

function derivationTypedData(c) {
  return {
    types: DERIVATION_TYPES,
    primaryType: "TemplarKeyDerivation",
    domain: domain(c.chain_id),
    message: { purpose: c.purpose, chain: c.chain, account: c.account },
  };
}

// ---------------------------------------------------------------------------------------------
// Deterministic pseudo-random inputs.
// ---------------------------------------------------------------------------------------------
const SEED = "templar/wallet-sig-spike/snip12/kat/v1";
const rnd = (label, bits) => {
  const h = BigInt("0x" + crypto.createHash("sha256").update(`${SEED}|${label}`).digest("hex"));
  return h % (2n ** BigInt(bits));
};
// ContractAddress must be < 2^251 - 256 for Cairo `TryInto<felt252, ContractAddress>`.
const rndAddr = (label) => hex(rnd(label, 256) % (2n ** 251n - 256n));
const rndFelt = (label) => hex(rnd(label, 256) % (2n ** 251n)); // < P
const rndU128 = (label) => rnd(label, 128).toString(10);

// ---------------------------------------------------------------------------------------------
// Cases.
// ---------------------------------------------------------------------------------------------
const ACCOUNT_FIXED = "0x0734b2c2";
const POOL_FIXED = "0x2da0011111111111111111111111111111111111111111111111111111137b9";

const spendCases = [
  {
    id: "fixed",
    chain_id: "SN_SEPOLIA",
    account: ACCOUNT_FIXED,
    pool: POOL_FIXED,
    binding: "0x1234",
    salt: "0x5678",
    token_out: "0x0",
    withdrawal_recipient: "0x0",
    withdrawal_amount: "0",
    intent: "0x0",
    valid_until: "16000000",
  },
  {
    id: "random1",
    chain_id: "SN_MAIN",
    account: rndAddr("spend/r1/account"),
    pool: rndAddr("spend/r1/pool"),
    binding: rndFelt("spend/r1/binding"),
    salt: rndFelt("spend/r1/salt"),
    token_out: rndAddr("spend/r1/token_out"),
    withdrawal_recipient: rndAddr("spend/r1/withdrawal_recipient"),
    withdrawal_amount: rndU128("spend/r1/withdrawal_amount"),
    intent: rndFelt("spend/r1/intent"),
    valid_until: rndU128("spend/r1/valid_until"),
  },
  {
    id: "random2",
    // Arbitrary felt chain id given as hex (exercises the numeric path of the shortstring encoder).
    chain_id: rndFelt("spend/r2/chain_id"),
    account: rndAddr("spend/r2/account"),
    pool: rndAddr("spend/r2/pool"),
    binding: rndFelt("spend/r2/binding"),
    salt: rndFelt("spend/r2/salt"),
    token_out: rndAddr("spend/r2/token_out"),
    withdrawal_recipient: rndAddr("spend/r2/withdrawal_recipient"),
    withdrawal_amount: (2n ** 128n - 1n).toString(10), // u128 max edge
    intent: rndFelt("spend/r2/intent"),
    valid_until: rndU128("spend/r2/valid_until"),
  },
];

const derivationCases = [
  {
    id: "fixed",
    chain_id: "SN_SEPOLIA",
    account: ACCOUNT_FIXED,
    purpose: "TEMPLAR_SECRET_V1",
    chain: "SN_SEPOLIA",
  },
  {
    id: "random1",
    chain_id: "SN_MAIN",
    account: rndAddr("derive/r1/account"),
    purpose: "TEMPLAR_SECRET_V1",
    chain: "SN_MAIN",
  },
  {
    id: "random2",
    chain_id: rndFelt("derive/r2/chain_id"),
    account: rndAddr("derive/r2/account"),
    purpose: rndFelt("derive/r2/purpose"),
    chain: rndFelt("derive/r2/chain"),
  },
];

// ---------------------------------------------------------------------------------------------
// Hashing (reference = starknet.js) + an independent hand-rolled recomputation as a sanity check.
// ---------------------------------------------------------------------------------------------
const feltOf = (v) => {
  // starknet.js getHex: numeric-looking strings (decimal or 0x) are numbers, else ASCII shortstring.
  try {
    return num.toBigInt(v);
  } catch (_) {
    return BigInt(shortString.encodeShortString(v));
  }
};

const typeInfo = {};
for (const [name, types] of [
  ["StarknetDomain", SPEND_TYPES],
  ["TemplarSpend", SPEND_TYPES],
  ["TemplarKeyDerivation", DERIVATION_TYPES],
]) {
  typeInfo[name] = {
    encode_type: typedData.encodeType(types, name, REV),
    type_hash: hex(typedData.getTypeHash(types, name, REV)),
  };
}

const STARKNET_MESSAGE = BigInt(shortString.encodeShortString("StarkNet Message"));
const manualDomain = (chainId) =>
  poseidon([typeInfo.StarknetDomain.type_hash, feltOf("Templar"), feltOf("1"), feltOf(chainId), feltOf("1")]);

function assertEq(a, b, what) {
  if (num.toBigInt(a) !== num.toBigInt(b)) throw new Error(`mismatch ${what}: ${hex(a)} != ${hex(b)}`);
}

const spendOut = spendCases.map((c) => {
  const td = spendTypedData(c);
  const message_hash = hex(typedData.getMessageHash(td, c.account));
  const domain_hash = hex(typedData.getStructHash(td.types, "StarknetDomain", td.domain, REV));
  const struct_hash = hex(typedData.getStructHash(td.types, "TemplarSpend", td.message, REV));
  const binding_commitment = td.message.binding_commitment;
  // Independent recomputation.
  const d = manualDomain(c.chain_id);
  const s = poseidon([
    typeInfo.TemplarSpend.type_hash,
    c.pool,
    poseidon([c.binding, c.salt]),
    c.token_out,
    c.withdrawal_recipient,
    BigInt(c.withdrawal_amount),
    c.intent,
    BigInt(c.valid_until),
  ]);
  const m = poseidon([STARKNET_MESSAGE, d, c.account, s]);
  assertEq(d, domain_hash, `spend ${c.id} domain`);
  assertEq(s, struct_hash, `spend ${c.id} struct`);
  assertEq(m, message_hash, `spend ${c.id} message`);
  return {
    id: c.id,
    inputs: { ...c, chain_id_felt: hex(feltOf(c.chain_id)) },
    binding_commitment,
    domain_hash,
    struct_hash,
    message_hash,
  };
});

const derivationOut = derivationCases.map((c) => {
  const td = derivationTypedData(c);
  const message_hash = hex(typedData.getMessageHash(td, c.account));
  const domain_hash = hex(typedData.getStructHash(td.types, "StarknetDomain", td.domain, REV));
  const struct_hash = hex(typedData.getStructHash(td.types, "TemplarKeyDerivation", td.message, REV));
  const d = manualDomain(c.chain_id);
  const s = poseidon([typeInfo.TemplarKeyDerivation.type_hash, feltOf(c.purpose), feltOf(c.chain), c.account]);
  const m = poseidon([STARKNET_MESSAGE, d, c.account, s]);
  assertEq(d, domain_hash, `derive ${c.id} domain`);
  assertEq(s, struct_hash, `derive ${c.id} struct`);
  assertEq(m, message_hash, `derive ${c.id} message`);
  return {
    id: c.id,
    inputs: {
      ...c,
      chain_id_felt: hex(feltOf(c.chain_id)),
      purpose_felt: hex(feltOf(c.purpose)),
      chain_felt: hex(feltOf(c.chain)),
    },
    domain_hash,
    struct_hash,
    message_hash,
  };
});

// Pitfall record: what the domain would hash to if `version`/`revision` were ASCII '1' (0x31).
const asciiVersionDomainSepolia = hex(
  poseidon([typeInfo.StarknetDomain.type_hash, feltOf("Templar"), 0x31n, feltOf("SN_SEPOLIA"), 1n])
);

const kat = {
  note:
    "P0b spike KAT. Reference: starknet.js " +
    require(path.join(REPO, "sdk/ts/node_modules/starknet/package.json")).version +
    " typedData.getMessageHash(td, account), SNIP-12 revision 1. Random cases are sha256-seeded (deterministic).",
  seed: SEED,
  starknet_message: hex(STARKNET_MESSAGE),
  domain: { name: "Templar", version: "1", revision: "1", name_felt: hex(feltOf("Templar")), version_felt: hex(feltOf("1")), revision_felt: hex(feltOf("1")) },
  types: typeInfo,
  pitfall_ascii_version_domain_hash_sn_sepolia: asciiVersionDomainSepolia,
  spend: spendOut,
  derivation: derivationOut,
};

const typedDataOut = {
  note:
    "Exact SNIP-12 rev-1 typedData objects for the fixed KAT (signing page). messageHash = " +
    "starknet.js typedData.getMessageHash(typedData, account). binding_commitment = poseidon_hash_many([binding, salt]).",
  spend: {
    account: spendCases[0].account,
    binding: spendCases[0].binding,
    salt: spendCases[0].salt,
    typedData: spendTypedData(spendCases[0]),
    messageHash: spendOut[0].message_hash,
  },
  derivation: {
    account: derivationCases[0].account,
    typedData: derivationTypedData(derivationCases[0]),
    messageHash: derivationOut[0].message_hash,
  },
};

// ---------------------------------------------------------------------------------------------
// Generated Cairo tests.
// ---------------------------------------------------------------------------------------------
const addr = (v) => `${hex(feltOf(v))}.try_into().unwrap()`;
const u128 = (v) => `${BigInt(v).toString(10)}_u128`;
let cairo = `// GENERATED by gen_kat.cjs from starknet.js ${require(path.join(REPO, "sdk/ts/node_modules/starknet/package.json")).version} -- do not edit.
// Asserts Cairo (templar_wallet_sig_snip12) == starknet.js typedData.getMessageHash for each KAT.
use starknet::ContractAddress;
use templar_wallet_sig_snip12::{
    STARKNET_DOMAIN_TYPE_HASH, TEMPLAR_KEY_DERIVATION_TYPE_HASH, TEMPLAR_SPEND_TYPE_HASH,
    binding_commitment, derivation_message_hash, derivation_struct_hash, domain_hash,
    spend_message_hash, spend_struct_hash,
};

#[test]
fn kat_type_hashes_match_starknet_js() {
    assert_eq!(STARKNET_DOMAIN_TYPE_HASH, ${typeInfo.StarknetDomain.type_hash});
    assert_eq!(TEMPLAR_SPEND_TYPE_HASH, ${typeInfo.TemplarSpend.type_hash});
    assert_eq!(TEMPLAR_KEY_DERIVATION_TYPE_HASH, ${typeInfo.TemplarKeyDerivation.type_hash});
}
`;
for (const o of spendOut) {
  const i = o.inputs;
  cairo += `
#[test]
fn kat_spend_${o.id}() {
    let chain_id: felt252 = ${i.chain_id_felt};
    let account: ContractAddress = ${addr(i.account)};
    let pool: ContractAddress = ${addr(i.pool)};
    let token_out: ContractAddress = ${addr(i.token_out)};
    let withdrawal_recipient: ContractAddress = ${addr(i.withdrawal_recipient)};
    let binding: felt252 = ${hex(feltOf(i.binding))};
    let salt: felt252 = ${hex(feltOf(i.salt))};
    let bc = binding_commitment(binding, salt);
    assert_eq!(bc, ${o.binding_commitment});
    assert_eq!(domain_hash(chain_id), ${o.domain_hash});
    assert_eq!(
        spend_struct_hash(
            pool, bc, token_out, withdrawal_recipient, ${u128(i.withdrawal_amount)}, ${hex(feltOf(i.intent))}, ${u128(i.valid_until)},
        ),
        ${o.struct_hash},
    );
    let h = spend_message_hash(
        chain_id,
        account,
        pool,
        binding,
        salt,
        token_out,
        withdrawal_recipient,
        ${u128(i.withdrawal_amount)},
        ${hex(feltOf(i.intent))},
        ${u128(i.valid_until)},
    );
    assert_eq!(h, ${o.message_hash});
}
`;
}
for (const o of derivationOut) {
  const i = o.inputs;
  cairo += `
#[test]
fn kat_derivation_${o.id}() {
    let chain_id: felt252 = ${i.chain_id_felt};
    let account: ContractAddress = ${addr(i.account)};
    assert_eq!(domain_hash(chain_id), ${o.domain_hash});
    assert_eq!(derivation_struct_hash(${i.purpose_felt}, ${i.chain_felt}, account), ${o.struct_hash});
    assert_eq!(derivation_message_hash(chain_id, account, ${i.purpose_felt}, ${i.chain_felt}), ${o.message_hash});
}
`;
}

fs.writeFileSync(path.join(__dirname, "kat.json"), JSON.stringify(kat, null, 2) + "\n");
fs.writeFileSync(path.join(__dirname, "typed-data.json"), JSON.stringify(typedDataOut, null, 2) + "\n");
fs.writeFileSync(path.join(__dirname, "tests/test_kat.cairo"), cairo);

console.log("type hashes:");
for (const [k, v] of Object.entries(typeInfo)) console.log(`  ${k}: ${v.type_hash}\n    ${v.encode_type}`);
for (const o of spendOut) console.log(`spend ${o.id}: ${o.message_hash}`);
for (const o of derivationOut) console.log(`derivation ${o.id}: ${o.message_hash}`);

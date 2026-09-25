// The R0 V5 spend message and binding with starknet.js (docs/account-bound-note-spec.md §5.2,
// §5.3), shared by the fixture and signing-request generators.
"use strict";
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "../../../../..");
const sn = require(path.join(REPO, "sdk/ts/node_modules/starknet"));
const { typedData, ec, shortString } = sn;
const poseidon = (xs) => ec.starkCurve.poseidonHashMany(xs.map((x) => BigInt(x)));
const hex = (x) => "0x" + BigInt(x).toString(16);

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

/// A prover's public.json. u128 amounts and 56-bit expiries exceed 2^53, so they are read from the
/// text, never as JS numbers.
function readPublic(dir) {
  const text = fs.readFileSync(path.join(dir, "public.json"), "utf8");
  const pub = JSON.parse(text);
  for (const k of ["withdrawal_amount", "valid_until"]) {
    pub[k] = BigInt(text.match(new RegExp(`"${k}":\\s*(\\d+)`))[1]);
  }
  return pub;
}

/// `TMR0_BIND_V5` (spec §5.2): V4's fields then `valid_until`; never the account.
function binding(p) {
  const b = [BigInt(shortString.encodeShortString("TMR0_BIND_V5")), p.chain, p.pool, p.token_out].map(BigInt);
  b.push(...p.root, ...p.nullifiers[0], ...p.nullifiers[1]);
  b.push(...p.commitments[0], p.deliveries[0], ...p.commitments[1], p.deliveries[1]);
  b.push(p.withdrawal_recipient, p.withdrawal_amount, p.intent, ...p.identity, p.valid_until);
  return poseidon(b);
}

/// The typed data the bound account signs for `pub` with `salt` (spec §5.3).
function spendTypedData(pub, salt) {
  return {
    types: TYPES,
    primaryType: "TemplarSpend",
    domain: { name: "Templar", version: "V5", chainId: shortString.decodeShortString(pub.chain), revision: "1" },
    message: {
      pool: hex(pub.pool),
      binding_commitment: hex(poseidon([binding(pub), salt])),
      token_out: hex(pub.token_out),
      withdrawal_recipient: hex(pub.withdrawal_recipient),
      withdrawal_amount: pub.withdrawal_amount.toString(),
      intent: hex(pub.intent),
    },
  };
}

const messageHash = (pub, salt) => BigInt(typedData.getMessageHash(spendTypedData(pub, salt), hex(pub.account)));

module.exports = { REPO, sn, poseidon, hex, TYPES, readPublic, binding, spendTypedData, messageHash };

// The R0 V6 binding with starknet.js (docs/pool-v3-spec.md §5.2): `TMR0_BIND_V5`, unchanged from
// V5, over a prover's public.json. Shared by the fixture generator and the pool end to end.
"use strict";
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "../../../../..");
const sn = require(path.join(REPO, "sdk/ts/node_modules/starknet"));
const { ec, shortString } = sn;
const poseidon = (xs) => ec.starkCurve.poseidonHashMany(xs.map((x) => BigInt(x)));
const hex = (x) => "0x" + BigInt(x).toString(16);

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

/// `TMR0_BIND_V5` (spec §5.2): V4's fields then `valid_until`.
function binding(p) {
  const b = [BigInt(shortString.encodeShortString("TMR0_BIND_V5")), p.chain, p.pool, p.token_out].map(BigInt);
  b.push(...p.root, ...p.nullifiers[0], ...p.nullifiers[1]);
  b.push(...p.commitments[0], p.deliveries[0], ...p.commitments[1], p.deliveries[1]);
  b.push(p.withdrawal_recipient, p.withdrawal_amount, p.intent, ...p.identity, p.valid_until);
  return poseidon(b);
}

module.exports = { REPO, sn, poseidon, hex, readPublic, binding };

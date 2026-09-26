#!/usr/bin/env node
// Fixtures for the statement-account tests (cairo-r6/account_tests): real client proofs with the
// expected binding computed by starknet.js (the reference encoding, independent of the Cairo code).
//
// Usage: node cairo-r6/kat/gen_fixtures.cjs WORK PROOFS V5_PROOF
//   PROOFS/partial                  an ordinary V6 partial withdrawal (prove_payment_r6)
//   PROOFS/forge-valid-until-zero   a V6 forgery the bridge rejects
//   V5_PROOF                        any R0 V5 proof directory (cairo-arguments.json, public.json)
// Writes WORK/account_tests/fixtures/{name}-{proof,constants}.txt (decimal, one per line).
"use strict";
const fs = require("fs");
const path = require("path");
const { hex, readPublic, binding } = require("./v6.cjs");

const [work, proofs, v5] = process.argv.slice(2);
const out = path.join(work, "account_tests/fixtures");
fs.mkdirSync(out, { recursive: true });

function proofFelts(dir) {
  const args = JSON.parse(fs.readFileSync(path.join(dir, "cairo-arguments.json"))).map((x) => BigInt(x));
  if (Number(args[0]) !== args.length - 1) throw new Error("span length");
  return args.slice(1);
}

/// `constants`: binding, chain, pool.
function write(name, dir) {
  const pub = readPublic(dir);
  const constants = [binding(pub), BigInt(pub.chain), BigInt(pub.pool)];
  fs.writeFileSync(path.join(out, `${name}-proof.txt`), proofFelts(dir).map(String).join("\n") + "\n");
  fs.writeFileSync(path.join(out, `${name}-constants.txt`), constants.map(String).join("\n") + "\n");
  console.log(JSON.stringify({ name, binding: hex(binding(pub)) }));
}

write("ordinary", path.join(proofs, "partial"));
write("forge-valid-until-zero", path.join(proofs, "forge-valid-until-zero"));
write("v5", v5);

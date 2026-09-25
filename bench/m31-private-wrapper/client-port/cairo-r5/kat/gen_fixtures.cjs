#!/usr/bin/env node
// Fixtures for the statement-account tests (cairo-r5/account_tests): real client proofs and, for
// the bound one, a salt, a signature and the spend message hash computed by starknet.js (the
// reference encoding, independent of the Cairo code), plus the expected binding.
//
// Usage: node cairo-r5/kat/gen_fixtures.cjs WORK PROOFS
//   PROOFS/fixture-bound    prove_payment_r5 --bound --account HEX (the mocks deploy at HEX)
//   PROOFS/fixture-ordinary prove_payment_r5 (ordinary)
//   PROOFS/wallet-*         optional real-wallet proofs with WORK/../sign-results/*.json
// Writes WORK/account_tests/fixtures/{name}-{proof,constants}.txt (decimal, one per line).
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { hex, poseidon, readPublic, binding, messageHash } = require("./v5.cjs");

const [work, proofs] = process.argv.slice(2);
const out = path.join(work, "account_tests/fixtures");
fs.mkdirSync(out, { recursive: true });

function proofFelts(dir) {
  const args = JSON.parse(fs.readFileSync(path.join(dir, "cairo-arguments.json"))).map((x) => BigInt(x));
  if (Number(args[0]) !== args.length - 1) throw new Error("span length");
  return args.slice(1);
}

/// `constants`: account, salt, hash, poseidon(signature), binding, chain, pool, then the signature.
function write(name, dir, salt, signature) {
  const pub = readPublic(dir);
  const account = BigInt(pub.account);
  const hash = account === 0n ? 0n : messageHash(pub, salt);
  const constants = [account, salt, hash, signature.length ? poseidon(signature) : 0n, binding(pub), BigInt(pub.chain), BigInt(pub.pool), ...signature];
  fs.writeFileSync(path.join(out, `${name}-proof.txt`), proofFelts(dir).map(String).join("\n") + "\n");
  fs.writeFileSync(path.join(out, `${name}-constants.txt`), constants.map(String).join("\n") + "\n");
  console.log(JSON.stringify({ name, account: pub.account, binding: hex(binding(pub)), hash: hex(hash) }));
}

const fixtureSalt = BigInt("0x" + crypto.createHash("sha256").update("templar-r5-fixture-salt").digest("hex")) % (1n << 251n) | 1n;
write("bound", path.join(proofs, "fixture-bound"), fixtureSalt, [0x1n, 0x2222n, 0x3333n]);
write("ordinary", path.join(proofs, "fixture-ordinary"), 0n, []);

// Real-wallet signatures (cairo-r5/sign results): the same proof, salt and signature the wallet
// signed, for the Sepolia-fork test against the real account classes.
const results = path.join(work, "..", "sign-results");
if (fs.existsSync(results)) {
  for (const f of fs.readdirSync(results).filter((f) => f.endsWith(".json"))) {
    const r = JSON.parse(fs.readFileSync(path.join(results, f)));
    write(`wallet-${r.wallet.id.toLowerCase().replace(/[^a-z0-9]/g, "")}`, path.join(proofs, r.request.proof), BigInt(r.request.salt), r.signature.map(BigInt));
  }
}

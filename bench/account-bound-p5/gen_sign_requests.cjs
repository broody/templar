#!/usr/bin/env node
// P5 signing requests (spec §15 P5, AB-IP6): for each bound proof in PROOFS named
// `<wallet>-<shape>` (prove_payment_r5 --bound --account <the wallet's account>), the exact V5 typed
// data with a fresh salt, grouped by account: the signing page (cairo-r5/sign) asks the connected
// wallet to sign each of its account's requests in turn.
//
// Usage: node bench/account-bound-p5/gen_sign_requests.cjs PROOFS OUT.json
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { hex, readPublic, binding, spendTypedData, messageHash } = require("../m31-private-wrapper/client-port/cairo-r5/kat/v5.cjs");

const [proofs, out] = process.argv.slice(2);
if (!proofs || !out) {
  console.error("usage: gen_sign_requests.cjs PROOFS OUT.json");
  process.exit(2);
}
const requests = {};
for (const d of fs.readdirSync(proofs).sort()) {
  if (!/^(ready|braavos)-[a-z-]+$/.test(d) || !fs.existsSync(path.join(proofs, d, "public.json"))) continue;
  const pub = readPublic(path.join(proofs, d));
  if (BigInt(pub.account) === 0n) continue;
  const salt = (BigInt("0x" + crypto.randomBytes(32).toString("hex")) % (1n << 251n)) | 1n;
  (requests[hex(pub.account)] ??= []).push({
    proof: d,
    salt: hex(salt),
    binding: hex(binding(pub)),
    typedData: spendTypedData(pub, salt),
    messageHash: hex(messageHash(pub, salt)),
  });
}
fs.writeFileSync(out, JSON.stringify(requests, null, 2) + "\n");
for (const [a, rs] of Object.entries(requests)) for (const r of rs) console.log(`${r.proof} ${a} ${r.messageHash}`);

#!/usr/bin/env node
// Signing requests for real wallets (spec §15 P3, "real-wallet signing of §5.3"): for each
// PROOFS/wallet-* proof (prove_payment_r5 --bound --account <the wallet's account>), the exact
// V5 typed data with a fresh salt, keyed by account. The signing page (cairo-r5/sign) shows the
// one for the connected account.
//
// Usage: node cairo-r5/kat/gen_sign_requests.cjs PROOFS OUT.json
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { hex, readPublic, binding, spendTypedData, messageHash } = require("./v5.cjs");

const [proofs, out] = process.argv.slice(2);
const requests = {};
for (const d of fs.readdirSync(proofs).filter((d) => d.startsWith("wallet-"))) {
  const pub = readPublic(path.join(proofs, d));
  const salt = BigInt("0x" + crypto.randomBytes(32).toString("hex")) % (1n << 251n) | 1n;
  requests[hex(pub.account)] = {
    proof: d,
    salt: hex(salt),
    binding: hex(binding(pub)),
    typedData: spendTypedData(pub, salt),
    messageHash: hex(messageHash(pub, salt)),
  };
}
fs.writeFileSync(out, JSON.stringify(requests, null, 2) + "\n");
console.log(Object.entries(requests).map(([a, r]) => `${r.proof} ${a} ${r.messageHash}`).join("\n"));

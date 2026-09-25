#!/usr/bin/env node
// P0b spike (throwaway): sign the SNIP-12 rev-1 TemplarSpend message for one R4 client proof's
// public statement with a FRESH random Stark key (generated here, used once, never written).
//
// Usage: node sign_spend.cjs PUBLIC_JSON OUT_DIR [VALID_UNTIL]
// Writes OUT_DIR/sign.json (typedData, hashes, public key, signature; no private key),
//        OUT_DIR/auth-spike.json    [owner_pubkey, salt, valid_until, r, s]  (valid)
//        OUT_DIR/auth-negative.json same, but (r, s) is the owner's signature over the message
//                                   with valid_until + 1 (a valid signature on another message).
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const REPO = path.resolve(__dirname, "../../..");
const starknet = require(path.join(REPO, "sdk/ts/node_modules/starknet"));
const { typedData, ec, num, shortString } = starknet;
const P = 2n ** 251n + 17n * 2n ** 192n + 1n;
const hex = (x) => num.toHex(x);
const poseidon = (xs) => ec.starkCurve.poseidonHashMany(xs.map((x) => num.toBigInt(x)));

const OWNER_ACCOUNT = "0x0734b2c2"; // same constant as account/src/lib.cairo (S1 KAT account)

const [publicPath, outDir, validUntilArg] = process.argv.slice(2);
const raw = fs.readFileSync(publicPath, "utf8");
const pub = JSON.parse(raw);
// withdrawal_amount is a JSON number above 2^53: take its exact digits from the text.
const amountMatch = raw.match(/"withdrawal_amount"\s*:\s*"?(\d+)"?/);
if (!amountMatch) throw new Error("withdrawal_amount");
pub.withdrawal_amount = amountMatch[1];
const validUntil = BigInt(validUntilArg || "16000000");

// Poseidon('TMR0_BIND_V4', chain, pool, token_out, root, nf0, nf1, cm0, d0, cm1, d1, recipient,
// amount, intent, identity) -- as templar_membership_bridge::binding and validate_bridge_r4.binding.
function binding(p) {
  const b = [BigInt(shortString.encodeShortString("TMR0_BIND_V4")), p.chain, p.pool, p.token_out];
  b.push(...p.root, ...p.nullifiers[0], ...p.nullifiers[1]);
  b.push(...p.commitments[0], p.deliveries[0], ...p.commitments[1], p.deliveries[1]);
  b.push(p.withdrawal_recipient, BigInt(p.withdrawal_amount), p.intent, ...p.identity);
  return poseidon(b);
}

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
    { name: "valid_until", type: "u128" },
  ],
};

function spend(bindingCommitment, vu) {
  return {
    types: TYPES,
    primaryType: "TemplarSpend",
    domain: { name: "Templar", version: "1", chainId: shortString.decodeShortString(pub.chain), revision: "1" },
    message: {
      pool: hex(pub.pool),
      binding_commitment: hex(bindingCommitment),
      token_out: hex(pub.token_out),
      withdrawal_recipient: hex(pub.withdrawal_recipient),
      withdrawal_amount: BigInt(pub.withdrawal_amount).toString(),
      intent: hex(pub.intent),
      valid_until: vu.toString(),
    },
  };
}

const bind = binding(pub);
const salt = BigInt("0x" + crypto.randomBytes(32).toString("hex")) % P;
const commitment = poseidon([bind, salt]);
const td = spend(commitment, validUntil);
const msgHash = BigInt(typedData.getMessageHash(td, OWNER_ACCOUNT));
const tdOther = spend(commitment, validUntil + 1n);
const otherHash = BigInt(typedData.getMessageHash(tdOther, OWNER_ACCOUNT));

// Fresh key, used only in this process.
const priv = ec.starkCurve.utils.randomPrivateKey();
const pubkey = BigInt(ec.starkCurve.getStarkKey(priv));
const sig = ec.starkCurve.sign(hex(msgHash), priv);
const sigOther = ec.starkCurve.sign(hex(otherHash), priv);
const fullPub = ec.starkCurve.getPublicKey(priv, false);
if (!ec.starkCurve.verify(sig, hex(msgHash), fullPub)) throw new Error("self-verify failed");
if (ec.starkCurve.verify(sigOther, hex(msgHash), fullPub)) throw new Error("negative verifies");

const auth = (s) => [pubkey, salt, validUntil, s.r, s.s].map(hex);
fs.mkdirSync(outDir, { recursive: true });
const record = {
  scope: "P0b spike (throwaway): fresh random Stark key, used once; private key never written",
  starknet_js: require(path.join(REPO, "sdk/ts/node_modules/starknet/package.json")).version,
  public_json: path.resolve(publicPath),
  owner_account: OWNER_ACCOUNT,
  owner_pubkey: hex(pubkey),
  binding: hex(bind),
  salt: hex(salt),
  binding_commitment: hex(commitment),
  valid_until: validUntil.toString(),
  typedData: td,
  message_hash: hex(msgHash),
  signature: { r: hex(sig.r), s: hex(sig.s) },
  negative: { reason: "owner signature over the same message with valid_until + 1", message_hash: hex(otherHash),
              signature: { r: hex(sigOther.r), s: hex(sigOther.s) } },
  calldata_tail_order: ["owner_pubkey", "salt", "valid_until", "r", "s"],
};
fs.writeFileSync(path.join(outDir, "sign.json"), JSON.stringify(record, null, 2) + "\n");
fs.writeFileSync(path.join(outDir, "auth-spike.json"), JSON.stringify(auth(sig)) + "\n");
fs.writeFileSync(path.join(outDir, "auth-negative.json"), JSON.stringify(auth(sigOther)) + "\n");
console.log(JSON.stringify({ binding: record.binding, message_hash: record.message_hash, owner_pubkey: record.owner_pubkey }));

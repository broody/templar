#!/usr/bin/env node
// P0b spike (throwaway): headless tests for the signing page logic (sign-logic.mjs) with the local
// starknet.js 10.8.0 and a mock wallet on a FRESH random Stark key (test/mock-wallet.mjs).
//
//   node bench/wallet-sig-spike/sign-page/test/test_logic.mjs [--live]
//
// --live also runs read-only JSON-RPC calls against the local Sepolia pathfinder
// (http://127.0.0.1:9545/rpc/v0_9): a class hash lookup and is_valid_signature on a real account
// with a mock signature (expected: not VALID). No transaction is ever built or sent.
//
// Library integrity: the SHA-384 pinned in LIBS is compared with the file inside the npm tarball
// in the local npm cache (content-addressed by the lockfile sha512), extracted under
// target/wallet-sig-spike/sign-page/npm/.
import { createRequire } from 'node:module';
import { readFileSync, existsSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import * as L from '../sign-logic.mjs';
import { createMockWallet, mockRpc } from './mock-wallet.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PAGE = path.resolve(HERE, '..');
const REPO = path.resolve(PAGE, '../../..');
const OUT = path.join(REPO, 'target/wallet-sig-spike/sign-page');
const require = createRequire(import.meta.url);
const snCjs = require(path.join(REPO, 'sdk/ts/node_modules/starknet'));
const LIVE = process.argv.includes('--live');

let passed = 0;
let failed = 0;
async function check(name, fn) {
  try {
    const note = await fn();
    passed++;
    console.log(`ok   ${name}${note ? `  (${note})` : ''}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}\n     ${String(e && e.stack ? e.stack : e).split('\n').slice(0, 4).join('\n     ')}`);
  }
}

const sha384 = (buf) => 'sha384-' + createHash('sha384').update(buf).digest('base64');

// npm tarball in the local cache (cacache content-v2 is addressed by the sha512 in the lockfile).
const TARBALLS = {
  starknet: {
    sri512: 'sha512-skJ2tTmj/Qz/iXRRwDBmZQtymR020xZt4+4k3SBbPlHgELyiC3HnJjEO0hbUQsEsQVjjVbpWVQc9B+dLHvZvzQ==',
    file: 'package/dist/index.global.js',
    lock: 'sdk/ts/package-lock.json',
  },
  getStarknet: {
    sri512: 'sha512-env/ZN5EmDJ6vDtIgjOjsEvvzdKBDaWZ0aLe79IVJ7lq2icqKbX86yR1/CUf4AU31AFYZHWZ3daOaGFT4nHSUQ==',
    file: 'package/dist/ui.js',
    lock: '~/development/jokers-of-neon-app/package-lock.json (@starknet-io/get-starknet 4.0.7)',
  },
};
function tarballFile(key) {
  const t = TARBALLS[key];
  const hex = Buffer.from(t.sri512.slice('sha512-'.length), 'base64').toString('hex');
  const blob = path.join(homedir(), '.npm/_cacache/content-v2/sha512', hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
  if (!existsSync(blob)) return null;
  const got = 'sha512-' + createHash('sha512').update(readFileSync(blob)).digest('base64');
  assert.equal(got, t.sri512, `cached tarball for ${key} does not match its sha512`);
  const dir = path.join(OUT, 'npm', `${L.LIBS[key].name.replace('/', '__')}-${L.LIBS[key].version}`);
  mkdirSync(dir, { recursive: true });
  execFileSync('tar', ['-xzf', blob, '-C', dir, t.file]);
  return readFileSync(path.join(dir, t.file));
}

const emptySigs = () => ({ derivation: [null, null], spend: [null, null] });

// ---------------------------------------------------------------------------------------------
await check('LIBS: pinned jsDelivr URLs (exact versions, /npm/ only)', () => {
  for (const lib of Object.values(L.LIBS)) {
    assert.ok(lib.url.startsWith(`https://cdn.jsdelivr.net/npm/${lib.name}@${lib.version}/`), lib.url);
    assert.match(lib.version, /^\d+\.\d+\.\d+$/);
    assert.match(lib.integrity, /^sha384-[A-Za-z0-9+/]{64}$/);
  }
});

let snIife = null;
await check('LIBS: starknet 10.8.0 integrity == npm tarball dist/index.global.js; local copy identical', () => {
  const buf = tarballFile('starknet');
  if (!buf) return 'SKIPPED: tarball not in npm cache';
  assert.equal(sha384(buf), L.LIBS.starknet.integrity);
  const local = readFileSync(path.join(REPO, 'sdk/ts/node_modules/starknet/dist/index.global.js'));
  assert.ok(buf.equals(local));
  // Evaluate exactly as index.html does (function scope, so no global `starknet` is declared).
  const code = buf.toString('utf8').replace(/^\/\/# sourceMappingURL=.*$/m, '');
  snIife = new Function(`${code}\n;return starknet;`)();
  assert.equal(typeof snIife.typedData.getMessageHash, 'function');
  assert.equal(globalThis.starknet, undefined);
  return L.LIBS.starknet.integrity;
});

await check('LIBS: get-starknet 4.0.7 integrity == npm tarball dist/ui.js (self-contained module)', () => {
  const buf = tarballFile('getStarknet');
  if (!buf) return 'SKIPPED: tarball not in npm cache';
  assert.equal(sha384(buf), L.LIBS.getStarknet.integrity);
  const src = buf.toString('utf8');
  assert.equal(/^\s*import\s/m.test(src), false, 'ui.js has static imports (would break the blob: import)');
  assert.ok(/export\s*\{[^}]*\bconnect\b/.test(src));
  return L.LIBS.getStarknet.integrity;
});

await check('KAT self-check (starknet.js CJS build) reproduces all S1 values', () => {
  const k = L.katSelfCheck(snCjs);
  assert.ok(k.ok, JSON.stringify(k.rows.filter((r) => !r.ok)));
  return `${k.rows.length}/${k.rows.length}`;
});

await check('KAT self-check (browser IIFE build, as evaluated by the page)', () => {
  if (!snIife) return 'SKIPPED';
  const k = L.katSelfCheck(snIife);
  assert.ok(k.ok, JSON.stringify(k.rows.filter((r) => !r.ok)));
  return `${k.rows.length}/${k.rows.length}`;
});

await check('typed data for the KAT inputs is identical to S1 typed-data.json', () => {
  const s1 = JSON.parse(readFileSync(path.join(REPO, 'bench/wallet-sig-spike/snip12/typed-data.json'), 'utf8'));
  assert.deepEqual(L.spendTypedData(snCjs, 'SN_SEPOLIA', L.KAT_SPEND), s1.spend.typedData);
  assert.deepEqual(
    L.derivationTypedData('SN_SEPOLIA', L.KAT_ACCOUNT, L.KAT_DERIVATION_PURPOSE, 'SN_SEPOLIA'),
    s1.derivation.typedData,
  );
  assert.equal(s1.spend.account, L.KAT_ACCOUNT);
  assert.equal(s1.spend.messageHash, L.KAT_EXPECTED.spend_message_hash);
  assert.equal(s1.derivation.messageHash, L.KAT_EXPECTED.derivation_message_hash);
});

await check('describeChainId: wallet hex -> domain short string, same felt, same hash', () => {
  const sep = L.describeChainId(snCjs, '0x534e5f5345504f4c4941');
  assert.deepEqual([sep.text, sep.domainValue, sep.network], ['SN_SEPOLIA', 'SN_SEPOLIA', 'sepolia']);
  const main = L.describeChainId(snCjs, '0x534e5f4d41494e');
  assert.deepEqual([main.text, main.network], ['SN_MAIN', 'mainnet']);
  assert.equal(L.describeChainId(snCjs, 'SN_SEPOLIA').hex, '0x534e5f5345504f4c4941');
  // A numeric-looking short string must stay hex (starknet.js would parse "123" as the number 123).
  const numeric = L.describeChainId(snCjs, snCjs.shortString.encodeShortString('123'));
  assert.equal(numeric.domainValue, numeric.hex);
  // A felt that is not printable text stays hex.
  const odd = L.describeChainId(snCjs, '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
  assert.equal(odd.domainValue, odd.hex);
  for (const c of [sep, main, numeric, odd]) {
    const a = L.messageHash(snCjs, L.spendTypedData(snCjs, c.domainValue, L.KAT_SPEND), L.KAT_ACCOUNT);
    const b = L.messageHash(snCjs, L.spendTypedData(snCjs, c.hex, L.KAT_SPEND), L.KAT_ACCOUNT);
    assert.equal(a, b);
  }
});

await check('normalizeSignature / sameSignature', () => {
  assert.deepEqual(L.normalizeSignature(['0x0a', '11', 12n]), ['0xa', '0xb', '0xc']);
  assert.deepEqual(L.normalizeSignature({ r: '0x1', s: 2n }), ['0x1', '0x2']);
  assert.ok(L.sameSignature(['0x0a', '0x1'], ['10', '1']));
  assert.ok(!L.sameSignature(['0x1', '0x2'], ['0x1', '0x2', '0x3']));
  assert.throws(() => L.normalizeSignature('0x1'));
});

// ---------------------------------------------------------------------------------------------
// Full page flow against mock wallets (the same functions index.html calls).
// ---------------------------------------------------------------------------------------------
async function flow(mode) {
  const mock = createMockWallet(snCjs, { mode });
  const conn = await L.readWallet(snCjs, mock.swo);
  const messages = L.buildMessages(snCjs, conn.account, conn.chain);
  const sigs = emptySigs();
  const steps = [];
  await L.signAll(mock.swo, messages, sigs, (i, step, status) => steps.push(`${i}:${status}`));
  const checks = await L.readOnlyChecks(snCjs, mockRpc(snCjs, mock), conn.account, messages, sigs);
  const kat = L.katSelfCheck(snCjs);
  const report = L.buildReport({ conn, messages, sigs, kat, checks, rpcLabel: 'mock', libsVerified: true });
  return { mock, conn, messages, sigs, steps, checks, report };
}

await check('mock wallet (deterministic): 4 signatures, pairs identical, all verify, only allowed wallet calls', async () => {
  const r = await flow('deterministic');
  assert.deepEqual(r.steps, ['0:pending', '0:done', '1:pending', '1:done', '2:pending', '2:done', '3:pending', '3:done']);
  assert.deepEqual(r.mock.calls, [
    'wallet_requestAccounts', 'wallet_requestChainId',
    'wallet_signTypedData', 'wallet_signTypedData', 'wallet_signTypedData', 'wallet_signTypedData',
  ]);
  assert.equal(L.pairStatus(r.sigs.derivation), true);
  assert.equal(L.pairStatus(r.sigs.spend), true);
  for (const k of ['derivation', 'spend']) {
    for (const s of r.sigs[k]) assert.ok(r.mock.verify(r.messages[k].messageHash, s.signature));
  }
  // The hash binds the connected account: it differs from the S1 KAT hash for 0x0734b2c2.
  assert.notEqual(r.messages.spend.messageHash, L.KAT_EXPECTED.spend_message_hash);
  assert.equal(
    r.messages.spend.messageHash,
    L.messageHash(snCjs, L.spendTypedData(snCjs, 'SN_SEPOLIA', L.KAT_SPEND), r.mock.address),
  );
  // The derivation message names the connected account and the spike-only purpose.
  assert.equal(BigInt(r.messages.derivation.typedData.message.account), BigInt(r.mock.address));
  assert.equal(r.messages.derivation.typedData.message.purpose, L.SPIKE_DERIVATION_PURPOSE);
  assert.equal(r.messages.derivation.typedData.message.chain, 'SN_SEPOLIA');
  assert.ok(r.checks.signatures.every((x) => x.matched_variant === 'standard'));
  assert.equal(r.checks.class_hash, '0x1234abcd');
});

await check('mock wallet (randomized nonce): pairs reported different, signatures still valid', async () => {
  const r = await flow('randomized');
  assert.equal(L.pairStatus(r.sigs.derivation), false);
  assert.equal(L.pairStatus(r.sigs.spend), false);
  assert.ok(r.checks.signatures.every((x) => x.matched_variant === 'standard'));
});

await check('mock wallet (ASCII domain version): diagnostic names the variant', async () => {
  const r = await flow('ascii_version');
  assert.ok(r.checks.signatures.every((x) => x.matched_variant === 'version_and_revision_ascii'));
  assert.ok(r.checks.signatures.every((x) => x.checks.standard.valid === false));
});

await check('signAll resumes after a rejected prompt without re-asking signed ones', async () => {
  const mock = createMockWallet(snCjs);
  let rejectOnce = true;
  const swo = {
    ...mock.swo,
    async request(call) {
      if (call.type === 'wallet_signTypedData' && call.params.primaryType === 'TemplarSpend' && rejectOnce) {
        rejectOnce = false;
        throw { code: 113, message: 'User abort' };
      }
      return mock.swo.request(call);
    },
  };
  const conn = await L.readWallet(snCjs, swo);
  const messages = L.buildMessages(snCjs, conn.account, conn.chain);
  const sigs = emptySigs();
  await assert.rejects(L.signAll(swo, messages, sigs));
  assert.ok(sigs.derivation[0] && !sigs.spend[0]);
  const before = mock.calls.filter((c) => c === 'wallet_signTypedData').length;
  await L.signAll(swo, messages, sigs);
  const after = mock.calls.filter((c) => c === 'wallet_signTypedData').length;
  assert.equal(before, 1);
  assert.equal(after - before, 3);
});

await check('report JSON: required fields, serialisable, no private material', async () => {
  const r = await flow('deterministic');
  const j = JSON.parse(JSON.stringify(r.report));
  for (const k of ['wallet', 'account', 'chain_id', 'class_hash', 'messages', 'kat_self_check_ok', 'libraries']) {
    assert.ok(k in j, k);
  }
  assert.equal(j.wallet.name, 'Templar mock wallet (test only)');
  assert.equal(j.chain_id.text, 'SN_SEPOLIA');
  assert.equal(j.class_hash, '0x1234abcd');
  assert.equal(j.messages.spend.identical, true);
  assert.equal(j.messages.spend.signatures.length, 2);
  assert.ok(j.messages.spend.typed_data.types.TemplarSpend);
  assert.equal(j.messages.spend.message_hash, r.messages.spend.messageHash);
  assert.equal(j.derivation_purpose, 'TEMPLAR_SIGTEST_V0');
  const text = JSON.stringify(j).toLowerCase();
  assert.ok(!/private|secret_key|privkey/.test(text));
  return `${JSON.stringify(j).length} bytes`;
});

await check('page sources: no transaction or permission calls; only jsDelivr URLs', () => {
  const html = readFileSync(path.join(PAGE, 'index.html'), 'utf8');
  const logic = readFileSync(path.join(PAGE, 'sign-logic.mjs'), 'utf8');
  for (const src of [html, logic]) {
    for (const bad of ['addInvokeTransaction', 'addDeclareTransaction', 'addDeployAccountTransaction',
      'switchStarknetChain', 'addStarknetChain', 'watchAsset', 'wallet_deploymentData', 'execute(']) {
      assert.ok(!src.includes(bad), bad);
    }
    const urls = src.match(/https?:\/\/[^\s'"`)<>]+/g) || [];
    for (const u of urls) assert.ok(u.startsWith('https://cdn.jsdelivr.net/npm/'), u);
  }
  const reqTypes = new Set([...html.matchAll(/type:\s*'(wallet_[A-Za-z]+)'/g), ...logic.matchAll(/type:\s*'(wallet_[A-Za-z]+)'/g)]
    .map((m) => m[1]));
  assert.deepEqual([...reqTypes].sort(), ['wallet_requestAccounts', 'wallet_requestChainId', 'wallet_signTypedData']);
  assert.ok(html.includes("from './sign-logic.mjs'"));
  assert.ok(html.includes("exclude: ['metamask']"));
});

// ---------------------------------------------------------------------------------------------
if (LIVE) {
  const RPC = 'http://127.0.0.1:9545/rpc/v0_9';
  await check(`live read-only: real Sepolia account via ${RPC}`, async () => {
    const rpc = L.makeRpc(RPC);
    assert.equal(await rpc('starknet_chainId', []), '0x534e5f5345504f4c4941');
    // Senders of INVOKEs in recent blocks are "some deployed accounts" (read-only lookups).
    const senders = [];
    let n = await rpc('starknet_blockNumber', []);
    for (let i = 0; i < 30 && senders.length < 12; i++, n--) {
      const b = await rpc('starknet_getBlockWithTxs', { block_id: { block_number: n } });
      for (const t of b.transactions) {
        if (t.type === 'INVOKE' && t.sender_address && !senders.includes(t.sender_address)) senders.push(t.sender_address);
      }
    }
    assert.ok(senders.length, 'no INVOKE sender found in the last 30 blocks');
    const notes = [];
    let exercised = false;
    for (const account of senders) {
      const mock = createMockWallet(snCjs, { address: account });
      const conn = await L.readWallet(snCjs, mock.swo);
      const messages = L.buildMessages(snCjs, conn.account, conn.chain);
      const sigs = emptySigs();
      await L.signAll(mock.swo, messages, sigs);
      const checks = await L.readOnlyChecks(snCjs, rpc, conn.account, messages, sigs);
      assert.match(checks.class_hash, /^0x[0-9a-f]+$/);
      assert.ok(checks.signatures.every((x) => x.matched_variant === null), 'mock key must not satisfy a real account');
      const s = checks.signatures[0].checks.standard;
      const outcome = s.error ? `error: ${s.error.slice(0, 90)}` : `[${s.result.join(', ')}]`;
      notes.push(`${conn.account.slice(0, 10)}.. class ${checks.class_hash.slice(0, 10)}.. ${s.entrypoint} -> ${outcome}`);
      if (!/entrypoint does not exist/i.test(outcome)) {
        exercised = true;
        break;
      }
    }
    assert.ok(exercised, `no sender with is_valid_signature among ${senders.length}`);
    return `\n       ${notes.join('\n       ')}`;
  });
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

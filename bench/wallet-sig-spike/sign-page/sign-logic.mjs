// P0b spike (throwaway): DOM-free logic for the wallet signing page (index.html).
//
// Everything here is plain ES module code with no imports: starknet.js is passed in as `sn` and the
// wallet as `swo` (a get-starknet StarknetWindowObject), so node tests can run the exact code the
// page runs, with a local starknet.js 10.8.0 and a mock wallet (test/test_logic.mjs).
//
// Typed data is the S1 SNIP-12 revision-1 encoding (bench/wallet-sig-spike/snip12/typed-data.json).
// The message hash is starknet.js typedData.getMessageHash(typedData, account): it binds the
// signer account.

export const PAGE_ID = 'templar-p0b-sign-page/v1';

// Libraries, fetched from jsDelivr (npm files served verbatim) and checked with Subresource
// Integrity before use. Integrity = sha384 of the npm tarball file (verified against the npm cache).
export const LIBS = {
  starknet: {
    name: 'starknet',
    version: '10.8.0',
    url: 'https://cdn.jsdelivr.net/npm/starknet@10.8.0/dist/index.global.js',
    integrity: 'sha384-DbZWEnxQq8varDEksnUMqbJiyXIfymtrLPEQBbN5K4eZR5elHpN2tinGSfS2+9pD',
  },
  getStarknet: {
    name: '@starknet-io/get-starknet',
    version: '4.0.7',
    url: 'https://cdn.jsdelivr.net/npm/@starknet-io/get-starknet@4.0.7/dist/ui.js',
    integrity: 'sha384-dapAnd74G6L9ETZfVGV/9duLXURycOIdirFA4UL5lbvChKom8DLNrwkmMp1AgL9u',
  },
};

// --------------------------------------------------------------------------------------------
// SNIP-12 revision 1 types (member order is the encoding order). Identical to S1.
// --------------------------------------------------------------------------------------------
export const STARKNET_DOMAIN = [
  { name: 'name', type: 'shortstring' },
  { name: 'version', type: 'shortstring' },
  { name: 'chainId', type: 'shortstring' },
  { name: 'revision', type: 'shortstring' },
];
export const TEMPLAR_SPEND = [
  { name: 'pool', type: 'ContractAddress' },
  { name: 'binding_commitment', type: 'felt' },
  { name: 'token_out', type: 'ContractAddress' },
  { name: 'withdrawal_recipient', type: 'ContractAddress' },
  { name: 'withdrawal_amount', type: 'u128' },
  { name: 'intent', type: 'felt' },
  { name: 'valid_until', type: 'u128' },
];
export const TEMPLAR_KEY_DERIVATION = [
  { name: 'purpose', type: 'shortstring' },
  { name: 'chain', type: 'shortstring' },
  { name: 'account', type: 'ContractAddress' },
];
export const SPEND_TYPES = { StarknetDomain: STARKNET_DOMAIN, TemplarSpend: TEMPLAR_SPEND };
export const DERIVATION_TYPES = {
  StarknetDomain: STARKNET_DOMAIN,
  TemplarKeyDerivation: TEMPLAR_KEY_DERIVATION,
};

// sn_keccak of the rev-1 encodeType strings (S1 report, also pinned in the Cairo package).
export const TYPE_HASHES = {
  StarknetDomain: '0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210',
  TemplarSpend: '0x345e1c67b3674e509394d35a1a2f6205c217586359fe5c5c729bd3cfd64710e',
  TemplarKeyDerivation: '0x2c12ffa63c6a1e80ff60bf73eef3bf52feb22e5cf5b4c75a4d5df70a8245e1',
};

// Fixed spend inputs (S1 KAT). The pool is a made-up test address and every amount is 0.
export const KAT_SPEND = {
  pool: '0x2da0011111111111111111111111111111111111111111111111111111137b9',
  binding: '0x1234',
  salt: '0x5678',
  token_out: '0x0',
  withdrawal_recipient: '0x0',
  withdrawal_amount: '0',
  intent: '0x0',
  valid_until: '16000000',
};
export const KAT_ACCOUNT = '0x0734b2c2';
export const KAT_CHAIN = 'SN_SEPOLIA';
export const KAT_DERIVATION_PURPOSE = 'TEMPLAR_SECRET_V1';

// S1 expected hashes for the fixed KAT (account 0x0734b2c2, SN_SEPOLIA).
export const KAT_EXPECTED = {
  binding_commitment: '0x4ab86daf490dde3bec017cc90ea7b076ea8e4a290b55d3b2e925cf392420afb',
  domain_hash: '0x4d3c5487c1499cd0d4be51d58e8830f2719c23a3556c31011f707d39fa2d909',
  spend_struct_hash: '0x39d457205462866c2081940ad88f5b51b9e5c445040e5abf24996ce9cd78f98',
  spend_message_hash: '0x2bf922f4a8ad28fd0054dc05d00ffe0a02894650e2ac1723fe3f81ac697be2c',
  derivation_struct_hash: '0x57ea3d3d29f5a38085220506972351f9c961963bc3b5016a98797dcf71fa864',
  derivation_message_hash: '0x154aae51ddf2e6c317b04c1ea92e565b969534c2f252d39588072d465f16864',
  domain_hash_ascii_version: '0x76913d0d05d57447acf2d9c33da65cd2bc2fb88f06a833bd581a48db0ff6f83',
};

// The page signs the derivation message with a spike-only purpose, NOT the S1 KAT purpose
// 'TEMPLAR_SECRET_V1': the exported JSON contains these signatures, and a signature over a future
// production derivation message would be the user's Templar secret. Same type, same encoding.
export const SPIKE_DERIVATION_PURPOSE = 'TEMPLAR_SIGTEST_V0';

// Signing order: interleaved, so a wallet that caches its last signature cannot fake determinism.
export const SIGN_PLAN = [
  { message: 'derivation', round: 1 },
  { message: 'spend', round: 1 },
  { message: 'derivation', round: 2 },
  { message: 'spend', round: 2 },
];

export const VALID = 0x56414c4944n; // 'VALID'
export const STARKNET_MESSAGE = 'StarkNet Message';

// --------------------------------------------------------------------------------------------
// Small helpers.
// --------------------------------------------------------------------------------------------
const clone = (x) => JSON.parse(JSON.stringify(x));
export const toHexFelt = (v) => '0x' + BigInt(v).toString(16);
export const normalizeAddress = (a) => '0x' + BigInt(a).toString(16).padStart(64, '0');
export const sameFelt = (a, b) => BigInt(a) === BigInt(b);

export function domain(chainId) {
  return { name: 'Templar', version: '1', chainId, revision: '1' };
}

export function bindingCommitment(sn, binding, salt) {
  return toHexFelt(sn.ec.starkCurve.poseidonHashMany([BigInt(binding), BigInt(salt)]));
}

export function spendTypedData(sn, chainId, f) {
  return {
    types: clone(SPEND_TYPES),
    primaryType: 'TemplarSpend',
    domain: domain(chainId),
    message: {
      pool: f.pool,
      binding_commitment: bindingCommitment(sn, f.binding, f.salt),
      token_out: f.token_out,
      withdrawal_recipient: f.withdrawal_recipient,
      withdrawal_amount: f.withdrawal_amount,
      intent: f.intent,
      valid_until: f.valid_until,
    },
  };
}

export function derivationTypedData(chainId, account, purpose, chain) {
  return {
    types: clone(DERIVATION_TYPES),
    primaryType: 'TemplarKeyDerivation',
    domain: domain(chainId),
    message: { purpose, chain, account },
  };
}

// Chain id from wallet_requestChainId (a hex felt, per the wallet API) -> the value the page puts
// in the domain. A printable short string such as 'SN_SEPOLIA' is used as text (same felt, and
// what the wallet shows); anything else stays hex. Numeric-looking text would be re-read as a
// number by starknet.js, so it also stays hex.
export function describeChainId(sn, raw) {
  const s = String(raw).trim();
  const big = /^(0x[0-9a-f]+|\d+)$/i.test(s) ? BigInt(s) : BigInt(sn.shortString.encodeShortString(s));
  const hex = toHexFelt(big);
  let text = null;
  try {
    text = sn.shortString.decodeShortString(hex);
  } catch (_) {
    text = null;
  }
  const printable = typeof text === 'string' && /^[\x20-\x7e]{1,31}$/.test(text);
  const numericLooking = printable && /^(\d+|0x[0-9a-f]*)$/i.test(text);
  const useText = printable && !numericLooking;
  return {
    raw: s,
    hex,
    text: printable ? text : null,
    domainValue: useText ? text : hex,
    network: text === 'SN_SEPOLIA' ? 'sepolia' : text === 'SN_MAIN' ? 'mainnet' : null,
  };
}

export function messageHash(sn, td, account) {
  return toHexFelt(sn.typedData.getMessageHash(td, account));
}

// Rev-1 message hash computed by hand, optionally with the domain version / revision encoded as
// ASCII ('1' = 0x31) instead of the number 1 that starknet.js uses. Used only as a diagnostic: if
// a wallet signature verifies against a variant, the wallet encodes the domain differently.
export function messageHashVariant(sn, td, account, { versionAscii = false, revisionAscii = false } = {}) {
  const dom = { ...td.domain };
  if (versionAscii) dom.version = sn.shortString.encodeShortString(String(td.domain.version));
  if (revisionAscii) dom.revision = sn.shortString.encodeShortString(String(td.domain.revision));
  const domainHash = sn.typedData.getStructHash(td.types, 'StarknetDomain', dom, '1');
  const structHash = sn.typedData.getStructHash(td.types, td.primaryType, td.message, '1');
  return toHexFelt(
    sn.ec.starkCurve.poseidonHashMany([
      BigInt(sn.shortString.encodeShortString(STARKNET_MESSAGE)),
      BigInt(domainHash),
      BigInt(account),
      BigInt(structHash),
    ]),
  );
}

export const HASH_VARIANTS = [
  { id: 'standard', opts: {} },
  { id: 'version_ascii', opts: { versionAscii: true } },
  { id: 'version_and_revision_ascii', opts: { versionAscii: true, revisionAscii: true } },
];

export function hashVariants(sn, td, account) {
  const out = {};
  for (const v of HASH_VARIANTS) out[v.id] = messageHashVariant(sn, td, account, v.opts);
  return out;
}

// Wallets return string[] (hex or decimal); very old ones returned { r, s }.
export function normalizeSignature(sig) {
  if (Array.isArray(sig)) return sig.map(toHexFelt);
  if (sig && typeof sig === 'object' && 'r' in sig && 's' in sig) return [toHexFelt(sig.r), toHexFelt(sig.s)];
  throw new Error(`unrecognised signature format (${typeof sig})`);
}

export function sameSignature(a, b) {
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => sameFelt(x, b[i]));
}

// --------------------------------------------------------------------------------------------
// Self-check: the loaded starknet.js reproduces the S1 KAT (account 0x0734b2c2, SN_SEPOLIA).
// --------------------------------------------------------------------------------------------
export function katSelfCheck(sn) {
  const spend = spendTypedData(sn, KAT_CHAIN, KAT_SPEND);
  const deriv = derivationTypedData(KAT_CHAIN, KAT_ACCOUNT, KAT_DERIVATION_PURPOSE, KAT_CHAIN);
  const got = {
    type_hash_StarknetDomain: toHexFelt(sn.typedData.getTypeHash(SPEND_TYPES, 'StarknetDomain', '1')),
    type_hash_TemplarSpend: toHexFelt(sn.typedData.getTypeHash(SPEND_TYPES, 'TemplarSpend', '1')),
    type_hash_TemplarKeyDerivation: toHexFelt(
      sn.typedData.getTypeHash(DERIVATION_TYPES, 'TemplarKeyDerivation', '1'),
    ),
    binding_commitment: spend.message.binding_commitment,
    domain_hash: toHexFelt(sn.typedData.getStructHash(SPEND_TYPES, 'StarknetDomain', spend.domain, '1')),
    spend_struct_hash: toHexFelt(sn.typedData.getStructHash(spend.types, 'TemplarSpend', spend.message, '1')),
    spend_message_hash: messageHash(sn, spend, KAT_ACCOUNT),
    derivation_struct_hash: toHexFelt(
      sn.typedData.getStructHash(deriv.types, 'TemplarKeyDerivation', deriv.message, '1'),
    ),
    derivation_message_hash: messageHash(sn, deriv, KAT_ACCOUNT),
    domain_hash_ascii_version: toHexFelt(
      sn.typedData.getStructHash(SPEND_TYPES, 'StarknetDomain', { ...spend.domain, version: '0x31' }, '1'),
    ),
    standard_variant_equals_getMessageHash: messageHashVariant(sn, spend, KAT_ACCOUNT),
  };
  const expected = {
    type_hash_StarknetDomain: TYPE_HASHES.StarknetDomain,
    type_hash_TemplarSpend: TYPE_HASHES.TemplarSpend,
    type_hash_TemplarKeyDerivation: TYPE_HASHES.TemplarKeyDerivation,
    ...KAT_EXPECTED,
    standard_variant_equals_getMessageHash: KAT_EXPECTED.spend_message_hash,
  };
  const rows = Object.keys(expected).map((k) => ({
    name: k,
    expected: expected[k],
    got: got[k],
    ok: sameFelt(expected[k], got[k]),
  }));
  return { ok: rows.every((r) => r.ok), rows };
}

// --------------------------------------------------------------------------------------------
// Wallet flow (DOM-free). The page and the node tests both call these.
// --------------------------------------------------------------------------------------------
export async function readWallet(sn, swo) {
  const accounts = await swo.request({ type: 'wallet_requestAccounts' });
  if (!Array.isArray(accounts) || accounts.length === 0) throw new Error('wallet returned no account');
  const chainRaw = await swo.request({ type: 'wallet_requestChainId' });
  return {
    wallet: { name: swo.name ?? null, id: swo.id ?? null, version: swo.version ?? null },
    account: normalizeAddress(accounts[0]),
    accountRaw: String(accounts[0]),
    chain: describeChainId(sn, chainRaw),
  };
}

// The two messages the page signs, with hashes computed locally for the connected account.
export function buildMessages(sn, account, chain, purpose = SPIKE_DERIVATION_PURPOSE) {
  const acc = normalizeAddress(account);
  const derivation = derivationTypedData(chain.domainValue, acc, purpose, chain.domainValue);
  const spend = spendTypedData(sn, chain.domainValue, KAT_SPEND);
  return {
    derivation: {
      label: 'TemplarKeyDerivation',
      typedData: derivation,
      messageHash: messageHash(sn, derivation, acc),
      hashVariants: hashVariants(sn, derivation, acc),
    },
    spend: {
      label: 'TemplarSpend (fixed test values)',
      typedData: spend,
      inputs: { binding: KAT_SPEND.binding, salt: KAT_SPEND.salt },
      messageHash: messageHash(sn, spend, acc),
      hashVariants: hashVariants(sn, spend, acc),
    },
  };
}

export async function signTypedData(swo, typedData) {
  const raw = await swo.request({ type: 'wallet_signTypedData', params: typedData });
  return { raw, signature: normalizeSignature(raw) };
}

// Runs SIGN_PLAN steps that are not yet in `sigs` ({ derivation: [s1, s2], spend: [s1, s2] }).
// onStep(index, step, status, detail) reports progress. Stops at the first error (rethrown).
export async function signAll(swo, messages, sigs, onStep = () => {}) {
  for (let i = 0; i < SIGN_PLAN.length; i++) {
    const step = SIGN_PLAN[i];
    if (sigs[step.message][step.round - 1]) {
      onStep(i, step, 'done', sigs[step.message][step.round - 1]);
      continue;
    }
    onStep(i, step, 'pending');
    try {
      const r = await signTypedData(swo, messages[step.message].typedData);
      sigs[step.message][step.round - 1] = r;
      onStep(i, step, 'done', r);
    } catch (e) {
      onStep(i, step, 'error', e);
      throw e;
    }
  }
  return sigs;
}

export function pairStatus(pair) {
  if (!pair[0] || !pair[1]) return null;
  return sameSignature(pair[0].signature, pair[1].signature);
}

// --------------------------------------------------------------------------------------------
// Optional read-only checks over JSON-RPC (starknet_getClassHashAt, starknet_call). No writes.
// --------------------------------------------------------------------------------------------
export function makeRpc(url, fetchImpl = globalThis.fetch) {
  let id = 0;
  return async (method, params) => {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
    });
    const text = await res.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch (_) {
      throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    if (body.error) {
      const data = body.error.data ? ` ${JSON.stringify(body.error.data).slice(0, 400)}` : '';
      throw new Error(`RPC ${body.error.code}: ${body.error.message}${data}`);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return body.result;
  };
}

const errText = (e) => String((e && e.message) || e).slice(0, 500);

export async function isValidSignature(sn, rpc, account, hash, signature) {
  const calldata = [toHexFelt(hash), toHexFelt(signature.length), ...signature.map(toHexFelt)];
  let last = null;
  for (const entrypoint of ['is_valid_signature', 'isValidSignature']) {
    try {
      const result = await rpc('starknet_call', {
        request: {
          contract_address: account,
          entry_point_selector: sn.hash.getSelectorFromName(entrypoint),
          calldata,
        },
        block_id: 'latest',
      });
      const valid = Array.isArray(result) && result.length > 0 && BigInt(result[0]) === VALID;
      return { entrypoint, result, valid };
    } catch (e) {
      last = { entrypoint, error: errText(e), valid: false };
      // Only fall through to the camelCase name when the snake_case one does not exist.
      if (!/entry.?point/i.test(last.error)) return last;
    }
  }
  return { ...last, missing: true };
}

// For each signature: is_valid_signature(standard hash). Only when that is not VALID are the
// ASCII-domain variants tried, to tell "wallet hashed differently" from "account rejects".
export async function readOnlyChecks(sn, rpc, account, messages, sigs) {
  const out = { rpc_chain_id: null, class_hash: null, class_hash_error: null, signatures: [] };
  try {
    out.rpc_chain_id = await rpc('starknet_chainId', []);
  } catch (e) {
    out.rpc_chain_id_error = errText(e);
  }
  try {
    out.class_hash = await rpc('starknet_getClassHashAt', { block_id: 'latest', contract_address: account });
  } catch (e) {
    out.class_hash_error = errText(e);
  }
  if (!out.class_hash) return out; // not deployed (or no node): nothing to call
  for (const key of ['derivation', 'spend']) {
    for (let round = 1; round <= 2; round++) {
      const s = sigs[key][round - 1];
      if (!s) continue;
      const row = { message: key, round, checks: {} };
      for (const v of HASH_VARIANTS) {
        const h = messages[key].hashVariants[v.id];
        row.checks[v.id] = { hash: h, ...(await isValidSignature(sn, rpc, account, h, s.signature)) };
        if (row.checks[v.id].valid || row.checks[v.id].missing) break;
      }
      row.matched_variant = HASH_VARIANTS.map((v) => v.id).find((id) => row.checks[id]?.valid) ?? null;
      out.signatures.push(row);
    }
  }
  return out;
}

// --------------------------------------------------------------------------------------------
// The exported JSON.
// --------------------------------------------------------------------------------------------
export function buildReport({ conn, messages, sigs, kat, checks, rpcLabel, libsVerified, now }) {
  const msg = (key) =>
    messages && {
      primary_type: messages[key].typedData.primaryType,
      typed_data: messages[key].typedData,
      message_hash: messages[key].messageHash,
      hash_variants: messages[key].hashVariants,
      ...(messages[key].inputs ? { inputs: messages[key].inputs } : {}),
      signatures: sigs[key].map((s) => (s ? s.signature : null)),
      signatures_raw: sigs[key].map((s) => (s ? s.raw : null)),
      identical: pairStatus(sigs[key]),
    };
  return {
    page: PAGE_ID,
    generated_at: (now || new Date()).toISOString(),
    libraries: {
      starknet: LIBS.starknet.version,
      get_starknet: LIBS.getStarknet.version,
      sri_verified: libsVerified ?? null,
    },
    wallet: conn ? conn.wallet : null,
    account: conn ? conn.account : null,
    account_as_returned: conn ? conn.accountRaw : null,
    chain_id: conn ? { hex: conn.chain.hex, text: conn.chain.text, domain_value: conn.chain.domainValue } : null,
    class_hash: checks ? checks.class_hash : null,
    class_hash_source: checks
      ? checks.class_hash
        ? `starknet_getClassHashAt(latest) via ${rpcLabel}`
        : `unavailable: ${checks.class_hash_error}`
      : 'read-only checks not run',
    derivation_purpose: messages ? messages.derivation.typedData.message.purpose : SPIKE_DERIVATION_PURPOSE,
    kat_self_check_ok: kat ? kat.ok : null,
    messages: messages ? { derivation: msg('derivation'), spend: msg('spend') } : null,
    read_only_checks: checks ?? null,
  };
}

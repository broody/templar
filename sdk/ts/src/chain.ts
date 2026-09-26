// Chain reads (spec §6, §8): pin verification against the chain, and the pool's events fetched in
// bulk by address and selector only, never by note.
import { hash, type RpcProvider } from 'starknet';

import { fail } from './errors.js';
import { canon, sameFelt, versionOf, type NetworkConstants, type PoolConstants } from './network.js';
import type { Digest, Hex } from './core.js';

export const SELECTORS = {
  NotePublished: hash.getSelectorFromName('NotePublished'),
  NullifierSpent: hash.getSelectorFromName('NullifierSpent'),
  AssetRegistered: hash.getSelectorFromName('AssetRegistered'),
  PolicySettled: hash.getSelectorFromName('PolicySettled'),
  Deposited: hash.getSelectorFromName('Deposited'),
} as const;

const shortString = (s: string): bigint => BigInt('0x' + [...new TextEncoder().encode(s)].map((b) => b.toString(16).padStart(2, '0')).join(''));

/** RPC 0.10.1 or later (proof fields). */
export async function checkSpecVersion(provider: RpcProvider): Promise<void> {
  const v = await provider.channel.getSpecVersion();
  const [maj, min, patch] = v.split('.').map((x) => Number.parseInt(x, 10));
  const ok = maj! > 0 || min! > 10 || (min === 10 && (patch ?? 0) >= 1);
  if (!ok) fail('rpc_version', `the RPC node speaks ${v}; 0.10.1 or later is required`);
}

/** Checks the chain against the pinned constants before first use (spec §8). */
export async function verifyPins(provider: RpcProvider, n: NetworkConstants, p: PoolConstants): Promise<void> {
  const chain = await provider.getChainId();
  if (!sameFelt(chain, n.chainId)) fail('wrong_chain', `the RPC node is on ${chain}`);
  await checkVerifier(provider, p);
  if (versionOf(p) === 'v5') {
    // Pool V3's expiry and root rules are constructor constants (docs/account-bound-note-spec.md §8).
    const want = p.parameters ?? fail('pin_mismatch', 'a pool V3 needs its pinned parameters');
    const got = (await provider.callContract({ contractAddress: p.pool, entrypoint: 'get_parameters', calldata: [] })).map((x) => Number(BigInt(x)));
    if (got[0] !== want.expiryWindow || got[1] !== want.quantum || got[2] !== want.rootWindow || got[3] !== want.timelock) fail('pin_mismatch', 'pool parameters');
    // Mainnet floors (§8.4): owner changes wait at least 7 days, and a replaced root outlives any
    // spend that could use it.
    if (sameFelt(n.chainId, MAINNET) && (want.timelock < 7 * 86_400 || want.rootWindow < want.expiryWindow + want.quantum)) {
      fail('pin_mismatch', 'pool parameters below the mainnet floors');
    }
  }
  if (!sameFelt(await provider.getClassHashAt(p.adapter), p.adapterClass)) fail('pin_mismatch', 'adapter class');
  if (!sameFelt(await provider.getClassHashAt(p.statement), p.statementClass)) fail('pin_mismatch', 'statement account class');
  const expect: [string, bigint][] = [
    ['pool', BigInt(p.pool)],
    ['statement', BigInt(p.statement)],
    ['statement_class', BigInt(p.statementClass)],
    ['os_program', BigInt(p.osProgram)],
    ['max_proof_age', BigInt(p.maxProofAge)],
    ['account_tag', shortString(p.accountTag)],
  ];
  for (const [name, want] of expect) {
    const got = await provider.getStorageAt(p.adapter, hash.starknetKeccak(name));
    const value = typeof got === 'string' ? got : (got as unknown as { value: string }).value;
    if (BigInt(value) !== want) fail('pin_mismatch', `adapter ${name}`);
  }
}

const MAINNET = canon(shortString('SN_MAIN'));

/** Pool V3's verifier kinds (docs/account-bound-note-spec.md §8.4). */
export const KIND_R0 = canon(shortString('R0'));
export const KIND_P1 = canon(shortString('P1'));

/** The pool's verifier must still be the pinned adapter (re-read before every simulation and deposit). */
export async function checkVerifier(provider: RpcProvider, p: PoolConstants): Promise<void> {
  // Pool V3 reads `get_verifier(kind)` (AB-PV7).
  const calldata = versionOf(p) === 'v5' ? [KIND_R0] : [];
  const [v] = await provider.callContract({ contractAddress: p.pool, entrypoint: 'get_verifier', calldata });
  if (!v || !sameFelt(v, p.adapter)) fail('verifier_changed', 'the pool no longer uses the pinned adapter');
}

/** A pending owner change on pool V3: a verifier kind or a shadow class hash, its value and eta. */
export interface Proposal {
  key: Hex;
  value: Hex;
  /** Unix seconds from which the owner may apply it. */
  eta: number;
  /** Unix seconds after which it can no longer apply (`eta + T`). */
  lapsesAt: number;
  /** Past `lapsesAt` at the latest block: shown, but it blocks nothing (AB-SP15). */
  lapsed: boolean;
  /** A verifier change (`R0` or `P1`) rather than a shadow class. */
  verifier: boolean;
}

/**
 * The pending proposals for both verifiers and the given shadow classes (spec §8.4, AB-PV2): the SDK
 * shows each, refuses deposits while a verifier change is pending, and stops the routes a pending
 * shadow-class change would break.
 */
export async function pendingProposals(provider: RpcProvider, p: PoolConstants, shadowClasses: Hex[] = []): Promise<Proposal[]> {
  if (versionOf(p) !== 'v5') return [];
  const timelock = p.parameters?.timelock ?? fail('pin_mismatch', 'a pool V3 needs its pinned parameters');
  // The pool keeps a lapsed proposal until it is replaced or cancelled: lapse is judged at the
  // latest block's timestamp, the clock the pool uses.
  const latest = await provider.getBlockLatestAccepted();
  const block = await provider.getBlockWithTxHashes(latest.block_number);
  const now = Number((block as { timestamp?: number }).timestamp ?? fail('bad_rpc', 'block timestamp'));
  const out: Proposal[] = [];
  for (const key of [KIND_R0, KIND_P1, ...shadowClasses.map(canon)]) {
    const [value, eta] = await provider.callContract({ contractAddress: p.pool, entrypoint: 'get_proposal', calldata: [key] });
    if (eta === undefined || BigInt(eta) === 0n) continue;
    const e = Number(BigInt(eta));
    out.push({ key, value: canon(value ?? 0), eta: e, lapsesAt: e + timelock, lapsed: now > e + timelock, verifier: key === KIND_R0 || key === KIND_P1 });
  }
  return out;
}

export type PoolEvent =
  | { kind: 'note'; block: number; index: number; commitment: Digest; digest: Hex; words: Hex[] }
  | { kind: 'nullifier'; block: number; nullifier: Digest }
  | { kind: 'asset'; block: number; asset: Hex; standard: number; contract: Hex; idLow: string; idHigh: string }
  | { kind: 'settled'; block: number; firstIndex: number; x: string }
  | { kind: 'deposited'; block: number; asset: Hex };

const digestOf = (xs: string[]): Digest => xs.map((x) => Number(BigInt(x)));

/** Parses one event, or `undefined` for a malformed one (which makes the sync incomplete). */
export function parseEvent(keys: string[], data: string[], block: number): PoolEvent | undefined {
  const d = data;
  const n = (i: number) => Number(BigInt(d[i]!));
  try {
    switch (BigInt(keys[0]!)) {
      case BigInt(SELECTORS.NotePublished): {
        if (n(1) !== 9 || n(12) !== 10 || d.length !== 23) return undefined;
        // Commitment words are M31 elements; anything else is malformed, never a throw (SDK-IP10).
        if (d.slice(2, 11).some((x) => BigInt(x) >= 2147483647n)) return undefined;
        return { kind: 'note', block, index: n(0), commitment: digestOf(d.slice(2, 11)), digest: canon(d[11]!), words: d.slice(13, 23).map(canon) };
      }
      case BigInt(SELECTORS.NullifierSpent):
        if (n(0) !== 9 || d.length !== 10 || d.slice(1, 10).some((x) => BigInt(x) >= 2147483647n)) return undefined;
        return { kind: 'nullifier', block, nullifier: digestOf(d.slice(1, 10)) };
      case BigInt(SELECTORS.AssetRegistered):
        if (d.length !== 5) return undefined;
        return { kind: 'asset', block, asset: canon(d[0]!), standard: n(1), contract: canon(d[2]!), idLow: BigInt(d[3]!).toString(), idHigh: BigInt(d[4]!).toString() };
      case BigInt(SELECTORS.PolicySettled):
        if (d.length !== 8) return undefined;
        return { kind: 'settled', block, firstIndex: n(6), x: BigInt(d[5]!).toString() };
      case BigInt(SELECTORS.Deposited):
        if (d.length !== 2) return undefined;
        return { kind: 'deposited', block, asset: canon(d[0]!) };
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Every pool event in `[from, to]`, by address and selector only (spec §6). Events from another
 * address or with another selector are dropped; a malformed pool event is reported.
 */
export async function fetchPoolEvents(
  provider: RpcProvider,
  pool: string,
  from: number,
  to: number | 'pre_confirmed',
): Promise<{ events: PoolEvent[]; malformed: number }> {
  const selectors = Object.values(SELECTORS);
  const events: PoolEvent[] = [];
  let malformed = 0;
  let token: string | undefined;
  do {
    const chunk = await provider.getEvents({
      address: pool,
      from_block: { block_number: from },
      to_block: to === 'pre_confirmed' ? 'pre_confirmed' : { block_number: to },
      keys: [selectors],
      chunk_size: 1000,
      ...(token ? { continuation_token: token } : {}),
    });
    for (const e of chunk.events) {
      if (!sameFelt(e.from_address, pool) || !e.keys.length || !selectors.some((s) => sameFelt(s, e.keys[0]!))) continue;
      const parsed = parseEvent(e.keys, e.data, e.block_number ?? -1);
      if (parsed) events.push(parsed);
      else malformed += 1;
    }
    token = chunk.continuation_token;
  } while (token);
  return { events, malformed };
}

export async function leafCountAndRoot(provider: RpcProvider, pool: string, block: number): Promise<{ count: number; root: Digest }> {
  const id = block;
  const [count] = await provider.callContract({ contractAddress: pool, entrypoint: 'get_leaf_count', calldata: [] }, id);
  const root = await provider.callContract({ contractAddress: pool, entrypoint: 'get_root', calldata: [] }, id);
  if (Number(BigInt(root[0]!)) !== 9) fail('bad_rpc', 'get_root');
  return { count: Number(BigInt(count!)), root: digestOf(root.slice(1, 10)) };
}

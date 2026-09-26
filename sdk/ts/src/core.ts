// The WebAssembly core (`templar-wasm`, spec §10.1), loaded once, with typed wrappers. Every
// protocol value is computed there; this layer only moves data (spec §1).
import init, * as wasm from '../wasm/templar.js';
import { TemplarError, coreError } from './errors.js';

export type Digest = number[];
export type Hex = string;

let loading: Promise<void> | undefined;

/**
 * A minimal module using one 128-bit SIMD instruction (`i8x16.splat`, `i8x16.popcnt`), the probe
 * `wasm-feature-detect` uses. The core is built with SIMD, so a runtime that rejects this cannot
 * load it.
 */
const SIMD_PROBE = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253, 15, 253, 98, 11,
]);

/** Refuses a runtime without WebAssembly or its 128-bit SIMD, with an actionable error. */
export function checkRuntime(wasmApi: { validate(b: BufferSource): boolean } | undefined = globalThis.WebAssembly): void {
  if (!wasmApi || typeof wasmApi.validate !== 'function') {
    throw new TemplarError('unsupported_browser', 'this browser does not support WebAssembly; please update it');
  }
  if (!wasmApi.validate(SIMD_PROBE)) {
    throw new TemplarError(
      'unsupported_browser',
      'this browser does not support WebAssembly SIMD (Chrome or Edge 91+, Firefox 89+, Safari 16.4+); please update it',
    );
  }
}

/** Loads the core. In Node the module is read from the package; in browsers it is fetched. */
export function loadCore(source?: BufferSource | URL | string): Promise<void> {
  loading ??= (async () => {
    checkRuntime();
    let s = source;
    if (s === undefined && typeof process !== 'undefined' && process.versions?.node) {
      const { readFile } = await import('node:fs/promises');
      s = await readFile(new URL('../wasm/templar_bg.wasm', import.meta.url));
    }
    await init(s === undefined ? undefined : { module_or_path: s as BufferSource });
  })();
  return loading;
}

/** Calls a core export, turning thrown JSON errors into `TemplarError`s. */
export function call<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    throw coreError(e);
  }
}

export const json = <T>(f: () => string): T => JSON.parse(call(f)) as T;

export interface AccountInfo {
  address: string;
  receiver: Digest;
  fingerprint: string;
}

export interface DecodedAddress {
  chain: Hex;
  pool: Hex;
  receiver: Digest;
  pk: string;
  fingerprint: string;
}

export type AssetKind =
  | 'Erc20'
  | 'Unknown'
  | { Erc721: { contract: Hex; id: [string, string] } }
  | { Erc1155: { contract: Hex; id: [string, string] } };

export interface OwnedNote {
  index: number;
  account: number;
  commitment: Digest;
  asset: Hex;
  kind: AssetKind;
  amount: string;
  rho: Digest;
  nullifier: Digest | null;
}

export interface NoteRef {
  index: number;
  account: number;
  asset: Hex;
  amount: string;
  rho: Digest;
  commitment: Digest;
}

export interface Companion {
  sk: Digest;
  rho: Digest;
  position: number;
  siblings: Digest[];
}

export type SpendRequest =
  | { kind: 'transfer'; asset: Hex; amount: string; to: string }
  | { kind: 'withdraw'; asset: Hex; amount: string; recipient: Hex }
  | { kind: 'consolidate'; asset: Hex };

export interface Plan {
  /** R0 V5 plans carry these; a V4 plan omits them. */
  version?: 'v4' | 'v5';
  valid_until?: number;
  bound_account?: Hex;
  chain: Hex;
  pool: Hex;
  asset: Hex;
  account: number;
  root: Digest;
  leaf_count: number;
  inputs: NoteRef[];
  paths: Digest[][];
  companion: Companion | null;
  companion_is_new: boolean;
  outputs: { receiver: Digest; rho: Digest; amount: string; ciphertext: Hex[]; delivery: Hex }[];
  withdrawal_recipient: Hex;
  withdrawal_amount: string;
}

export interface Statement {
  chain: Hex;
  pool: Hex;
  token_out: Hex;
  root: Digest;
  nullifiers: [Digest, Digest];
  commitments: [Digest, Digest];
  deliveries: [Hex, Hex];
  withdrawal_recipient: Hex;
  withdrawal_amount: number | string;
  intent: Hex;
  identity: Digest;
  /** R0 V5: the bound account (`0x0` for an ordinary spend) and the expiry. */
  account?: Hex;
  valid_until?: number | string;
}

/** The latest block and the pool's `E` and `Q`: a V5 plan's expiry inputs, read with its tree. */
export interface Expiry {
  latest_block: number;
  window: number;
  quantum: number;
}

/** A bound account's SNIP-12 spend message: the typed data to sign and the hash it signs. */
export interface SpendMessage {
  typed_data: object;
  hash: Hex;
}

export interface Proved {
  version?: 'v4' | 'v5';
  /** The statement exactly as the core serialized it (send this, never a re-serialization). */
  statement_json: string;
  proof: Hex[];
  statement: Statement;
  binding: Hex;
  calldata: Hex[];
  circuit_hash: number[];
  nullifiers: [Digest, Digest];
}

export interface Pins {
  chain: Hex;
  pool: Hex;
  statement: Hex;
  statement_class: Hex;
  account_tag: string;
  os_program: Hex;
  config_hash: Hex;
  max_proof_age: number;
}

export interface ServerResult {
  proof: string;
  proof_facts: Hex[];
  base_block: number;
  binding: Hex;
  /** R0 V5: the last block the result may land in, and the pool call the relayer settles. */
  send_deadline?: number;
  pool_call?: { entry_point: string; calldata: Hex[] };
}

export interface Window {
  submit_after: number;
  valid_until: number;
}

export { wasm };

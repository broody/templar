// The WebAssembly core (`templar-wasm`, spec §10.1), loaded once, with typed wrappers. Every
// protocol value is computed there; this layer only moves data (spec §1).
import init, * as wasm from '../wasm/templar.js';
import { coreError } from './errors.js';

export type Digest = number[];
export type Hex = string;

let loading: Promise<void> | undefined;

/** Loads the core. In Node the module is read from the package; in browsers it is fetched. */
export function loadCore(source?: BufferSource | URL | string): Promise<void> {
  loading ??= (async () => {
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
}

export interface Proved {
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
}

export interface Window {
  submit_after: number;
  valid_until: number;
}

export { wasm };

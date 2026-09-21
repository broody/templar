/* tslint:disable */
/* eslint-disable */

export class MembershipResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly proof_bytes: Uint8Array;
    readonly shape_json: string;
    readonly summary_json: string;
}

export function prove_membership(fixture_json: string): MembershipResult;

export function test_membership_mutations(proof_bytes: Uint8Array): string;

export function verify_membership(proof_bytes: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_membershipresult_free: (a: number, b: number) => void;
    readonly membershipresult_proof_bytes: (a: number) => [number, number];
    readonly membershipresult_shape_json: (a: number) => [number, number];
    readonly membershipresult_summary_json: (a: number) => [number, number];
    readonly prove_membership: (a: number, b: number) => [number, number, number];
    readonly test_membership_mutations: (a: number, b: number) => [number, number, number, number];
    readonly verify_membership: (a: number, b: number) => [number, number, number];
    readonly LIBBZ2_RS_SYS_v0.1.x_BZ2_bzBuffToBuffCompress: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
    readonly LIBBZ2_RS_SYS_v0.1.x_BZ2_bzBuffToBuffDecompress: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly LIBBZ2_RS_SYS_v0.1.x_BZ2_bzCompress: (a: number, b: number) => number;
    readonly LIBBZ2_RS_SYS_v0.1.x_BZ2_bzCompressEnd: (a: number) => number;
    readonly LIBBZ2_RS_SYS_v0.1.x_BZ2_bzCompressInit: (a: number, b: number, c: number, d: number) => number;
    readonly LIBBZ2_RS_SYS_v0.1.x_BZ2_bzDecompress: (a: number) => number;
    readonly LIBBZ2_RS_SYS_v0.1.x_BZ2_bzDecompressEnd: (a: number) => number;
    readonly LIBBZ2_RS_SYS_v0.1.x_BZ2_bzDecompressInit: (a: number, b: number, c: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

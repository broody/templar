// P0b spike: class hash, compiled class hashes (Poseidon v1 and Blake v2) and sizes of a Scarb
// build. Read-only, local. Usage: node class_info.mjs SIERRA.json CASM.json
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
const require = createRequire(import.meta.url);
const { hash } = require('/home/broody/development/templar/sdk/ts/node_modules/starknet');

const [sierraPath, casmPath] = process.argv.slice(2);
const sierra = JSON.parse(readFileSync(sierraPath, 'utf8'));
const casm = JSON.parse(readFileSync(casmPath, 'utf8'));
const sierraVersion = sierra.sierra_program.slice(0, 3).map((x) => BigInt(x).toString()).join('.');
const compilerVersion = sierra.sierra_program.slice(3, 6).map((x) => BigInt(x).toString()).join('.');
const out = {
  class_hash: hash.computeSierraContractClassHash(sierra),
  compiled_class_hash_v1_poseidon: hash.computeCompiledClassHashPoseidon(casm),
  compiled_class_hash_v2_blake: hash.computeCompiledClassHashBlake(casm),
  sierra_version: sierraVersion,
  compiler_version: compilerVersion,
  sierra_program_felts: sierra.sierra_program.length,
  casm_bytecode_felts: casm.bytecode.length,
  // Declaration cost rule measured on Sepolia (bench/m31-sepolia/README.md): 40,960 L2 gas per
  // class felt (Sierra + CASM).
  declare_l2_gas_rule: 40960 * (sierra.sierra_program.length + casm.bytecode.length),
  sierra_file_bytes: readFileSync(sierraPath).length,
  casm_file_bytes: readFileSync(casmPath).length,
  entry_points: {
    external: sierra.entry_points_by_type.EXTERNAL.map((e) => e.selector),
    constructor: sierra.entry_points_by_type.CONSTRUCTOR.length,
  },
};
console.log(JSON.stringify(out, null, 2));

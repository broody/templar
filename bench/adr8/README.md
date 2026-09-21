# ADR-0008 benchmark — felt252-Poseidon in a BN254 SNARK

Measures the cost of ONE canonical Starknet Poseidon permutation
(`hades_permutation([a,b,2])[0]`) expressed in non-native arithmetic over
BN254 — the dominant cost of the M2 inner statement (tree paths + note
derivations).

- `ref_poseidon.py` — pure-Python Starknet Poseidon (x^3 S-box, r_f=8,
  r_p=83, small MDS, sha256-derived round constants). Validated against the
  Cairo VM: reproduces corelib's `poseidon_hash_span([1,2])` docstring vector
  `0x0371cb…0e7` exactly.
- `main.go` — the same permutation as a gnark circuit (emulated felt252 over
  BN254); proves knowledge of (a,b) for public H(a,b); benchmarks Groth16 and
  PLONK.

Run:

```bash
python3 ref_poseidon.py          # writes tv.json (validated against Cairo VM)
go run . -limbs 3 -bits 84 -proof groth16
go run . -limbs 3 -bits 84 -proof plonk
go run . -limbs 4 -bits 64 -proof groth16   # limb-config sensitivity
```

Requires Go ≥1.22 and `github.com/consensys/gnark` (see go.mod-style imports;
`go mod init bench && go get github.com/consensys/gnark@v0.16.3 && go mod tidy`).

Results (2026-09-19, gnark v0.16.3, single permutation):

| Config | System | Constraints | Setup | Prove | Verify | Proof |
|---|---|---|---|---|---|---|
| 3×84 limbs | Groth16 | 47,501 | 3.6 s (per-circuit) | 154 ms | 1 ms | 196 B |
| 4×64 limbs | Groth16 | 49,703 | 3.5 s | 162 ms | 1 ms | 196 B |
| 3×84 limbs | PLONK | 197,173 (SCS gates) | 0.4 s (universal SRS) | 1.61 s | 2 ms | 584 B |

Note: 2×126 limbs overflows the BN254 scalar field in the carry constraints
(gnark rejects it) — ~2×126 is the theoretical minimum but is out of reach for
gnark's general emulated reduction; audited custom limb-folding (xJsnark/circom
style) targets ~15–30 constraints per 252-bit mul, i.e. ~6–8 K per permutation
(the spec §1 estimate), vs ~222/mul for gnark's general `emulated` package.

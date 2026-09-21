# Vendored: noir-bignum

Vendored snapshot of [noir-lang/noir-bignum](https://github.com/noir-lang/noir-bignum)
at upstream commit `6e24b919bd3069694243dec7424bf3663bd7c2aa` (v0.9.2), used by
the [ADR-0016](../../docs/adr/0016-noir-honk-feasibility.md) microbenchmark to benchmark felt252-Poseidon
arithmetic through Noir/Honk.

Local vendoring change: the `benchmarks` and `tests` modules in `src/lib.nr`
are disabled so the tree compiles standalone. Upstream license is preserved in
`LICENSE`.

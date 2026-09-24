# M31 payment statement — client-cost measurement (step 1)

Recorded 2026-09-22. First measurement of the payment-shaped M31 statement
from [../inventory.md](../inventory.md) §2: two notes, depth-32 membership
paths (sibling-pair construction: the two leaves are each other's level-0
siblings, indices differ only in bit 0, merged spine), leaf preimages and
nullifier derivations — all as sponge requests over the reviewed
Plonky3 width-24 Poseidon2 AIR (vendored byte-identical from
`bench/m31-append/client/src`; m31.rs sha256
`645c5200692f1fbe387ff118efb0b319d23d273e6c2fedccef487ea0ea5bdd13`).

Scope: measurement pathfinding only. No privacy claim, no format
commitment; synthetic secrets are carried in the clear at this stage (the
hiding stage replaces this), and the felt252 binding residual is not yet
included (inventory §2 component 2 — next step).

## Result

| Metric | Value |
| --- | --- |
| Workload | 132 sponge requests (2 leaf + 2 nullifier + 2×32 node hashes; node frames span 2 sponge blocks each) → 256 rows, log 8 |
| Trace columns | 1,172 + 4 interaction (unchanged AIR) |
| Peak RSS | **~11 MiB** (10,992–11,260 KB across three runs) |
| Complete wall time | **0.109–0.124 s** (stark prove 0.064 s of it) |
| Proof size (bincode envelope) | 170,462 B (second fixture: 170,638 B) |
| Reproducibility | 3 runs byte-identical |
| Second fixture (different seed) | proves and verifies |
| Negative battery | **16 mutations rejected** + padding-omission control accepted-check |

Config: pinned `pow_bits 27, FriConfig(0, 3, 23, 4)`, interaction PoW 24,
lifting log 11, bounded-memory mode (16-column FRI batches) — the same
shape as the append experiment.

## Interpretation

1. The payment-shaped M31 statement lands at **~11 MiB / ~0.1 s** — the
   inventory's "~50–150 MiB public client" estimate was conservative; the
   M31-native statement is two orders of magnitude below the felt
   statement's 1.97 GiB.
2. The unmeasured residuals are now the only cost carriers: the felt252
   binding residual (inventory estimate 30–60 MiB LDE, next step) and the
   hiding pads (~77 MiB at full coverage, inventory §3). Even with both,
   the client plausibly stays ≤ ~0.2 GiB — browser-class.
3. Node-hash sponge framing: the 18-word node payload (two 9-word digests)
   spans 2 sponge blocks per hash. A tighter frame (e.g., 8-word truncated
   sibling encoding) would halve node-hash cost — noted as a v2 design
   option, not exercised here.

## Environment and reproduction

Toolchain `nightly-2026-01-15`, `RUSTFLAGS="-Ctarget-cpu=native"`, release;
build PATH sanitized as recorded in
[../client/README.md](../client/README.md) (the `~/bin/cc` shim issue).
Path deps to the frozen `target/m31-append` copies of stwo (`489a0f3`) and
stwo-cairo (`9b6be27`).

```bash
cd bench/m31-statement/client
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" CARGO_BUILD_JOBS=16 \
  RUSTFLAGS="-Ctarget-cpu=native" cargo +nightly-2026-01-15 build --release
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" ./target/release/templar-m31-statement \
  --make-fixtures 0x434841494e 0x456 1 /tmp/fixtures
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" /usr/bin/time -v \
  ./target/release/templar-m31-statement /tmp/fixtures/payment-2x32.json /tmp/run1
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" ./target/release/templar-m31-statement \
  --verify-tests /tmp/run1/proof.bin /tmp/tests
```

Artifacts copied into `results/`: [summary.json](summary.json),
[negative-tests.json](negative-tests.json). Machine: i9-10980XE, 125 GB;
single-run class (three prove repetitions, byte-identical).

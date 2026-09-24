`direct-air/` holds the manifests and lockfiles that produced `results/log25-baseline/`,
`results/circuit-a/`, `results/proof2/` and `results/spike-upstream-client/`. Those builds
used the pre-monorepo `stwo-circuits@5ef951a`, the local `target/direct-air/stwo` copy
(with Templar's bounded-memory prover patch), and the Cairo vendor from `stwo-cairo@16700cc9`.
The crate now builds against `starkware-libs/proving@5a7c5ed` (`target/proving-main`).

`direct-air/examples/spike_prove.rs` produced the spike measurements. It needs the old pins
(Templar's bounded-memory prover patch is not upstream) and is kept here, not built.

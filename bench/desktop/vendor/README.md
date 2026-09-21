# Pinned parameter sources

The two headers come from AztecProtocol/aztec-packages tag
`v3.0.0-nightly.20251104`, matching the bb binary used here:

- https://github.com/AztecProtocol/aztec-packages/blob/v3.0.0-nightly.20251104/barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2_params.hpp
- https://github.com/AztecProtocol/aztec-packages/blob/v3.0.0-nightly.20251104/barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2_permutation.hpp

They retain upstream attribution. Constants were not selected or modified for
Templar. `native_reference.py` extracts the pinned parameters and
`generate_cairo.py` uses Garaga 1.1.0 to generate an equivalent arithmetic circuit.
The benchmark implements the same initial external layer, round order, S-box,
and internal/external matrices. This is not a claim that the generated Cairo
implementation has inherited an upstream audit.

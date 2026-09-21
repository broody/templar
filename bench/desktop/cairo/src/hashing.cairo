//! Experimental BN254 Poseidon2 sponge, rate 3, length * 2^64 capacity.
//! Root/nullifier/commitment values remain u256; never truncate to felt252.
use garaga::core::circuit::{into_u256_unchecked, u256_to_u384};
use desktop::permutation::run_desktop_poseidon2_circuit;
pub const FR: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
fn add(a: u256, b: u256) -> u256 {
    let sum = a + b;
    if sum >= FR { sum - FR } else { sum }
}
pub fn hash(values: Span<u256>) -> u256 {
    let mut s0: u256 = 0;
    let mut s1: u256 = 0;
    let mut s2: u256 = 0;
    let mut s3: u256 = values.len().into() * 0x10000000000000000;
    let mut i = 0;
    loop {
        if i < values.len() { let v = *values.at(i); assert(v < FR, 'NONCANONICAL'); s0 = add(s0, v); i += 1; }
        if i < values.len() { let v = *values.at(i); assert(v < FR, 'NONCANONICAL'); s1 = add(s1, v); i += 1; }
        if i < values.len() { let v = *values.at(i); assert(v < FR, 'NONCANONICAL'); s2 = add(s2, v); i += 1; }
        let (a,b,c,d) = run_desktop_poseidon2_circuit(u256_to_u384(s0),u256_to_u384(s1),u256_to_u384(s2),u256_to_u384(s3));
        // Sound here because the circuit modulus FR is strictly below 2^256.
        s0 = into_u256_unchecked(a); s1 = into_u256_unchecked(b);
        s2 = into_u256_unchecked(c); s3 = into_u256_unchecked(d);
        if i == values.len() { break; }
    };
    s0
}
pub fn pair(a: u256, b: u256) -> u256 { hash(array![a,b].span()) }

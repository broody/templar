//! Independent permutation/sponge oracle: actual pinned Plonky3, no S-two implementation.
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_mersenne_31::{Mersenne31 as F, default_mersenne31_poseidon2_24};
use p3_symmetric::{CryptographicHasher, Increment, Pad10Sponge, Permutation};
use serde_json::json;
use std::collections::BTreeMap;

type Digest = [u32; 9];
fn hash(message: &[u32]) -> Digest {
    let sponge = Pad10Sponge::<F, _, _, 24, 15, 9>::new(
        default_mersenne31_poseidon2_24(),
        Increment::new(F::ONE),
    );
    sponge
        .hash_iter(message.iter().copied().map(F::new))
        .map(|v| v.as_canonical_u32())
}
fn framed(kind: u32, level: u32, payload: &[u32]) -> Digest {
    let mut words = vec![0x544d5031, 1, kind, level];
    words.extend(payload);
    hash(&words)
}
fn leaf(v: &BigUint) -> Digest {
    let mask = (BigUint::one() << 28_u32) - BigUint::one();
    let limbs = std::array::from_fn::<_, 9, _>(|i| ((v >> (28 * i)) & &mask).to_u32().unwrap());
    framed(1, 0, &limbs)
}
fn node(level: u32, left: Digest, right: Digest) -> Digest {
    framed(2, level, &[left.as_slice(), right.as_slice()].concat())
}
fn packed(d: Digest) -> [String; 2] {
    let low: BigUint = d[..8]
        .iter()
        .enumerate()
        .map(|(i, &v)| BigUint::from(v) << (31 * i))
        .sum();
    [format!("0x{low:x}"), format!("0x{:x}", d[8])]
}
fn main() {
    let mut inputs = vec![[0; 24], std::array::from_fn(|i| i as u32), [0x7ffffffe; 24]];
    inputs.push(std::array::from_fn(|i| {
        ((i as u64 * 982451653 + 32452843) % 2147483647) as u32
    }));
    let permutations: Vec<_> = inputs
        .into_iter()
        .map(|input| {
            let mut output = input.map(F::new);
            default_mersenne31_poseidon2_24().permute_mut(&mut output);
            json!({"input":input,"output":output.map(|v|v.as_canonical_u32())})
        })
        .collect();
    let sponges: Vec<_> = [0, 1, 13, 14, 15, 16, 22, 29, 30, 31]
        .into_iter()
        .map(|n| {
            let message: Vec<_> = (0..n).map(|i| (i * 107 + 3) as u32).collect();
            json!({"input":message,"digest":hash(&message)})
        })
        .collect();
    let prime = BigUint::parse_bytes(
        b"800000000000011000000000000000000000000000000000000000000000001",
        16,
    )
    .unwrap();
    let mut values: Vec<BigUint> = (0_u32..=32).map(BigUint::from).collect();
    values.extend([
        &prime - BigUint::one(),
        BigUint::one() << 248,
        (BigUint::one() << 28) - BigUint::one(),
        BigUint::one() << 28,
    ]);
    let leaves: Vec<_> = values
        .iter()
        .map(|v| {
            let d = leaf(v);
            json!({"felt":format!("0x{v:x}"),"digest":d,"packed":packed(d)})
        })
        .collect();
    let mut empty = vec![framed(3, 0, &[])];
    for level in 1..=32 {
        empty.push(node(
            level,
            empty[level as usize - 1],
            empty[level as usize - 1],
        ));
    }
    let a: Digest = std::array::from_fn(|i| i as u32);
    let b: Digest = std::array::from_fn(|i| 0x7ffffffe - i as u32);
    let nodes: Vec<_> = [
        (1, a, b),
        (1, b, a),
        (32, a, b),
        (17, [0; 9], [0x7ffffffe; 9]),
    ]
    .into_iter()
    .map(|(level, left, right)| {
        let d = node(level, left, right);
        json!({"level":level,"left":left,"right":right,"digest":d,"packed":packed(d)})
    })
    .collect();
    let mut stored = BTreeMap::<(u32, u32), Digest>::new();
    let mut roots = Vec::new();
    for i in 0..32_u32 {
        let mut cur = leaf(&BigUint::from(i + 1));
        let mut index = i;
        stored.insert((0, index), cur);
        for level in 0..32 {
            let sibling = *stored
                .get(&(level, index ^ 1))
                .unwrap_or(&empty[level as usize]);
            cur = if index & 1 == 0 {
                node(level + 1, cur, sibling)
            } else {
                node(level + 1, sibling, cur)
            };
            index >>= 1;
            stored.insert((level + 1, index), cur);
        }
        roots.push(json!({"count":i+1,"root":cur,"packed":packed(cur)}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "plonky3_pin":"00fe0a985b398d3ef1f10d69543ca2b8f9f236da",
            "permutation":"default_mersenne31_poseidon2_24",
            "sponge":"Pad10Sponge<24,15,9>; Increment(1)",
            "domain_tag":0x544d5031u32,"version":1,
            "permutations":permutations,"sponges":sponges,"leaves":leaves,
            "empty":empty,"nodes":nodes,"append_roots":roots
        }))
        .unwrap()
    );
}

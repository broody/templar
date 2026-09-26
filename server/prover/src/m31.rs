//! Poseidon2 over M31 (width 24, 8 full + 22 partial rounds, x^5; the pinned Plonky3 Grain
//! constants) and the client's framed hash and note commitment (`client-port/src/payment.rs`,
//! `bench/m31-pool/cairo/src/hash.cairo`), for the free full-withdrawal check: the server
//! recomputes each output's commitment from its opening (docs/account-bound-note-spec.md §7.2).
//! Checked against the pool's vectors (`bench/m31-pool/vectors.json`).
use starknet_types_core::felt::Felt;

pub const P: u64 = (1 << 31) - 1;
const WIDTH: usize = 24;
/// Frame tag `TMR0`.
const TAG: u64 = 0x544d5230;
const NOTE: u64 = 5;

pub type Digest = [u32; 9];

const EXTERNAL_INITIAL: [[u32; 24]; 4] = [
    [
        0x1feaba61, 0x53224454, 0x6bceb9e2, 0x5019f9b4, 0x48726592, 0x2b22d0a8, 0x6151bbf9,
        0x2f474b21, 0x2eb5f337, 0x3b645d87, 0x0942cef0, 0x65228c52, 0x78ffb30f, 0x4d2837c8,
        0x0e17ac4f, 0x05546686, 0x046c06cc, 0x0b51c3b6, 0x568db763, 0x38b334e4, 0x57f5acf0,
        0x19d32611, 0x77d02f4b, 0x6c82e9b8,
    ],
    [
        0x7148c1b6, 0x08067c75, 0x46d1e8c9, 0x30973b07, 0x20614f3b, 0x5c3ff851, 0x30503329,
        0x4972e7cc, 0x02d1d8bc, 0x09d5bfa6, 0x097104c0, 0x7ba49a34, 0x4a07c2fc, 0x24c1ee69,
        0x28a6ab41, 0x5d9108a0, 0x3a7851c7, 0x1dd495f9, 0x12b49ff4, 0x7bad5760, 0x5fed64c2,
        0x66f5c96c, 0x7eafbd02, 0x39b3593b,
    ],
    [
        0x4a653b49, 0x75091dc1, 0x56e488e0, 0x1704a355, 0x745e4ff3, 0x392ef16e, 0x31e33fdf,
        0x02c28c66, 0x36c3083a, 0x3104d1fa, 0x5b03cda3, 0x6641e1af, 0x37754b56, 0x396f5af9,
        0x1a1a461a, 0x688e26f2, 0x6f829784, 0x1bb91d69, 0x5b788016, 0x704aa5c5, 0x0181869c,
        0x41211e56, 0x0ce803a0, 0x23bff3a0,
    ],
    [
        0x17fb7064, 0x47317220, 0x76914b53, 0x219c1905, 0x16655528, 0x4df35544, 0x60808465,
        0x3350f833, 0x03bccdc7, 0x0a87180a, 0x017a99f5, 0x6e945726, 0x15445504, 0x780533b1,
        0x3b91bf38, 0x3fc77eb1, 0x4b4d960e, 0x3cd93d2e, 0x0ea4e976, 0x1d5306cc, 0x3a7ac284,
        0x0ec22934, 0x4d979713, 0x51a41c65,
    ],
];
const EXTERNAL_FINAL: [[u32; 24]; 4] = [
    [
        0x1c662299, 0x057c955a, 0x7ab6c0f2, 0x25a6ad0a, 0x75850b58, 0x48fd3793, 0x0b4366b1,
        0x0fdd0d49, 0x7db419f9, 0x49b9cc0f, 0x48949716, 0x29c35890, 0x76445485, 0x1c27d30c,
        0x10aa7a3b, 0x30f34fb6, 0x6fe06435, 0x02135ecd, 0x6caaba96, 0x3eb290d0, 0x22fd8d3b,
        0x768b1525, 0x5be95814, 0x523d7fe9,
    ],
    [
        0x55e94cec, 0x47c42e1f, 0x1aa53b5e, 0x2fd1fe7e, 0x59230e91, 0x7472da66, 0x6443f2df,
        0x2d9de19d, 0x6f7f6a84, 0x77800430, 0x0f014bc8, 0x7bf3d095, 0x26afd318, 0x582561f7,
        0x5ee3198c, 0x6acc0000, 0x2f315e26, 0x27cac040, 0x2595081e, 0x5963b7da, 0x7e073565,
        0x6cf3f5f1, 0x09f8a3a4, 0x0da8ccfe,
    ],
    [
        0x60be2365, 0x7ed742f5, 0x668b8031, 0x4bb03494, 0x59019333, 0x700e2878, 0x1cc45856,
        0x1d1617f7, 0x7b988da6, 0x4eb4936c, 0x78c9f87e, 0x63ce3e94, 0x7178341b, 0x45bc2f86,
        0x05b775bc, 0x704b0244, 0x29eed278, 0x47f43032, 0x2127b2e5, 0x1997903f, 0x24b3ce03,
        0x0c32298c, 0x7d2b6f3a, 0x17fcaa81,
    ],
    [
        0x72f37fef, 0x3028e7a9, 0x5edd4d96, 0x1f96583b, 0x4cd6918a, 0x14880f0e, 0x69170359,
        0x173cbd33, 0x0969e7f4, 0x6e7f23ab, 0x6182ea87, 0x4dcb1f5c, 0x585fa113, 0x729cb3b6,
        0x01b3a27a, 0x1ba173e7, 0x4b33bcea, 0x63d93bbb, 0x6b3fbf99, 0x6f17e9d1, 0x0c3dd8ba,
        0x0bc1f9a8, 0x64d3f370, 0x465a6a18,
    ],
];
const INTERNAL: [u32; 22] = [
    0x22776a11, 0x5fa34268, 0x1415528d, 0x563fbd14, 0x34f45244, 0x120ea1b6, 0x261368a5, 0x27665ec1,
    0x36be2805, 0x345c4784, 0x17efdcc1, 0x393e6530, 0x6da0b4b8, 0x31e5ded3, 0x675b27ac, 0x0ae88c30,
    0x577841cc, 0x5fe06dec, 0x56b0691a, 0x7242de1f, 0x3c377529, 0x339b7523,
];

fn add(a: u64, b: u64) -> u64 {
    (a + b) % P
}
fn mul(a: u64, b: u64) -> u64 {
    a * b % P
}
fn sbox(x: u64) -> u64 {
    let x2 = mul(x, x);
    mul(mul(x2, x2), x)
}

fn external(s: &mut [u64; WIDTH]) {
    const M: [[u64; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    for off in (0..WIDTH).step_by(4) {
        let x: [u64; 4] = std::array::from_fn(|i| s[off + i]);
        for i in 0..4 {
            s[off + i] = (0..4).fold(0, |acc, j| add(acc, mul(x[j], M[i][j])));
        }
    }
    let sums: [u64; 4] = std::array::from_fn(|k| (0..WIDTH).step_by(4).fold(0, |acc, i| add(acc, s[i + k])));
    for i in 0..WIDTH {
        s[i] = add(s[i], sums[i % 4]);
    }
}

fn internal(s: &mut [u64; WIDTH]) {
    let total = s.iter().fold(0, |acc, v| add(acc, *v));
    for i in 0..WIDTH {
        let diag = if i == 0 { P - 2 } else { 1u64 << (i - 1) };
        s[i] = add(total, mul(s[i], diag));
    }
}

pub fn permutation(input: [u64; WIDTH]) -> [u64; WIDTH] {
    let mut s = input.map(|v| v % P);
    external(&mut s);
    for c in &EXTERNAL_INITIAL {
        for i in 0..WIDTH {
            s[i] = sbox(add(s[i], c[i] as u64));
        }
        external(&mut s);
    }
    for c in INTERNAL {
        s[0] = sbox(add(s[0], c as u64));
        internal(&mut s);
    }
    for c in &EXTERNAL_FINAL {
        for i in 0..WIDTH {
            s[i] = sbox(add(s[i], c[i] as u64));
        }
        external(&mut s);
    }
    s
}

/// The framed rate-15 sponge (`membership::sponge`): overwrite the first `n ≤ 15` rate words; a
/// short last block is padded with a 1 then zeros; a full last block adds 1 to word 15.
pub fn sponge(message: &[u64]) -> Digest {
    let mut state = [0u64; WIDTH];
    let mut offset = 0;
    loop {
        let n = (message.len() - offset).min(15);
        state[..n].copy_from_slice(&message[offset..offset + n]);
        offset += n;
        let done = offset == message.len();
        if n < 15 {
            state[n] = 1;
            state[n + 1..15].fill(0);
        } else if done {
            state[15] = add(state[15], 1);
        }
        state = permutation(state);
        if done {
            return std::array::from_fn(|i| state[i] as u32);
        }
    }
}

/// `H(kind, level, payload) = sponge([TAG, 1, kind, level] ‖ payload)`.
pub fn h(kind: u64, level: u64, payload: &[u64]) -> Digest {
    sponge(&[vec![TAG, 1, kind, level], payload.to_vec()].concat())
}

/// A felt below 2^252 as nine 28-bit little-endian limbs.
fn felt_limbs(f: &Felt) -> [u64; 9] {
    let b = f.to_bytes_be();
    let bit = |k: usize| -> u64 { ((b[31 - k / 8] >> (k % 8)) & 1) as u64 };
    std::array::from_fn(|l| (0..28).map(|i| bit(l * 28 + i) << i).sum())
}

/// `cm = H(NOTE, chain ‖ pool ‖ token ‖ amount₈ ‖ inner)` (the amount as eight 16-bit limbs).
pub fn commitment(chain: &Felt, pool: &Felt, token: &Felt, amount: u128, inner: &Digest) -> Digest {
    let mut payload = vec![];
    for f in [chain, pool, token] {
        payload.extend(felt_limbs(f));
    }
    payload.extend((0..8).map(|k| ((amount >> (16 * k)) & 0xffff) as u64));
    payload.extend(inner.iter().map(|w| *w as u64));
    h(NOTE, 0, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../../bench/m31-pool/vectors.json");

    fn arr<const N: usize>(v: &Value) -> [u64; N] {
        std::array::from_fn(|i| v[i].as_u64().unwrap())
    }

    #[test]
    fn permutation_and_commitment_match_the_vectors() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let p = &v["permutation"];
        assert_eq!(permutation(arr::<24>(&p["input"])), arr::<24>(&p["output"]));
        let d = &v["deposit"];
        let f = |k: &str| crate::rpc::felt(d[k].as_str().unwrap()).unwrap();
        let inner: Digest = arr::<9>(&d["inner"]).map(|w| w as u32);
        let cm = commitment(&f("chain"), &f("pool"), &f("token"), d["amount"].as_str().unwrap().parse().unwrap(), &inner);
        assert_eq!(cm, arr::<9>(&d["commitment"]).map(|w| w as u32));
    }
}

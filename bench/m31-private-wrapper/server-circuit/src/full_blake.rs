//! Full Blake2s-256 via existing circuit gates. Public workload only; no private witness.
use circuits::blake::{blake_g_gate, triple_xor, BLAKE2S_IV};
use circuits::context::{Context, Var};
use circuits::ivalue::IValue;
use circuits::ops::{eq, guess};
use circuits::eval;
use stwo::core::fields::qm31::QM31;
pub const BLAKE_SIGMA: [[u32; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const G_STATE_INDICES: [(usize, usize, usize, usize); 8] = [
    (0, 4, 8, 12),
    (1, 5, 9, 13),
    (2, 6, 10, 14),
    (3, 7, 11, 15),
    (0, 5, 10, 15),
    (1, 6, 11, 12),
    (2, 7, 8, 13),
    (3, 4, 9, 14),
];

pub fn full_blake<Value: IValue>(
    ctx: &mut Context<Value>,
    input: &[Var],
    n_bytes: usize,
) -> [Var; 8] {
    // Word count, message length and loop bounds are trusted topology parameters.
    assert!(n_bytes <= 4_000_000);
    assert_eq!(input.len(), n_bytes.div_ceil(4));
    const BLOCK_BYTES: usize = 64;
    const WORDS_PER_BLOCK: usize = 16;
    let zero = ctx.zero();
    // TripleXor's lookup constraints enforce canonical (u16,u16,0,0) inputs.
    let mut message_u32s: Vec<Var> = input.iter().map(|&word| {
        let checked = triple_xor(ctx, word, zero, zero);
        eq(ctx, checked, word);
        checked
    }).collect();
    if n_bytes % 4 != 0 {
        let word = *input.last().unwrap();
        let native = ctx.get(word).unpack_u32();
        let mut packed = zero;
        // Boolean decomposition also forces all unused high bytes to zero.
        for bit in 0..(8 * (n_bytes % 4)) {
            let value = guess(ctx, Value::from_qm31(((native >> bit) & 1).into()));
            let boolean = eval!(ctx, (value) * ((value) - (1)));
            eq(ctx, boolean, zero);
            let coefficient = ctx.constant(QM31::pack_u32(1 << bit));
            packed = eval!(ctx, (packed) + ((value) * (coefficient)));
        }
        eq(ctx, packed, word);
    }

    let n_blocks = std::cmp::max(1, n_bytes.div_ceil(BLOCK_BYTES));
    let total_words = n_blocks * WORDS_PER_BLOCK;
    let zero_u32 = ctx.constant(QM31::pack_u32(0));
    while message_u32s.len() < total_words {
        message_u32s.push(zero_u32);
    }

    // `h`: IV XORed with the parameter block (depth 1, fanout 1, digest length 32, key length 0).
    let mut h: [Var; 8] = std::array::from_fn(|i| {
        let iv_val = if i == 0 { BLAKE2S_IV[0] ^ 0x01010020 } else { BLAKE2S_IV[i] };
        ctx.constant(QM31::pack_u32(iv_val))
    });

    for block_idx in 0..n_blocks {
        let block: [Var; WORDS_PER_BLOCK] =
            std::array::from_fn(|i| message_u32s[block_idx * WORDS_PER_BLOCK + i]);
        let t0 = std::cmp::min(n_bytes, (block_idx + 1) * BLOCK_BYTES) as u32;
        let t1 = 0u32;
        let last = block_idx == n_blocks - 1;

        let prev_h = h;

        let mut v: [Var; 16] = std::array::from_fn(|i| {
            if i < 8 {
                h[i]
            } else {
                let mut iv = BLAKE2S_IV[i - 8];
                if i == 12 {
                    iv ^= t0;
                }
                if i == 13 {
                    iv ^= t1;
                }
                if i == 14 && last {
                    iv ^= 0xFFFF_FFFF;
                }
                ctx.constant(QM31::pack_u32(iv))
            }
        });

        for permutation in BLAKE_SIGMA.iter() {
            for (g_idx, &(ai, bi, ci, di)) in G_STATE_INDICES.iter().enumerate() {
                let (new_a, new_b, new_c, new_d) = blake_g_gate(
                    ctx,
                    v[ai],
                    v[bi],
                    v[ci],
                    v[di],
                    block[permutation[g_idx * 2] as usize],
                    block[permutation[g_idx * 2 + 1] as usize],
                );
                v[ai] = new_a;
                v[bi] = new_b;
                v[ci] = new_c;
                v[di] = new_d;
            }
        }

        for i in 0..8 {
            h[i] = triple_xor(ctx, prev_h[i], v[i], v[i + 8]);
        }
    }

    // Preserve all 256 bits: no reduction modulo M31.
    h
}

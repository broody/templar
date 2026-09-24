//! Standard unkeyed RFC7693 Blake2s-256. Public cost probe, not an inner verifier.
use core::blake::{blake2s_compress, blake2s_finalize};

/// Input words encode bytes little-endian, with only the final partial word padded.
/// Preserve all 256 digest bits: no reduction to M31 or to a Starknet felt.
pub fn hash(mut words: Span<u32>, byte_len: u32) -> Box<[u32; 8]> {
    assert!(byte_len <= 65536, "MESSAGE_CAP");
    assert!(words.len() == (byte_len + 3) / 4, "PACKED_LENGTH");
    let tail = byte_len % 4;
    if tail != 0 {
        let limit = if tail == 1 { 256 } else if tail == 2 { 65536 } else { 16777216 };
        assert!(*words.at(words.len() - 1) < limit, "NONZERO_PADDING");
    };
    // RFC7693 IV[0] XOR parameter block 0x01010020 (32 bytes, no key, fanout/depth 1).
    let mut state = BoxTrait::new([
        0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    let mut consumed = 0;
    while consumed + 64 < byte_len {
        let block = words.multi_pop_front::<16>().unwrap();
        consumed += 64;
        state = blake2s_compress(state, consumed, *block);
    };
    let mut last = array![];
    last.append_span(words);
    for _ in words.len()..16 { last.append(0); };
    // Empty input finalizes one zero block with count 0. Exact block multiples
    // finalize the last full block; they must not add an extra empty block.
    blake2s_finalize(state, byte_len, *last.span().try_into().unwrap())
}

pub fn digest_words(words: Span<u32>, byte_len: u32) -> Array<u32> {
    let [a, b, c, d, e, f, g, h] = hash(words, byte_len).unbox();
    array![a, b, c, d, e, f, g, h]
}

#[executable]
fn main(byte_len: u32, words: Span<u32>) -> Array<u32> {
    digest_words(words, byte_len)
}

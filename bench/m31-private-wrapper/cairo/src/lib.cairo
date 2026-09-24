//! Exact SHAKE256(96 bytes) cost probe. This is not a proof verifier.
mod keccak;

pub fn shake96(data: Span<u8>) -> Array<u64> {
    assert!(data.len() <= 65536, "HASH_INPUT_CAP");
    let blocks = data.len() / 136 + 1;
    let padded_len = blocks * 136;
    let mut state: Array<u64> = array![];
    for _ in 0_usize..25 { state.append(0); };
    for block in 0..blocks {
        let mut next: Array<u64> = array![];
        for lane in 0_usize..17 {
            let mut word: u64 = 0;
            let mut factor: u64 = 1;
            for byte in 0_usize..8 {
                let index = block * 136 + lane * 8 + byte;
                let mut value: u64 = if index < data.len() {
                    (*data.at(index)).into()
                } else if index == data.len() { 0x1f } else { 0 };
                if index == padded_len - 1 { value = value ^ 0x80; };
                word = word + value * factor;
                if byte < 7 { factor = factor * 256; };
            };
            next.append(*state.at(lane) ^ word);
        };
        for lane in 17_usize..25 { next.append(*state.at(lane)); };
        state = keccak::permute(next);
    };
    let mut output = array![];
    for lane in 0_usize..12 { output.append(*state.at(lane)); };
    output
}

#[executable]
fn main(data: Span<u8>) -> Array<u64> { shake96(data) }

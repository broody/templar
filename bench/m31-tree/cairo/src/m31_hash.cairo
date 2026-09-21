//! Benchmark encoding reviewed in ../review.md. Plonky3 00fe0a985b398d3ef1f10d69543ca2b8f9f236da.
//! Poseidon2 width24 / RF8 / RP22 / x^5, MDSMat4, Pad10Sponge rate15/output9.
//! Straightforward canonical integer arithmetic; this is not Starknet's Poseidon builtin.
use super::m31_constants::{initial_constants, internal_constants, final_constants};

pub const P: u32 = 2147483647;
const P64: u64 = 2147483647;

#[derive(Copy, Drop, Serde, PartialEq, Debug, starknet::Store)]
pub struct Digest {
    pub low: felt252,
    pub high: felt252,
}

#[generate_trait]
pub impl DigestMethods of DigestTrait {
    fn key(self: Digest) -> (felt252, felt252) { (self.low, self.high) }
    fn is_zero(self: Digest) -> bool { self.low == 0 && self.high == 0 }
}

fn reduce(x: u64) -> u32 { (x % P64).try_into().unwrap() }
fn power5(x: u32) -> u32 {
    let wide: u64 = x.into();
    let square: u64 = reduce(wide * wide).into();
    let fourth: u64 = reduce(square * square).into();
    reduce(fourth * wide)
}

// Inputs are canonical. Every product is <P^2<2^62. The small matrix sums are
// <2^37; internal diagonal products and their sums are <2^54, hence fit u64.
fn external(state: Span<u32>) -> Array<u32> {
    let mut blocks = array![];
    let mut i: usize = 0;
    while i < 24 {
        let a: u64 = (*state.at(i)).into();
        let b: u64 = (*state.at(i + 1)).into();
        let c: u64 = (*state.at(i + 2)).into();
        let d: u64 = (*state.at(i + 3)).into();
        blocks.append(reduce(2*a + 3*b + c + d));
        blocks.append(reduce(a + 2*b + 3*c + d));
        blocks.append(reduce(a + b + 2*c + 3*d));
        blocks.append(reduce(3*a + b + c + 2*d));
        i += 4;
    }
    let mut sums: Array<u64> = array![];
    let mut k = 0;
    while k < 4 {
        let mut sum: u64 = 0;
        let mut j = k;
        while j < 24 { sum += (*blocks.at(j)).into(); j += 4; }
        sums.append(sum);
        k += 1;
    }
    let mut result = array![];
    i = 0;
    while i < 24 {
        result.append(reduce((*blocks.at(i)).into() + *sums.at(i % 4)));
        i += 1;
    }
    result
}

fn external_rounds(mut state: Array<u32>, constants: Span<u32>) -> Array<u32> {
    let mut round = 0;
    while round < 4 {
        let mut nonlinear = array![];
        let mut i: usize = 0;
        while i < 24 {
            nonlinear.append(power5(reduce((*state.at(i)).into() + (*constants.at(round*24+i)).into())));
            i += 1;
        }
        state = external(nonlinear.span());
        round += 1;
    }
    state
}

pub fn permutation(input: Span<u32>) -> Array<u32> {
    assert(input.len() == 24, 'STATE_LENGTH');
    for x in input { assert(*x < P, 'NONCANONICAL_M31'); };
    let mut state = external(input);
    state = external_rounds(state, initial_constants().span());
    let constants = internal_constants();
    let mut round = 0;
    while round < 22 {
        let first = power5(reduce((*state.at(0)).into() + (*constants.at(round)).into()));
        let mut sum: u64 = first.into();
        let mut i = 1;
        while i < 24 { sum += (*state.at(i)).into(); i += 1; }
        let mut result = array![];
        let first_wide: u64 = first.into();
        result.append(reduce(sum + 2*P64 - 2*first_wide));
        let mut diagonal: u64 = 1;
        i = 1;
        while i < 24 {
            result.append(reduce(sum + diagonal * (*state.at(i)).into()));
            diagonal *= 2;
            i += 1;
        }
        state = result;
        round += 1;
    }
    external_rounds(state, final_constants().span())
}

pub fn pack(words: Span<u32>) -> Digest {
    assert(words.len() == 9, 'DIGEST_LENGTH');
    for w in words { assert(*w < P, 'NONCANONICAL_M31'); };
    let mut low: felt252 = 0;
    let mut factor: felt252 = 1;
    let mut i: usize = 0;
    while i < 8 {
        low += factor * (*words.at(i)).into();
        factor *= 0x80000000;
        i += 1;
    }
    Digest { low, high: (*words.at(8)).into() }
}

pub fn unpack(digest: Digest) -> Array<u32> {
    let mut low: u256 = digest.low.into();
    let mut result = array![];
    let mut i: usize = 0;
    while i < 8 {
        let word: u32 = (low % 0x80000000).try_into().unwrap();
        assert(word < P, 'NONCANONICAL_M31');
        result.append(word);
        low /= 0x80000000;
        i += 1;
    }
    assert(low == 0, 'DIGEST_TOP_BITS');
    let high: u32 = digest.high.try_into().expect('DIGEST_HIGH_RANGE');
    assert(high < P, 'NONCANONICAL_M31');
    result.append(high);
    result
}

pub fn sponge(message: Span<u32>) -> Digest {
    for x in message { assert(*x < P, 'NONCANONICAL_M31'); };
    let mut state = array![];
    let mut i: usize = 0;
    while i < 24 { state.append(0_u32); i += 1; }
    let mut offset = 0;
    loop {
        let remaining = message.len() - offset;
        let take = if remaining < 15 { remaining } else { 15 };
        let mut block = array![];
        i = 0;
        while i < 15 {
            let value = if i < take { *message.at(offset+i) }
                else if i == take { 1 } else { 0 };
            block.append(value);
            i += 1;
        }
        while i < 24 {
            let value = if i == 15 && remaining == 15 {
                reduce((*state.at(i)).into() + 1)
            } else { *state.at(i) };
            block.append(value);
            i += 1;
        }
        state = permutation(block.span());
        offset += take;
        if remaining <= 15 { break; }
    };
    pack(state.span().slice(0, 9))
}

fn header(kind: u32, level: u32) -> Array<u32> { array![0x544d5031, 1, kind, level] }

pub fn empty_leaf() -> Digest { sponge(header(3, 0).span()) }

pub fn leaf_hash(value: felt252) -> Digest {
    let mut words = header(1, 0);
    let mut n: u256 = value.into();
    let mut i: usize = 0;
    while i < 9 {
        words.append((n % 0x10000000).try_into().unwrap());
        n /= 0x10000000;
        i += 1;
    }
    assert(n == 0, 'LEAF_TOP_BITS');
    sponge(words.span())
}

pub fn node_hash(level: u64, left: Digest, right: Digest) -> Digest {
    assert(level >= 1 && level <= 32, 'NODE_LEVEL');
    let mut words = header(2, level.try_into().unwrap());
    for x in unpack(left).span() { words.append(*x); };
    for x in unpack(right).span() { words.append(*x); };
    sponge(words.span())
}

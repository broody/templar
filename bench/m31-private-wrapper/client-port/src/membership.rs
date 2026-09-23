//! Spike: the TMPZK002 membership relation (`air::witness`) as a plain stwo-circuits
//! circuit, for a blinded upstream client proof. Public output: the nine root words.
//! The permutation is the client's own `hash::{external, internal}` code with its
//! pinned constants, traced through the symbolic field.
use crate::hash::{WIDTH, external, internal};
use crate::constants::{EXTERNAL_FINAL, EXTERNAL_INITIAL, INTERNAL};
use crate::merkle::guess_bits;
use crate::ro::guess_m31;
use crate::sym::{Sym, compile};
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::IValue;
use stwo::core::fields::m31::M31;
use stwo::core::fields::Field;

pub const TAG: u32 = 0x544d5031;

/// The width-24 permutation exactly as `hash::record` computes its output.
pub fn permute<F: Field + From<M31>>(input: [F; WIDTH]) -> [F; WIDTH] {
    let sbox = |x: F| { let x2 = x * x; let x4 = x2 * x2; x4 * x };
    let mut s = input;
    external(&mut s);
    for c in &EXTERNAL_INITIAL {
        for i in 0..WIDTH {
            s[i] = sbox(s[i] + F::from(M31::from(c[i])));
        }
        external(&mut s);
    }
    for c in INTERNAL {
        s[0] = sbox(s[0] + F::from(M31::from(c)));
        internal(&mut s);
    }
    for c in &EXTERNAL_FINAL {
        for i in 0..WIDTH {
            s[i] = sbox(s[i] + F::from(M31::from(c[i])));
        }
        external(&mut s);
    }
    s
}

pub fn permute_gates<V: IValue>(ctx: &mut Context<V>, input: &[Var]) -> Vec<Var> {
    let syms = Sym::begin(WIDTH);
    let out = permute::<Sym>(syms.try_into().unwrap());
    compile(ctx, input, &out)
}

/// `hash::sponge` over variables: 15-element overwrite rate, 9-element capacity.
pub fn sponge<V: IValue>(ctx: &mut Context<V>, message: &[Var]) -> Vec<Var> {
    let zero = ctx.zero();
    let one = ctx.one();
    let mut state = vec![zero; WIDTH];
    let mut offset = 0;
    loop {
        let n = (message.len() - offset).min(15);
        state[..n].copy_from_slice(&message[offset..offset + n]);
        offset += n;
        let done = offset == message.len();
        if n < 15 {
            state[n] = one;
            for s in &mut state[n + 1..15] {
                *s = zero;
            }
        } else if done {
            let s15 = state[15];
            state[15] = eval!(ctx, (s15) + (one));
        }
        state = permute_gates(ctx, &state);
        // The rate part is overwritten by the next absorb; only used lanes need uses.
        for v in &state {
            ctx.mark_as_maybe_unused(v);
        }
        if done {
            return state;
        }
    }
}

fn frame<V: IValue>(ctx: &mut Context<V>, kind: u32, level: u32, payload: &[Var]) -> Vec<Var> {
    let mut x: Vec<Var> = [TAG, 1, kind, level].iter().map(|v| ctx.constant(M31::from(*v).into())).collect();
    x.extend_from_slice(payload);
    x
}

/// Builds the relation for a private witness and returns the root variables.
pub fn build<V: IValue>(ctx: &mut Context<V>, secret: &[u32; 9], siblings: &[[u32; 9]], bits: &[u32]) -> Vec<Var> {
    assert_eq!((siblings.len(), bits.len()), (32, 32));
    let secret: Vec<Var> = secret.iter().map(|v| guess_m31(ctx, *v)).collect();
    let leaf = frame(ctx, 1, 0, &secret);
    let mut cur: Vec<Var> = sponge(ctx, &leaf)[..9].to_vec();
    for level in 0..32 {
        let sib: Vec<Var> = siblings[level].iter().map(|v| guess_m31(ctx, *v)).collect();
        let bit = guess_bits(ctx, bits[level] as usize, 1)[0];
        let mut left = vec![];
        let mut right = vec![];
        for (c, s) in cur.iter().zip(&sib) {
            let (c, s) = (*c, *s);
            let d = eval!(ctx, (bit) * ((s) - (c)));
            left.push(eval!(ctx, (c) + (d)));
            right.push(eval!(ctx, (s) - (d)));
        }
        left.extend(right);
        let node = frame(ctx, 3, level as u32, &left);
        cur = sponge(ctx, &node)[..9].to_vec();
    }
    cur
}

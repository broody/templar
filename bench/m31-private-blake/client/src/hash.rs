//! Same width-24 Poseidon2 parameters and round order as the vector-checked M31 bench.
use crate::constants::{EXTERNAL_FINAL, EXTERNAL_INITIAL, INTERNAL};
use num_traits::{One, Zero};
use stwo::core::fields::{Field, m31::M31};

pub const WIDTH: usize = 24;
pub const PERM_COLS: usize = 1172;
pub const TAG: u32 = 0x544d5031;

pub fn external<F: Field + From<M31>>(s: &mut [F; WIDTH]) {
    for off in (0..WIDTH).step_by(4) {
        let x: [F; 4] = std::array::from_fn(|i| s[off + i]);
        let mat = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
        for i in 0..4 {
            s[off + i] = (0..4).map(|j| x[j] * F::from(M31::from(mat[i][j]))).sum();
        }
    }
    let sums: [F; 4] = std::array::from_fn(|k| (0..WIDTH).step_by(4).map(|i| s[i + k]).sum());
    for i in 0..WIDTH {
        s[i] += sums[i % 4];
    }
}
pub fn internal<F: Field + From<M31>>(s: &mut [F; WIDTH]) {
    let total: F = s.iter().copied().sum();
    for i in 0..WIDTH {
        let diag = if i == 0 {
            M31::from(2147483645)
        } else {
            M31::from(1u32 << (i - 1))
        };
        s[i] = total + s[i] * F::from(diag);
    }
}
pub fn record(input: [M31; WIDTH]) -> (Vec<M31>, [M31; WIDTH]) {
    let mut trace = input.to_vec();
    let mut state = input;
    external(&mut state);
    for constants in &EXTERNAL_INITIAL {
        for i in 0..WIDTH {
            let x = state[i] + M31::from(constants[i]);
            let x2 = x * x;
            let x4 = x2 * x2;
            trace.extend([x2, x4]);
            state[i] = x4 * x;
        }
        external(&mut state);
        trace.extend(state);
    }
    for constant in INTERNAL {
        let x = state[0] + M31::from(constant);
        let x2 = x * x;
        let x4 = x2 * x2;
        trace.extend([x2, x4]);
        state[0] = x4 * x;
        internal(&mut state);
        trace.extend(state);
    }
    for constants in &EXTERNAL_FINAL {
        for i in 0..WIDTH {
            let x = state[i] + M31::from(constants[i]);
            let x2 = x * x;
            let x4 = x2 * x2;
            trace.extend([x2, x4]);
            state[i] = x4 * x;
        }
        external(&mut state);
        trace.extend(state);
    }
    assert_eq!(trace.len(), PERM_COLS);
    (trace, state)
}
pub fn constraints<F: Field + From<M31>>(row: &[F], out: &mut Vec<F>) {
    let mut cursor = WIDTH;
    let mut s: [F; WIDTH] = row[..WIDTH].try_into().unwrap();
    external(&mut s);
    for constants in &EXTERNAL_INITIAL {
        for i in 0..WIDTH {
            let x = s[i] + F::from(M31::from(constants[i]));
            let x2 = row[cursor];
            let x4 = row[cursor + 1];
            cursor += 2;
            out.extend([x2 - x * x, x4 - x2 * x2]);
            s[i] = x4 * x;
        }
        external(&mut s);
        for v in &mut s {
            let n = row[cursor];
            cursor += 1;
            out.push(n - *v);
            *v = n;
        }
    }
    for constant in INTERNAL {
        let x = s[0] + F::from(M31::from(constant));
        let x2 = row[cursor];
        let x4 = row[cursor + 1];
        cursor += 2;
        out.extend([x2 - x * x, x4 - x2 * x2]);
        s[0] = x4 * x;
        internal(&mut s);
        for v in &mut s {
            let n = row[cursor];
            cursor += 1;
            out.push(n - *v);
            *v = n;
        }
    }
    for constants in &EXTERNAL_FINAL {
        for i in 0..WIDTH {
            let x = s[i] + F::from(M31::from(constants[i]));
            let x2 = row[cursor];
            let x4 = row[cursor + 1];
            cursor += 2;
            out.extend([x2 - x * x, x4 - x2 * x2]);
            s[i] = x4 * x;
        }
        external(&mut s);
        for v in &mut s {
            let n = row[cursor];
            cursor += 1;
            out.push(n - *v);
            *v = n;
        }
    }
    assert_eq!(cursor, PERM_COLS);
}
pub fn sponge(message: &[M31]) -> Vec<([M31; 24], [M31; 24])> {
    let mut state = [M31::zero(); 24];
    let mut offset = 0;
    let mut rows = vec![];
    loop {
        let n = (message.len() - offset).min(15);
        state[..n].copy_from_slice(&message[offset..offset + n]);
        offset += n;
        let done = offset == message.len();
        if n < 15 {
            state[n] = M31::one();
            state[n + 1..15].fill(M31::zero());
        } else if done {
            state[15] += M31::one();
        }
        let input = state;
        state = record(input).1;
        rows.push((input, state));
        if done {
            return rows;
        }
    }
}

//! Dual-number M31 for exact derivatives of the expansion map.
//! value: M31, grad: [M31; N] (product rule; all arithmetic mod P).
use crate::m31::P;

#[derive(Clone, Copy, Debug)]
pub struct Dual<const N: usize> {
    pub v: u32,
    pub g: [u32; N],
}
impl<const N: usize> Dual<N> {
    pub fn c(v: u32) -> Self {
        Dual { v: v % P, g: [0; N] }
    }
    pub fn var(v: u32, idx: usize) -> Self {
        let mut g = [0; N];
        g[idx] = 1;
        Dual { v: v % P, g }
    }
    fn mul_grad(a: &[u32; N], av: u32, b: &[u32; N], bv: u32) -> [u32; N] {
        let mut out = [0u32; N];
        for i in 0..N {
            out[i] = (a[i] * bv % P + b[i] * av % P) % P;
        }
        out
    }
}
impl<const N: usize> std::ops::Add for Dual<N> {
    type Output = Self;
    fn add(self, o: Self) -> Self {
        Dual {
            v: (self.v + o.v) % P,
            g: std::array::from_fn(|i| (self.g[i] + o.g[i]) % P),
        }
    }
}
impl<const N: usize> std::ops::Sub for Dual<N> {
    type Output = Self;
    fn sub(self, o: Self) -> Self {
        Dual {
            v: (self.v + P - o.v) % P,
            g: std::array::from_fn(|i| (self.g[i] + P - o.g[i]) % P),
        }
    }
}
impl<const N: usize> std::ops::Mul for Dual<N> {
    type Output = Self;
    fn mul(self, o: Self) -> Self {
        let v = (self.v as u64 * o.v as u64) % P as u64;
        Dual {
            v: v as u32,
            g: Self::mul_grad(&self.g, self.v, &o.g, o.v),
        }
    }
}
impl<const N: usize> std::ops::Add<u32> for Dual<N> {
    type Output = Self;
    fn add(self, o: u32) -> Self {
        self + Dual::c(o)
    }
}

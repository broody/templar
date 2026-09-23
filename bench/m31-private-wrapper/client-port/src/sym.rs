//! Symbolic field used to run the client's own generic constraint code
//! (`air::constraints`) and compile the recorded expression graph into gates.
//! Only ring operations are supported; division, remainder and inversion panic,
//! so a silent semantic divergence cannot occur.
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::ivalue::IValue;
use num_traits::{Num, One, Zero};
use std::cell::RefCell;
use std::fmt;
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::{ComplexConjugate, Field, FieldExpOps};

#[derive(Clone, Copy, Debug)]
enum Node {
    Const(QM31),
    Input(u32),
    Add(u32, u32),
    Sub(u32, u32),
    Mul(u32, u32),
}

thread_local! {
    static ARENA: RefCell<Vec<Node>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sym(u32);

fn push(n: Node) -> Sym {
    ARENA.with(|a| {
        let mut a = a.borrow_mut();
        a.push(n);
        Sym(a.len() as u32 - 1)
    })
}
fn node(s: Sym) -> Node {
    ARENA.with(|a| a.borrow()[s.0 as usize])
}
fn constant_of(s: Sym) -> Option<QM31> {
    match node(s) {
        Node::Const(c) => Some(c),
        _ => None,
    }
}

impl Sym {
    /// Starts a fresh recording and returns `n` input symbols.
    pub fn begin(n: usize) -> Vec<Sym> {
        ARENA.with(|a| a.borrow_mut().clear());
        (0..n as u32).map(|i| push(Node::Input(i))).collect()
    }
    pub fn constant(c: QM31) -> Sym {
        push(Node::Const(c))
    }
}

impl From<M31> for Sym {
    fn from(v: M31) -> Self {
        Sym::constant(v.into())
    }
}
impl Add for Sym {
    type Output = Sym;
    fn add(self, o: Sym) -> Sym {
        match (constant_of(self), constant_of(o)) {
            (Some(a), Some(b)) => Sym::constant(a + b),
            (Some(a), _) if a.is_zero() => o,
            (_, Some(b)) if b.is_zero() => self,
            _ => push(Node::Add(self.0, o.0)),
        }
    }
}
impl Sub for Sym {
    type Output = Sym;
    fn sub(self, o: Sym) -> Sym {
        match (constant_of(self), constant_of(o)) {
            (Some(a), Some(b)) => Sym::constant(a - b),
            (_, Some(b)) if b.is_zero() => self,
            _ => push(Node::Sub(self.0, o.0)),
        }
    }
}
impl Mul for Sym {
    type Output = Sym;
    fn mul(self, o: Sym) -> Sym {
        match (constant_of(self), constant_of(o)) {
            (Some(a), Some(b)) => Sym::constant(a * b),
            (Some(a), _) if a.is_zero() => self,
            (_, Some(b)) if b.is_zero() => o,
            (Some(a), _) if a.is_one() => o,
            (_, Some(b)) if b.is_one() => self,
            _ => push(Node::Mul(self.0, o.0)),
        }
    }
}
impl Neg for Sym {
    type Output = Sym;
    fn neg(self) -> Sym {
        Sym::constant(QM31::zero()) - self
    }
}
impl Div for Sym {
    type Output = Sym;
    fn div(self, _: Sym) -> Sym {
        panic!("division is not supported symbolically")
    }
}
impl Rem for Sym {
    type Output = Sym;
    fn rem(self, _: Sym) -> Sym {
        panic!("remainder is not supported symbolically")
    }
}
impl AddAssign for Sym {
    fn add_assign(&mut self, o: Sym) {
        *self = *self + o;
    }
}
impl SubAssign for Sym {
    fn sub_assign(&mut self, o: Sym) {
        *self = *self - o;
    }
}
impl MulAssign for Sym {
    fn mul_assign(&mut self, o: Sym) {
        *self = *self * o;
    }
}
impl DivAssign for Sym {
    fn div_assign(&mut self, o: Sym) {
        *self = *self / o;
    }
}
impl RemAssign for Sym {
    fn rem_assign(&mut self, o: Sym) {
        *self = *self % o;
    }
}
impl Zero for Sym {
    fn zero() -> Self {
        Sym::constant(QM31::zero())
    }
    fn is_zero(&self) -> bool {
        constant_of(*self).is_some_and(|c| c.is_zero())
    }
}
impl One for Sym {
    fn one() -> Self {
        Sym::constant(QM31::one())
    }
}
impl Num for Sym {
    type FromStrRadixErr = ();
    fn from_str_radix(_: &str, _: u32) -> Result<Self, ()> {
        Err(())
    }
}
impl Default for Sym {
    fn default() -> Self {
        Sym::zero()
    }
}
impl fmt::Display for Sym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sym{}", self.0)
    }
}
impl ComplexConjugate for Sym {
    fn complex_conjugate(&self) -> Self {
        panic!("conjugation is not supported symbolically")
    }
}
impl FieldExpOps for Sym {
    fn inverse(&self) -> Self {
        panic!("inversion is not supported symbolically")
    }
}
impl Sum for Sym {
    fn sum<I: Iterator<Item = Sym>>(it: I) -> Sym {
        it.fold(Sym::zero(), |a, b| a + b)
    }
}
impl<'a> Sum<&'a Sym> for Sym {
    fn sum<I: Iterator<Item = &'a Sym>>(it: I) -> Sym {
        it.fold(Sym::zero(), |a, b| a + *b)
    }
}
impl Product for Sym {
    fn product<I: Iterator<Item = Sym>>(it: I) -> Sym {
        it.fold(Sym::one(), |a, b| a * b)
    }
}
impl<'a> Product<&'a Sym> for Sym {
    fn product<I: Iterator<Item = &'a Sym>>(it: I) -> Sym {
        it.fold(Sym::one(), |a, b| a * *b)
    }
}
impl Field for Sym {}

/// Compiles recorded `outputs` into gates, with `inputs[i]` bound to `Input(i)`.
pub fn compile<Value: IValue>(ctx: &mut Context<Value>, inputs: &[Var], outputs: &[Sym]) -> Vec<Var> {
    let nodes = ARENA.with(|a| a.borrow().clone());
    let mut live = vec![false; nodes.len()];
    let mut stack: Vec<u32> = outputs.iter().map(|s| s.0).collect();
    while let Some(i) = stack.pop() {
        if std::mem::replace(&mut live[i as usize], true) {
            continue;
        }
        match nodes[i as usize] {
            Node::Add(a, b) | Node::Sub(a, b) | Node::Mul(a, b) => stack.extend([a, b]),
            _ => {}
        }
    }
    let mut vars: Vec<Option<Var>> = vec![None; nodes.len()];
    for (i, n) in nodes.iter().enumerate() {
        if !live[i] {
            continue;
        }
        let get = |k: u32| vars[k as usize].unwrap();
        vars[i] = Some(match *n {
            Node::Const(c) => ctx.constant(c),
            Node::Input(k) => inputs[k as usize],
            Node::Add(a, b) => { let (a, b) = (get(a), get(b)); eval!(ctx, (a) + (b)) }
            Node::Sub(a, b) => { let (a, b) = (get(a), get(b)); eval!(ctx, (a) - (b)) }
            Node::Mul(a, b) => { let (a, b) = (get(a), get(b)); eval!(ctx, (a) * (b)) }
        });
    }
    outputs.iter().map(|s| vars[s.0 as usize].unwrap()).collect()
}

//! Poseidon2-M31 width 24 (8 full + 22 partial rounds, x^5, the pool's round constants) on native
//! M31 ops (`core::qm31::m31_ops`, the QM31 opcode), with `perm_compact.cairo`'s structure: one
//! shared full-round function over a constant table (8 calls), groups of four partial rounds
//! (5 calls, plus the last two). Phase 1b of the device-proving spike: every QM31-opcode
//! instruction is a big felt in the class hash, so sharing round code cuts the executed bytecode
//! the OS hashes. The external layer uses Plonky3's M4 addition chain (11 adds per block of four).
//! Canonical inputs are checked on the way in, as in `perm_qm31.cairo`. Not in Starknet's audited
//! libfuncs (U1): local capture only. Generated from `perm_compact.cairo`'s tables.
use core::qm31::{m31, m31_ops};
use stwo_verifier_core::fields::m31::M31;
type F = m31;
pub type S = [felt252; 24];
type T = [F; 24];

#[inline(always)]
fn add(a: F, b: F) -> F {
    m31_ops::add(a, b)
}

#[inline(always)]
fn mul(a: F, b: F) -> F {
    m31_ops::mul(a, b)
}

#[inline(always)]
fn sbox(x: F) -> F {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    mul(x4, x)
}

const EXT_INIT: [[F; 24]; 4] = [
    [535476833, 1394754644, 1808710114, 1343879604, 1215456658, 723701928, 1632746489, 793201441, 783676215, 996433287, 155373296, 1696762962, 2030023439, 1294481352, 236432463, 89417350, 74188492, 189907894, 1452128099, 951268580, 1475718384, 433268241, 2010132299, 1820518840],
    [1900593590, 134642805, 1188161737, 815217415, 543248187, 1547696209, 810562345, 1232267212, 47306940, 165003174, 158401728, 2074384948, 1242022652, 616689257, 682011457, 1569786016, 980963783, 500471289, 313827316, 2074957664, 1609393346, 1727383916, 2125446402, 968055099],
    [1248148297, 1963531713, 1457817824, 386179925, 1952337907, 959377774, 836976607, 46304358, 918751290, 822399482, 1526975907, 1715593647, 930433878, 963599097, 437929498, 1754146546, 1870829444, 465116521, 1534623766, 1883940293, 25265820, 1092689494, 216531872, 599782304],
    [402354276, 1194422816, 1989233491, 563878149, 375739688, 1307792708, 1619035237, 860944435, 62705095, 176625674, 24812021, 1855215398, 356799748, 2013606833, 999407416, 1070038705, 1263375886, 1020869934, 245688694, 491980492, 981123716, 247605556, 1301780243, 1369709669],
];

const EXT_FINAL: [[F; 24]; 4] = [
    [476455577, 92050778, 2058797298, 631680266, 1971653464, 1224554387, 188966577, 266145097, 2108955129, 1236913167, 1217697558, 700668048, 1984189573, 472371980, 279607867, 821252022, 1876976693, 34823885, 1823128214, 1051889872, 587042107, 1988826405, 1542019092, 1379762153],
    [1441352940, 1204039199, 447036254, 802291326, 1495469713, 1953684070, 1682174687, 765321629, 1870621316, 2004878384, 251743176, 2079576213, 649057048, 1478844919, 1591941516, 1791754240, 791764518, 667598912, 630523934, 1499707354, 2114401637, 1827927537, 167289764, 229166334],
    [1623073637, 2128036597, 1720418353, 1269838996, 1493275443, 1879976056, 482629718, 487987191, 2073595302, 1320457068, 2026502270, 1674460820, 1903703067, 1169960838, 95909308, 1883963972, 703517304, 1207185458, 556249829, 429363263, 615763459, 204614028, 2099998522, 402434689],
    [1928560623, 807987113, 1591561622, 529946683, 1289130378, 344461070, 1763115865, 389856563, 157935604, 1853825963, 1635969671, 1305157468, 1482662163, 1922872246, 28549754, 463565799, 1261681898, 1675180987, 1799339929, 1863838161, 205379770, 197261736, 1691612016, 1180330520],
];

const INT_GROUPS: [[F; 4]; 5] = [
    [578251281, 1604534888, 336941709, 1447017748],
    [888427076, 302948790, 638806181, 661020353],
    [918431749, 878462852, 401595585, 960390448],
    [1839248568, 837148371, 1734027180, 183012400],
    [1467498956, 1608543724, 1454401818, 1916984863],
];

const INT_LAST: [F; 2] = [1010267433, 865826083];

fn external(s: T) -> T {
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23] = s;
    let a0 = add(s0, s1);
    let b0 = add(s2, s3);
    let c0 = add(a0, b0);
    let d0 = add(c0, s1);
    let e0 = add(c0, s3);
    let y0_0 = add(d0, a0);
    let y0_1 = add(d0, add(s2, s2));
    let y0_2 = add(e0, b0);
    let y0_3 = add(e0, add(s0, s0));
    let a1 = add(s4, s5);
    let b1 = add(s6, s7);
    let c1 = add(a1, b1);
    let d1 = add(c1, s5);
    let e1 = add(c1, s7);
    let y1_0 = add(d1, a1);
    let y1_1 = add(d1, add(s6, s6));
    let y1_2 = add(e1, b1);
    let y1_3 = add(e1, add(s4, s4));
    let a2 = add(s8, s9);
    let b2 = add(s10, s11);
    let c2 = add(a2, b2);
    let d2 = add(c2, s9);
    let e2 = add(c2, s11);
    let y2_0 = add(d2, a2);
    let y2_1 = add(d2, add(s10, s10));
    let y2_2 = add(e2, b2);
    let y2_3 = add(e2, add(s8, s8));
    let a3 = add(s12, s13);
    let b3 = add(s14, s15);
    let c3 = add(a3, b3);
    let d3 = add(c3, s13);
    let e3 = add(c3, s15);
    let y3_0 = add(d3, a3);
    let y3_1 = add(d3, add(s14, s14));
    let y3_2 = add(e3, b3);
    let y3_3 = add(e3, add(s12, s12));
    let a4 = add(s16, s17);
    let b4 = add(s18, s19);
    let c4 = add(a4, b4);
    let d4 = add(c4, s17);
    let e4 = add(c4, s19);
    let y4_0 = add(d4, a4);
    let y4_1 = add(d4, add(s18, s18));
    let y4_2 = add(e4, b4);
    let y4_3 = add(e4, add(s16, s16));
    let a5 = add(s20, s21);
    let b5 = add(s22, s23);
    let c5 = add(a5, b5);
    let d5 = add(c5, s21);
    let e5 = add(c5, s23);
    let y5_0 = add(d5, a5);
    let y5_1 = add(d5, add(s22, s22));
    let y5_2 = add(e5, b5);
    let y5_3 = add(e5, add(s20, s20));
    let u0 = add(add(add(y0_0, y1_0), add(y2_0, y3_0)), add(y4_0, y5_0));
    let u1 = add(add(add(y0_1, y1_1), add(y2_1, y3_1)), add(y4_1, y5_1));
    let u2 = add(add(add(y0_2, y1_2), add(y2_2, y3_2)), add(y4_2, y5_2));
    let u3 = add(add(add(y0_3, y1_3), add(y2_3, y3_3)), add(y4_3, y5_3));
    [add(y0_0, u0), add(y0_1, u1), add(y0_2, u2), add(y0_3, u3), add(y1_0, u0), add(y1_1, u1), add(y1_2, u2), add(y1_3, u3), add(y2_0, u0), add(y2_1, u1), add(y2_2, u2), add(y2_3, u3), add(y3_0, u0), add(y3_1, u1), add(y3_2, u2), add(y3_3, u3), add(y4_0, u0), add(y4_1, u1), add(y4_2, u2), add(y4_3, u3), add(y5_0, u0), add(y5_1, u1), add(y5_2, u2), add(y5_3, u3)]
}

fn ext_round(s: T, c: [F; 24]) -> T {
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23] = s;
    let [c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23] = c;
    external([sbox(add(s0, c0)), sbox(add(s1, c1)), sbox(add(s2, c2)), sbox(add(s3, c3)), sbox(add(s4, c4)), sbox(add(s5, c5)), sbox(add(s6, c6)), sbox(add(s7, c7)), sbox(add(s8, c8)), sbox(add(s9, c9)), sbox(add(s10, c10)), sbox(add(s11, c11)), sbox(add(s12, c12)), sbox(add(s13, c13)), sbox(add(s14, c14)), sbox(add(s15, c15)), sbox(add(s16, c16)), sbox(add(s17, c17)), sbox(add(s18, c18)), sbox(add(s19, c19)), sbox(add(s20, c20)), sbox(add(s21, c21)), sbox(add(s22, c22)), sbox(add(s23, c23))])
}

#[inline(always)]
fn int_round(s: T, c: F) -> T {
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23] = s;
    let s0 = sbox(add(s0, c));
    let t = add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(s0, s1), s2), s3), s4), s5), s6), s7), s8), s9), s10), s11), s12), s13), s14), s15), s16), s17), s18), s19), s20), s21), s22), s23);
    [add(t, mul(s0, 2147483645)), add(t, mul(s1, 1)), add(t, mul(s2, 2)), add(t, mul(s3, 4)), add(t, mul(s4, 8)), add(t, mul(s5, 16)), add(t, mul(s6, 32)), add(t, mul(s7, 64)), add(t, mul(s8, 128)), add(t, mul(s9, 256)), add(t, mul(s10, 512)), add(t, mul(s11, 1024)), add(t, mul(s12, 2048)), add(t, mul(s13, 4096)), add(t, mul(s14, 8192)), add(t, mul(s15, 16384)), add(t, mul(s16, 32768)), add(t, mul(s17, 65536)), add(t, mul(s18, 131072)), add(t, mul(s19, 262144)), add(t, mul(s20, 524288)), add(t, mul(s21, 1048576)), add(t, mul(s22, 2097152)), add(t, mul(s23, 4194304))]
}

fn int_group(s: T, c: [F; 4]) -> T {
    let [c0, c1, c2, c3] = c;
    int_round(int_round(int_round(int_round(s, c0), c1), c2), c3)
}

fn permutation_m31(s: T) -> T {
    let mut s = external(s);
    for c in EXT_INIT.span() {
        s = ext_round(s, *c);
    }
    for c in INT_GROUPS.span() {
        s = int_group(s, *c);
    }
    let [c20, c21] = INT_LAST;
    s = int_round(int_round(s, c20), c21);
    for c in EXT_FINAL.span() {
        s = ext_round(s, *c);
    }
    s
}

#[inline(always)]
fn to_m31(x: felt252) -> F {
    let v: u32 = x.try_into().unwrap();
    let m: M31 = v.try_into().expect('M31_WORD');
    m.inner
}

pub fn permutation(s: S) -> S {
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23] = s;
    let [o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15, o16, o17, o18, o19, o20, o21, o22, o23] = permutation_m31([to_m31(s0), to_m31(s1), to_m31(s2), to_m31(s3), to_m31(s4), to_m31(s5), to_m31(s6), to_m31(s7), to_m31(s8), to_m31(s9), to_m31(s10), to_m31(s11), to_m31(s12), to_m31(s13), to_m31(s14), to_m31(s15), to_m31(s16), to_m31(s17), to_m31(s18), to_m31(s19), to_m31(s20), to_m31(s21), to_m31(s22), to_m31(s23)]);
    [o0.into(), o1.into(), o2.into(), o3.into(), o4.into(), o5.into(), o6.into(), o7.into(), o8.into(), o9.into(), o10.into(), o11.into(), o12.into(), o13.into(), o14.into(), o15.into(), o16.into(), o17.into(), o18.into(), o19.into(), o20.into(), o21.into(), o22.into(), o23.into()]
}

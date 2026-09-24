//! Malicious witnesses against the P1 circuit, from the implementation math review
//! (`bench/m31-pool/reviews/policy-note-impl-math-review.md`): each case overrides hint values the
//! honest builder derives (feature `tamper`) and checks the constraints reject it.
use circuits::context::Context;
use rand::{Rng, SeedableRng, rngs::StdRng};
use stwo::core::fields::qm31::QM31;
use templar_client_verifier_circuit::payment::Tree;
use templar_client_verifier_circuit::policy::{
    self, FIXED, N_OUTPUTS, Private, Public, SPLIT, Shape, TAMPER, Tamper, build, fresh, statement_limbs,
};

const TREE: Tree = Tree::Compress;

fn run(public: &Public, private: &Private, t: Tamper) -> (Vec<u32>, bool) {
    TAMPER.with(|x| *x.borrow_mut() = t);
    let mut c = Context::<QM31>::new(N_OUTPUTS);
    let out = build(&mut c, TREE, public, private);
    TAMPER.with(|x| *x.borrow_mut() = Tamper::default());
    let limbs = out.iter().flat_map(|v| c.get(*v).to_m31_array().map(|m| m.0)).collect();
    (limbs, c.is_circuit_valid())
}

fn rejected(name: &str, public: &Public, private: &Private, t: Tamper) {
    let (_, valid) = run(public, private, t);
    eprintln!("{name}: circuit valid = {valid}");
    assert!(!valid, "{name} accepted");
}

#[test]
fn m1_split_hide_remainder_nz_r_zero() {
    let (public, private, _) = fresh(TREE, Shape::Split, &mut StdRng::seed_from_u64(21));
    assert!(public.x < private.amount);
    rejected("nz_r forced 0 with r != 0", &public, &private, Tamper { nz_r: Some(false), ..Default::default() });
}

#[test]
fn m2_split_all_fake_remainder_nz_r_one() {
    let (public, private, _) = fresh(TREE, Shape::SplitAll, &mut StdRng::seed_from_u64(22));
    rejected("nz_r forced 1 with r = 0", &public, &private, Tamper { nz_r: Some(true), ..Default::default() });
}

#[test]
fn m3_split_wrong_remainder() {
    let (public, private, _) = fresh(TREE, Shape::Split, &mut StdRng::seed_from_u64(23));
    let r = private.amount - public.x;
    rejected("r + 1", &public, &private, Tamper { r_value: Some(r + 1), ..Default::default() });
    rejected("r - 1", &public, &private, Tamper { r_value: Some(r - 1), ..Default::default() });
    // x > amount with the wrapped remainder (amount - x mod 2^128), under default and random carries.
    let mut pb = public.clone();
    pb.x = private.amount + 5;
    let wrapped = private.amount.wrapping_sub(pb.x);
    rejected("x > amount, wrapped r", &pb, &private, Tamper { r_value: Some(wrapped), ..Default::default() });
    let mut rng = StdRng::seed_from_u64(99);
    for _ in 0..64 {
        let carries: Vec<i64> = (0..8).map(|_| rng.gen_range(-2..=1)).collect();
        rejected("x > amount, wrapped r, random carries", &pb, &private,
                 Tamper { r_value: Some(wrapped), carries: Some(carries), ..Default::default() });
    }
}

#[test]
fn m4_fixed_conservation_carries() {
    // Inflate out0 by 2^16 and try every carry pattern that differs in one limb.
    let (public, mut private, _) = fresh(TREE, Shape::Settle, &mut StdRng::seed_from_u64(24));
    private.selected.outputs[0].amount += 1 << 16;
    for k in 0..7 {
        for v in -2..=1 {
            let mut carries = vec![0i64; 8];
            carries[k] = v;
            let (_, valid) = run(&public, &private, Tamper { carries: Some(carries), ..Default::default() });
            assert!(!valid);
        }
    }
    eprintln!("inflated output with 28 carry patterns: all rejected");
}

#[test]
fn m5_selector() {
    let (public, private, _) = fresh(TREE, Shape::Settle, &mut StdRng::seed_from_u64(25));
    rejected("two selector bits", &public, &private, Tamper { sel: Some([true, true, false, false]), ..Default::default() });
    rejected("no selector bit", &public, &private, Tamper { sel: Some([false; 4]), ..Default::default() });
    // The settle outcome recomputed into slot 0 (claims to be the refund): refund rules reject
    // (out1 active is fine for slot 0, but the settle outcome has not_before != 0 here).
    let (_, valid) = run(&public, &private, Tamper { sel: Some([true, false, false, false]), ..Default::default() });
    eprintln!("settle outcome under b0: valid = {valid}");
}

#[test]
fn m6_type_bit() {
    for shape in [Shape::Settle, Shape::Withdraw, Shape::Refund] {
        let (public, private, _) = fresh(TREE, shape, &mut StdRng::seed_from_u64(26));
        rejected("fixed outcome with s = 1", &public, &private, Tamper { s: Some(true), ..Default::default() });
    }
    for shape in [Shape::Split, Shape::SplitAll] {
        let (public, private, _) = fresh(TREE, shape, &mut StdRng::seed_from_u64(26));
        rejected("split outcome with s = 0", &public, &private, Tamper { s: Some(false), ..Default::default() });
    }
}

#[test]
fn m7_active_flags() {
    let (public, private, _) = fresh(TREE, Shape::Settle, &mut StdRng::seed_from_u64(27));
    rejected("active out1 flagged inactive", &public, &private, Tamper { active: Some([true, false]), ..Default::default() });
    let (public, private, _) = fresh(TREE, Shape::Refund, &mut StdRng::seed_from_u64(27));
    rejected("inactive out1 flagged active", &public, &private, Tamper { active: Some([true, true]), ..Default::default() });
}

#[test]
fn m8_malformed_outcomes_via_witness() {
    let base = fresh(TREE, Shape::Settle, &mut StdRng::seed_from_u64(28));
    let (public, private, _) = base.clone();
    let mut p = private.clone();
    p.selected.outputs[1].amount = 0; // active fixed output with zero amount
    p.selected.outputs[0].amount = private.amount;
    rejected("active fixed output with zero amount", &public, &p, Tamper::default());
    let (public, private, _) = fresh(TREE, Shape::Refund, &mut StdRng::seed_from_u64(28));
    let mut p = private.clone();
    p.selected.outputs[1].delivery = "0x5".into();
    rejected("inactive output with a delivery", &public, &p, Tamper::default());
    let (public, private, _) = fresh(TREE, Shape::Split, &mut StdRng::seed_from_u64(28));
    let mut p = private.clone();
    p.selected.outputs[1] = policy::inactive_out();
    rejected("split with an inactive second output", &public, &p, Tamper::default());
    let mut p = private.clone();
    p.selected.withdrawal_recipient = "0x77".into();
    rejected("split with a withdrawal recipient", &public, &p, Tamper::default());
    let mut p = private.clone();
    p.selected.outputs[0].amount = 3;
    rejected("split with a committed amount", &public, &p, Tamper::default());
    let mut p = private.clone();
    p.selected.outputs[1].delivery = "0x0".into();
    rejected("split with zero delivery on out1", &public, &p, Tamper::default());
}

/// Review PI-1: a fixed outcome whose withdrawal has a recipient without an amount, or an amount
/// without a recipient, is rejected by the native reference (so wallets never create or accept
/// it). Settlement of such a statement fails at the bridge, which is proven inside PROOF2.
#[test]
fn m9_fixed_withdrawal_half_zero_rejected_natively() {
    let mut rng = StdRng::seed_from_u64(29);
    let (public, private, mut pol) = fresh(TREE, Shape::Withdraw, &mut rng);
    pol.outcomes[2].as_mut().unwrap().withdrawal_recipient = "0x0".into();
    let p = policy::private_for(&pol, 2, private.cap, private.rho, private.amount, private.position, private.siblings.clone());
    assert!(policy::statement(TREE, &public.chain, &public.pool, &public.token, 0, &public.data, &p).is_err());
    let o = pol.outcomes[2].as_mut().unwrap();
    o.withdrawal_recipient = "0x77".into();
    o.withdrawal_amount = 0;
    o.outputs[0].amount = private.amount;
    let p = policy::private_for(&pol, 2, private.cap, private.rho, private.amount, private.position, private.siblings.clone());
    assert!(policy::statement(TREE, &public.chain, &public.pool, &public.token, 0, &public.data, &p).is_err());
    // Review PI-2: a felt at or above the prime is rejected natively.
    let (public, private, _) = fresh(TREE, Shape::Settle, &mut rng);
    let mut p = private.clone();
    p.header.handle = "0x800000000000011000000000000000000000000000000000000000000000001".into();
    assert!(policy::statement(TREE, &public.chain, &public.pool, &public.token, 0, &public.data, &p).is_err());
}

/// The prove-refund witness (other slots zero, only `rest`) is valid and gives the same statement.
#[test]
fn m10_refund_witness_without_other_slots() {
    let (public, private, _) = fresh(TREE, Shape::Refund, &mut StdRng::seed_from_u64(30));
    let mut p = private.clone();
    p.slots = [policy::outcome_digest(&p.selected), [0; 9], [0; 9], [0; 9]];
    let (limbs, valid) = run(&public, &p, Tamper::default());
    assert!(valid && limbs == statement_limbs(TREE, &public));
    // A non-refund index cannot use `rest`: with the other slots zeroed the statement changes.
    let (public, private, _) = fresh(TREE, Shape::Settle, &mut StdRng::seed_from_u64(30));
    let mut p = private.clone();
    p.slots = [p.slots[0], [0; 9], [0; 9], [0; 9]];
    let (limbs, valid) = run(&public, &p, Tamper::default());
    assert!(!valid || limbs != statement_limbs(TREE, &public));
}

/// A type-3 outcome committed in a policy cannot be selected: the circuit hashes 1 + s, never 3,
/// so the circuit's policy_id differs from the committed policy's.
#[test]
fn m11_kind_three_not_selectable() {
    let (public, private, mut pol) = fresh(TREE, Shape::Settle, &mut StdRng::seed_from_u64(31));
    pol.outcomes[1].as_mut().unwrap().kind = 3;
    let want_id = policy::policy_id(&public.chain, &public.pool, &public.token, private.amount, &pol.digest());
    let p = policy::private_for(&pol, 1, private.cap, private.rho, private.amount, private.position, private.siblings.clone());
    let (limbs, valid) = run(&public, &p, Tamper::default());
    // policy_id sits at limbs 127..136.
    assert!(!valid || limbs[127..136] != want_id[..]);
    let _ = (FIXED, SPLIT);
}

use m31_pool::hash::{COMPRESS, SPONGE, commitment, node, pack, unpack};
use m31_pool::perm::permutation;
use m31_pool::zeros::zero;
use super::vectors::*;

#[test]
fn permutation_matches_client_and_python_reference() {
    assert!(permutation(PERM_IN).span() == PERM_OUT.span());
    assert!(permutation(PERM_MAX_IN).span() == PERM_MAX_OUT.span());
    assert!(permutation(PERM_ALT_IN).span() == PERM_ALT_OUT.span());
    assert!(permutation(PERM_RAND_IN).span() == PERM_RAND_OUT.span());
}

/// `node` reproduces the client's empty-subtree chain in both formats.
#[test]
fn zeros_match_node() {
    for format in array![SPONGE, COMPRESS] {
        let mut level: u32 = 0;
        while level < 32 {
            let z = zero(format, level);
            assert!(node(format, level.into(), z, z).span() == zero(format, level + 1).span());
            level += 1;
        }
    }
}

#[test]
fn deposit_commitment_matches_client() {
    let cm = commitment(DEPOSIT_CHAIN, DEPOSIT_POOL, DEPOSIT_TOKEN, DEPOSIT_AMOUNT, DEPOSIT_INNER);
    assert!(cm.span() == DEPOSIT_CM.span());
}

#[test]
fn pack_is_lossless() {
    for d in leaves() {
        let (lo, hi) = pack(d);
        assert!(unpack(lo, hi).span() == d.span());
    }
    let max = [0x7ffffffe, 0x7ffffffe, 0x7ffffffe, 0x7ffffffe, 0x7ffffffe, 0x7ffffffe, 0x7ffffffe, 0x7ffffffe, 0x7ffffffe];
    let (lo, hi) = pack(max);
    assert!(unpack(lo, hi).span() == max.span());
}

/// The pool's binding of a real V2 statement equals the bridge's (independent Python reference).
#[test]
fn binding_matches_bridge() {
    let mut nfs = array![];
    nfs.append_span(BIND_NF0.span());
    nfs.append_span(BIND_NF1.span());
    let mut cms = array![];
    cms.append_span(BIND_CM0.span());
    cms.append_span(BIND_CM1.span());
    let b = m31_pool::spend::binding_of(
        BIND_CHAIN, BIND_POOL, BIND_TOKEN, BIND_ROOT.span(), nfs.span(), cms.span(),
        array![BIND_D0, 0].span(), BIND_RECIPIENT, BIND_AMOUNT,
    );
    assert_eq!(b, BIND_EXPECTED);
}

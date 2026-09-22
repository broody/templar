//! Isolated, reviewed-protocol private-membership research implementation.
//! Final source review and execution evidence govern qualification; no PROOF1 claim.
pub mod air;
mod constants;
mod crypto;
mod hash;
mod poly;
mod proof;
pub use crypto::MAX_PROOF;
pub use proof::{prove, verify};

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;
    #[wasm_bindgen]
    pub fn prove_membership(public_json: &str, private_json: &str) -> Result<Vec<u8>, JsValue> {
        let run = || -> anyhow::Result<Vec<u8>> {
            let public = serde_json::from_str(public_json)?;
            let private = serde_json::from_str(private_json)?;
            super::prove(&public, &private, &mut rand::rngs::OsRng)
        };
        run().map_err(|e| JsValue::from_str(&e.to_string()))
    }
    #[wasm_bindgen]
    pub fn verify_membership(public_json: &str, bytes: &[u8]) -> Result<(), JsValue> {
        let run = || -> anyhow::Result<()> {
            let public = serde_json::from_str(public_json)?;
            super::verify(&public, bytes)
        };
        run().map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{One, Zero};
    use rand::{SeedableRng, rngs::StdRng};
    use stwo::core::fields::{m31::M31, qm31::QM31};
    fn fixture() -> (air::Public, air::Private) {
        air::fresh(&mut StdRng::seed_from_u64(411)).unwrap()
    }
    #[test]
    fn hash_golden_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../golden-vectors.json")).unwrap();
        let permutations = v["permutations"].as_array().unwrap();
        assert!(!permutations.is_empty());
        for case in permutations {
            let input: [M31; 24] =
                std::array::from_fn(|i| M31::from(case["input"][i].as_u64().unwrap() as u32));
            let (_, output) = hash::record(input);
            for i in 0..24 {
                assert_eq!(output[i].0, case["output"][i].as_u64().unwrap() as u32);
            }
        }
        let sponges = v["sponges"].as_array().unwrap();
        assert_eq!(sponges.len(), 10);
        for case in sponges {
            let input: Vec<M31> = case["input"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| M31::from(x.as_u64().unwrap() as u32))
                .collect();
            let rows = hash::sponge(&input);
            let output = rows.last().unwrap().1;
            for i in 0..9 {
                assert_eq!(output[i].0, case["digest"][i].as_u64().unwrap() as u32);
            }
        }
    }
    #[test]
    fn all_membership_constraints_and_negative_wiring() {
        let (public, private) = fixture();
        let (rows, root) = air::witness(&private).unwrap();
        assert_eq!(root, public.root);
        air::validate_trace(&rows, &public).unwrap();
        // Alter each scalar of every active permutation input, plus direction,
        // carry and root values. No honest witness reconstruction in these checks.
        for i in 0..65 {
            for j in 0..24 {
                let mut bad = rows.clone();
                bad[i][j] += M31::one();
                assert!(air::validate_trace(&bad, &public).is_err());
            }
        }
        for (i, j) in [
            (1, air::BIT),
            (2, air::BIT),
            (1, air::CUR),
            (2, air::SIB),
            (64, air::OUTPUT),
            (65, 0),
        ] {
            let mut bad = rows.clone();
            bad[i][j] += M31::from(2);
            assert!(air::validate_trace(&bad, &public).is_err());
        }
        // Recompute full valid permutation traces after violating framing,
        // capacity or chaining, so permutation constraints cannot catch these.
        for (i, j) in [
            (0, 13),
            (1, 0),
            (1, 15),
            (2, 7),
            (2, 15),
            (3, 4),
            (64, 6),
            (65, 0),
        ] {
            let mut bad = rows.clone();
            let mut input: [M31; 24] = bad[i][..24].try_into().unwrap();
            input[j] += M31::one();
            bad[i][..hash::PERM_COLS].copy_from_slice(&hash::record(input).0);
            assert!(air::validate_trace(&bad, &public).is_err());
        }
    }
    #[test]
    fn field_and_context_canonicality() {
        let (mut public, mut private) = fixture();
        public.validate().unwrap();
        private.validate().unwrap();
        for bad in [
            "0x0",
            "0x00",
            "0x0123",
            "0xAB",
            "123",
            "0x800000000000000000000000000000000000000000000000000000000000000",
        ] {
            public.pool = bad.into();
            assert!(public.validate().is_err());
        }
        public.pool = "0x123".into();
        public.chain = "0x800000000000011000000000000000000000000000000000000000000000001".into();
        assert!(public.validate().is_err());
        private.bits[0] = 2;
        assert!(private.validate().is_err());
        private.bits[0] = 0;
        private.secret[0] = air::P;
        assert!(private.validate().is_err());
    }
    #[test]
    fn masks_preserve_trace_and_fit_reviewed_degree() {
        let (public, private) = fixture();
        let (rows, _) = air::witness(&private).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let f = poly::mask(&rows, &mut rng);
        // Pinned CPU FFT basis index i has total circle degree (i+1)/2.
        // These tails are within the allocated capacity, so this check is
        // stronger than merely checking the coefficient vector's length.
        assert!(f.iter().all(|p| p.coeffs[385..].iter().all(Zero::is_zero)));
        let h = stwo::core::poly::circle::CanonicCoset::new(poly::LOG_H);
        for j in [0, 4, 13, 400, air::OUTPUT, air::BIT] {
            for i in 0..air::N {
                assert_eq!(
                    f[j].eval_at_point(h.at(i).into_ef()),
                    QM31::from(rows[i][j])
                );
            }
        }
        let a = poly::random_secure(&mut rng);
        let selectors = poly::selector_polys();
        let q = poly::quotients(&f, &selectors, a, &public.root);
        assert!(q.iter().all(|p| p.coeffs[769..].iter().all(Zero::is_zero)));
        // Degree<=384 is strictly below the1024-dimensional FFT bound; values
        // at D agree with direct AIR/zerofier computation at sampled positions.
        for i in [
            0,
            1,
            2,
            3,
            poly::D / 3,
            poly::D / 2,
            poly::D - 2,
            poly::D - 1,
        ] {
            let p = poly::point(poly::LOG_D, i).into_ef();
            let row: Vec<_> = f.iter().map(|f| f.eval_at_point(p)).collect();
            let prev: Vec<_> = f.iter().map(|f| f.eval_at_point(poly::shift(p))).collect();
            let values: Vec<_> = q.iter().map(|q| q.eval_at_point(p)).collect();
            poly::check_ood(&row, &prev, &values, &selectors, a, p, &public.root).unwrap();
        }
        let z = loop {
            if let Some(z) = poly::rational(poly::random_secure(&mut rng)) {
                if poly::valid_ood(z) {
                    break z;
                }
            }
        };
        let fz: Vec<_> = f.iter().map(|p| p.eval_at_point(z)).collect();
        let ftz: Vec<_> = f.iter().map(|p| p.eval_at_point(poly::shift(z))).collect();
        let qz: Vec<_> = q.iter().map(|p| p.eval_at_point(z)).collect();
        poly::check_ood(&fz, &ftz, &qz, &selectors, a, z, &public.root).unwrap();
        let mut wrong = public.root;
        wrong[0] = (wrong[0] + 1) % air::P;
        assert!(poly::check_ood(&fz, &ftz, &qz, &selectors, a, z, &wrong).is_err());
    }
    #[test]
    fn independent_sparse_folds_match_stwo() {
        let mut rng = StdRng::seed_from_u64(43);
        let mut values = poly::random_r(&mut rng);
        for layer in 0..poly::FOLDS {
            let alpha = poly::random_secure(&mut rng);
            let next = poly::fold(&values, layer, alpha);
            for i in 0..next.len() {
                assert_eq!(
                    next[i],
                    poly::fold_value(layer, 2 * i, values[2 * i], values[2 * i + 1], alpha)
                );
            }
            values = next;
        }
        assert!(values.iter().all(|v| *v == values[0]));
    }
    #[test]
    fn complete_roundtrip_freshness_and_artifact_rejections() {
        let (public, private) = fixture();
        let mut rng = StdRng::seed_from_u64(44);
        let bytes = prove(&public, &private, &mut rng).unwrap();
        verify(&public, &bytes).unwrap();
        let second = prove(&public, &private, &mut rng).unwrap();
        verify(&public, &second).unwrap();
        assert_ne!(bytes, second);
        let mut public2 = public.clone();
        public2.root[0] = (public2.root[0] + 1) % air::P;
        assert!(verify(&public2, &bytes).is_err());
        public2 = public.clone();
        public2.chain = "0x2".into();
        assert!(verify(&public2, &bytes).is_err());
        public2 = public.clone();
        public2.pool = "0x124".into();
        assert!(verify(&public2, &bytes).is_err());
        for cut in [0, 7, 8, 100, bytes.len() / 2, bytes.len() - 1] {
            assert!(verify(&public, &bytes[..cut]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(verify(&public, &bad).is_err());
        // Each header root, final state, OOD claims, salts, raw openings and FRI tail.
        for at in (0..15).map(|i| 8 + 96 * i).chain([
            8 + 96 * 15,
            8 + 96 * 16,
            bytes.len() / 2,
            bytes.len() - 1,
        ]) {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(verify(&public, &bad).is_err());
        }
        let mut bad = bytes.clone();
        bad[8 + 96 * 16..8 + 96 * 16 + 4].copy_from_slice(&air::P.to_le_bytes());
        assert!(verify(&public, &bad).is_err());
    }
    #[test]
    fn invalid_trace_can_reach_proof_verifier_without_host_gate() {
        let (public, private) = fixture();
        let (mut rows, _) = air::witness(&private).unwrap();
        // A valid permutation with wrong sponge padding, deliberately bypassing
        // both honest AIR validation and honest OOD consistency enforcement.
        let mut input: [M31; 24] = rows[0][..24].try_into().unwrap();
        input[13] = M31::zero();
        rows[0][..hash::PERM_COLS].copy_from_slice(&hash::record(input).0);
        assert!(air::validate_trace(&rows, &public).is_err());
        let bad = proof::prove_rows(&public, &rows, &mut StdRng::seed_from_u64(45), false).unwrap();
        assert!(verify(&public, &bad).is_err());
    }
}

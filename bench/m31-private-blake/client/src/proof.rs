use crate::{
    air::{self, Private, Public, W},
    crypto::{self, Digest, Reader, Transcript, Tree},
    poly::{self, D, FOLDS, LOG_D, Pair, Point},
};
use anyhow::{Result, ensure};
use num_traits::Zero;
use rand::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use stwo::core::fields::{m31::M31, qm31::QM31};

const ROOTS: usize = 4 + FOLDS + 1;
const MAGIC: &[u8; 8] = b"TMPZK002";
pub fn public_bytes(public: &Public) -> Result<Vec<u8>> {
    public.validate()?;
    let circuit = crypto::ro(
        b"circuit",
        &[
            include_bytes!("air.rs"),
            include_bytes!("hash.rs"),
            include_bytes!("constants.rs"),
            include_bytes!("poly.rs"),
            include_bytes!("crypto.rs"),
            include_bytes!("proof.rs"),
        ],
    );
    let mut bytes = MAGIC.to_vec();
    bytes.extend(circuit);
    bytes.extend(serde_json::to_vec(public)?);
    Ok(bytes)
}
fn batch_at(
    row: &[M31],
    q: &[M31],
    r: QM31,
    claims: &[QM31],
    z: Point,
    lambda: QM31,
    p: Point,
) -> QM31 {
    let mut out = r;
    let mut power = lambda;
    let tz = poly::shift(z);
    for i in 0..W {
        let f = QM31::from(row[i]);
        for v in [
            f,
            Pair::new(z, claims[i]).at(p, f),
            Pair::new(tz, claims[W + i]).at(p, f),
        ] {
            out += power * v;
            power *= lambda;
        }
    }
    for i in 0..4 {
        let f = QM31::from(q[i]);
        for v in [f, Pair::new(z, claims[2 * W + i]).at(p, f)] {
            out += power * v;
            power *= lambda;
        }
    }
    out
}
fn batch(base: &Tree, q: &Tree, r: &[QM31], claims: &[QM31], z: Point, lambda: QM31) -> Vec<QM31> {
    // Collect equal-denominator DEEP terms before division. This is exactly
    // batch_at's positive-power order, checked differentially in tests.
    let tz = poly::shift(z);
    let mut power = lambda;
    let mut raw = vec![QM31::zero(); D];
    let mut kz = raw.clone();
    let mut kt = raw.clone();
    let (mut az, mut bz, mut at, mut bt) = (QM31::zero(), QM31::zero(), QM31::zero(), QM31::zero());
    let zeroz = Pair::new(z, QM31::zero());
    let zerot = Pair::new(tz, QM31::zero());
    for col in 0..W {
        let weights = [power, power * lambda, power * lambda * lambda];
        power *= lambda * lambda * lambda;
        let a = Pair::new(z, claims[col]);
        let b = Pair::new(tz, claims[W + col]);
        az += weights[1] * a.a;
        bz += weights[1] * a.b;
        at += weights[2] * b.a;
        bt += weights[2] * b.b;
        for i in 0..D {
            let v = base.columns[col][i];
            raw[i] += weights[0] * v;
            kz[i] += weights[1] * v;
            kt[i] += weights[2] * v;
        }
    }
    for col in 0..4 {
        let weights = [power, power * lambda];
        power *= lambda * lambda;
        let a = Pair::new(z, claims[2 * W + col]);
        az += weights[1] * a.a;
        bz += weights[1] * a.b;
        for i in 0..D {
            let v = q.columns[col][i];
            raw[i] += weights[0] * v;
            kz[i] += weights[1] * v;
        }
    }
    (0..D)
        .map(|i| {
            let p = poly::point(LOG_D, i).into_ef();
            r[i] + raw[i]
                + (zeroz.c * kz[i] - az * p.y - bz) / zeroz.denominator(p)
                + (zerot.c * kt[i] - at * p.y - bt) / zerot.denominator(p)
        })
        .collect()
}
fn trace_queries(q: &[usize]) -> Vec<usize> {
    let prev = poly::previous_indices(LOG_D);
    q.iter()
        .flat_map(|i| [*i, prev[*i]])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn fri_queries(q: &[usize], layer: usize) -> Vec<usize> {
    q.iter()
        .flat_map(|i| {
            let j = i >> layer;
            [j & !1, (j & !1) + 1]
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
/// Use fresh, independent cryptographic randomness for every proof. Never reset
/// or clone an RNG state across proofs. The native CLI and WASM API use OsRng.
pub fn prove(
    public: &Public,
    private: &Private,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    let (rows, root) = air::witness(private)?;
    ensure!(root == public.root, "witness root mismatch");
    prove_rows(public, &rows, rng, true)
}
pub(crate) fn prove_rows(
    public: &Public,
    rows: &[Vec<M31>],
    rng: &mut impl RngCore,
    check_trace: bool,
) -> Result<Vec<u8>> {
    if check_trace {
        air::validate_trace(rows, public)?;
    }
    let mut ch = Transcript::new(public_bytes(public)?);
    let selectors = poly::selector_polys();
    let f = poly::mask(rows, rng);
    let base = Tree::new(f.iter().map(|p| poly::eval(p, LOG_D)).collect(), 0, rng);
    ch.commit(&base.root());
    let alpha = ch.coins().field()?;
    let qs = poly::quotients(&f, &selectors, alpha, &public.root);
    let q = Tree::new(qs.iter().map(|p| poly::eval(p, LOG_D)).collect(), 1, rng);
    ch.commit(&q.root());
    let z = ch.coins().ood()?;
    let tz = poly::shift(z);
    let mut claims: Vec<_> = f.iter().map(|p| p.eval_at_point(z)).collect();
    claims.extend(f.iter().map(|p| p.eval_at_point(tz)));
    claims.extend(qs.iter().map(|p| p.eval_at_point(z)));
    if check_trace {
        poly::check_ood(
            &claims[..W],
            &claims[W..2 * W],
            &claims[2 * W..],
            &selectors,
            alpha,
            z,
            &public.root,
        )?;
    }
    let claim_values: Vec<M31> = claims.iter().flat_map(|x| x.to_m31_array()).collect();
    let claim_tree = Tree::new(claim_values.iter().map(|v| vec![*v]).collect(), 2, rng);
    ch.commit(&claim_tree.root());
    let rv = poly::random_r(rng);
    let r = Tree::new(crypto::secure_columns(&rv), 3, rng);
    ch.commit(&r.root());
    let lambda = ch.coins().field()?;
    let mut current = batch(&base, &q, &rv, &claims, z, lambda);
    #[cfg(test)]
    for i in [0, 1, 2, 3, D / 3, D / 2, D - 2, D - 1] {
        let reference = batch_at(
            &base.columns.iter().map(|c| c[i]).collect::<Vec<_>>(),
            &q.columns.iter().map(|c| c[i]).collect::<Vec<_>>(),
            rv[i],
            &claims,
            z,
            lambda,
            poly::point(LOG_D, i).into_ef(),
        );
        assert!(current[i] == reference, "batch differential mismatch");
    }
    let mut fri = vec![];
    for layer in 0..FOLDS {
        let tree = Tree::new(crypto::secure_columns(&current), (4 + layer) as u32, rng);
        ch.commit(&tree.root());
        let challenge = ch.coins().field()?;
        current = poly::fold(&current, layer, challenge);
        fri.push(tree);
    }
    ensure!(
        current.len() == D >> FOLDS && current.iter().all(|v| *v == current[0]),
        "FRI final degree"
    );
    let last = Tree::new(
        crypto::secure_columns(&current[..1]),
        (ROOTS - 1) as u32,
        rng,
    );
    ch.commit(&last.root());
    let queries = ch.coins().queries();
    let mut out = MAGIC.to_vec();
    for tree in [&base, &q, &claim_tree, &r]
        .into_iter()
        .chain(fri.iter())
        .chain(std::iter::once(&last))
    {
        out.extend(tree.root());
    }
    out.extend(ch.sigma);
    claim_tree.open(0, &mut out);
    last.open(0, &mut out);
    for i in trace_queries(&queries) {
        base.open(i, &mut out);
    }
    for i in &queries {
        q.open(*i, &mut out);
    }
    for i in &queries {
        r.open(*i, &mut out);
    }
    for (layer, t) in fri.iter().enumerate() {
        for i in fri_queries(&queries, layer) {
            t.open(i, &mut out);
        }
    }
    ensure!(out.len() <= crypto::MAX_PROOF, "proof output size");
    Ok(out)
}
pub fn verify(public: &Public, bytes: &[u8]) -> Result<()> {
    let mut rd = Reader::new(bytes)?;
    ensure!(&rd.take::<8>()? == MAGIC, "proof version");
    let roots: Vec<Digest> = (0..ROOTS).map(|_| rd.take()).collect::<Result<_>>()?;
    let final_sigma = rd.take::<{ crypto::HASH }>()?;
    let mut ch = Transcript::new(public_bytes(public)?);
    ch.commit(&roots[0]);
    let alpha = ch.coins().field()?;
    ch.commit(&roots[1]);
    let z = ch.coins().ood()?;
    let claims =
        crypto::secure_values(&crypto::open(&mut rd, 2, &roots[2], 0, 1, 4 * (2 * W + 4))?);
    poly::check_ood(
        &claims[..W],
        &claims[W..2 * W],
        &claims[2 * W..],
        &poly::selector_polys(),
        alpha,
        z,
        &public.root,
    )?;
    ch.commit(&roots[2]);
    ch.commit(&roots[3]);
    let lambda = ch.coins().field()?;
    let mut challenges = vec![];
    for layer in 0..FOLDS {
        ch.commit(&roots[4 + layer]);
        challenges.push(ch.coins().field()?);
    }
    let last = QM31::from_m31_array(
        crypto::open(&mut rd, (ROOTS - 1) as u32, &roots[ROOTS - 1], 0, 1, 4)?
            .try_into()
            .unwrap(),
    );
    ch.commit(&roots[ROOTS - 1]);
    ensure!(ch.sigma == final_sigma, "transcript state");
    let queries = ch.coins().queries();
    let mut base = BTreeMap::new();
    for i in trace_queries(&queries) {
        base.insert(i, crypto::open(&mut rd, 0, &roots[0], i, D, W)?);
    }
    let mut q = BTreeMap::new();
    for i in &queries {
        q.insert(*i, crypto::open(&mut rd, 1, &roots[1], *i, D, 4)?);
    }
    let mut expected = BTreeMap::new();
    for i in &queries {
        let r = QM31::from_m31_array(
            crypto::open(&mut rd, 3, &roots[3], *i, D, 4)?
                .try_into()
                .unwrap(),
        );
        expected.insert(
            *i,
            batch_at(
                &base[i],
                &q[i],
                r,
                &claims,
                z,
                lambda,
                poly::point(LOG_D, *i).into_ef(),
            ),
        );
    }
    for layer in 0..FOLDS {
        let mut values = BTreeMap::new();
        for i in fri_queries(&queries, layer) {
            let v = QM31::from_m31_array(
                crypto::open(
                    &mut rd,
                    (4 + layer) as u32,
                    &roots[4 + layer],
                    i,
                    D >> layer,
                    4,
                )?
                .try_into()
                .unwrap(),
            );
            values.insert(i, v);
        }
        let mut next = BTreeMap::new();
        for (i, v) in expected {
            ensure!(values.get(&i) == Some(&v), "FRI layer {layer} consistency");
            let pair = i & !1;
            let folded = poly::fold_value(
                layer,
                pair,
                values[&pair],
                values[&(pair + 1)],
                challenges[layer],
            );
            if let Some(old) = next.insert(i >> 1, folded) {
                ensure!(old == folded, "duplicate fold inconsistency");
            }
        }
        expected = next;
    }
    ensure!(expected.values().all(|v| *v == last), "FRI final constant");
    rd.finish()
}

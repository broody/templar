//! Golden vectors for the option-A pool (bench/m31-pool): the permutation, the empty-subtree
//! digests and roots after successive appends for both node formats, and a deposit commitment.
//! Roots are computed twice, by an incremental frontier (the pool's algorithm) and by hashing the
//! full tree level by level, and must agree.
use serde_json::json;
use stwo::core::fields::m31::M31;
use templar_client_verifier_circuit::membership::permute;
use templar_client_verifier_circuit::payment::{self, DEPTH, Digest, INNER, NOTE, Tree, amount_limbs, felt_limbs, h, node};

fn zeros(tree: Tree) -> Vec<Digest> {
    let mut z = vec![[0u32; 9]];
    for level in 0..DEPTH {
        let last = *z.last().unwrap();
        z.push(node(tree, level as u32, &last, &last));
    }
    z
}

/// The pool's frontier append: returns the new root.
fn append(tree: Tree, zeros: &[Digest], frontier: &mut [Digest], count: u64, leaf: Digest) -> Digest {
    let mut cur = leaf;
    let mut index = count;
    for level in 0..DEPTH {
        if index & 1 == 0 {
            frontier[level] = cur;
            cur = node(tree, level as u32, &cur, &zeros[level]);
        } else {
            cur = node(tree, level as u32, &frontier[level], &cur);
        }
        index >>= 1;
    }
    cur
}

/// Root of the tree holding `leaves` at 0..n, by hashing every level (independent of `append`).
fn full_root(tree: Tree, zeros: &[Digest], leaves: &[Digest]) -> Digest {
    let mut level_nodes = leaves.to_vec();
    for level in 0..DEPTH {
        let mut next = vec![];
        for pair in level_nodes.chunks(2) {
            let r = if pair.len() == 2 { pair[1] } else { zeros[level] };
            next.push(node(tree, level as u32, &pair[0], &r));
        }
        if next.is_empty() {
            next.push(zeros[level + 1]);
        }
        level_nodes = next;
    }
    level_nodes[0]
}

fn main() {
    let input: [M31; 24] = std::array::from_fn(|i| M31::from(((i as u64 * 0x1234567 + 89) % ((1 << 31) - 1)) as u32));
    let perm = permute(input);
    let mut leaves: Vec<Digest> = vec![];
    let mut seed: u64 = 0x5eed;
    for _ in 0..6 {
        leaves.push(std::array::from_fn(|_| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((seed >> 33) % payment::P as u64) as u32
        }));
    }
    let mut formats = serde_json::Map::new();
    for tree in [Tree::Sponge, Tree::Compress] {
        let z = zeros(tree);
        let mut frontier = vec![[0u32; 9]; DEPTH];
        let mut roots = vec![];
        for (n, leaf) in leaves.iter().enumerate() {
            let root = append(tree, &z, &mut frontier, n as u64, *leaf);
            assert_eq!(root, full_root(tree, &z, &leaves[..=n]), "{tree:?} frontier root {n}");
            roots.push(root);
        }
        formats.insert(format!("{tree:?}"), json!({"zeros": z, "roots": roots}));
    }
    // Deposit: the pool computes cm = H(NOTE, chain ‖ pool ‖ token ‖ amount₈ ‖ inner) on chain.
    let (chain, pool, token) = ("0x534e5f5345504f4c4941", "0x1234", "0x5678");
    let amount: u128 = 123_456_789_012_345_678_901;
    let inner = h(INNER, 0, &[[7u32; 9], [9u32; 9]].concat());
    let context = [felt_limbs(chain), felt_limbs(pool), felt_limbs(token)].concat();
    let cm = h(NOTE, 0, &[context.clone(), amount_limbs(amount).to_vec(), inner.to_vec()].concat());
    let out = json!({
        "permutation": {"input": input.map(|m| m.0), "output": perm.map(|m| m.0)},
        "leaves": leaves,
        "formats": formats,
        "deposit": {"chain": chain, "pool": pool, "token": token, "amount": amount.to_string(), "inner": inner, "commitment": cm},
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

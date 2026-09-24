//! The pool's depth-32 note tree, kept locally from every published leaf (spec §5): append,
//! truncate (reorgs), root and membership paths, matching the pool's `Tree::Compress` nodes.
use templar_client_verifier_circuit::payment::{self, DEPTH, Tree as Format};

use crate::{Digest, Error, Result};

const FORMAT: Format = Format::Compress;

pub struct Tree {
    /// `levels[0]` are the leaves; `levels[k]` the nodes at height `k` that have a nonempty left
    /// child (the last one may have an empty right subtree).
    levels: Vec<Vec<Digest>>,
    zeros: Vec<Digest>,
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree {
    pub fn new() -> Tree {
        let mut zeros = vec![[0u32; 9]];
        for level in 0..DEPTH {
            let z = zeros[level];
            zeros.push(payment::node(FORMAT, level as u32, &z, &z));
        }
        Tree { levels: vec![vec![]; DEPTH + 1], zeros }
    }

    pub fn len(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    fn child(&self, level: usize, index: usize) -> Digest {
        self.levels[level].get(index).copied().unwrap_or(self.zeros[level])
    }

    /// Recomputes the ancestors of leaf `index`.
    fn update(&mut self, mut index: usize) {
        for level in 0..DEPTH {
            let parent = index / 2;
            let node = payment::node(FORMAT, level as u32, &self.child(level, 2 * parent), &self.child(level, 2 * parent + 1));
            let up = &mut self.levels[level + 1];
            if parent < up.len() {
                up[parent] = node;
            } else {
                up.push(node);
            }
            index = parent;
        }
    }

    pub fn append(&mut self, leaves: &[Digest]) -> Result<()> {
        if self.len() + leaves.len() as u64 > 1u64 << DEPTH {
            return Err(Error::input("tree full"));
        }
        for leaf in leaves {
            self.levels[0].push(*leaf);
            let i = self.levels[0].len() - 1;
            self.update(i);
        }
        Ok(())
    }

    /// Keeps the first `n` leaves (a reorg rollback).
    pub fn truncate(&mut self, n: u64) {
        if n >= self.len() {
            return;
        }
        let mut count = n as usize;
        for level in 0..=DEPTH {
            self.levels[level].truncate(count);
            count = count.div_ceil(2);
        }
        if n > 0 {
            self.update(n as usize - 1);
        }
    }

    pub fn root(&self) -> Digest {
        self.levels[DEPTH].first().copied().unwrap_or(self.zeros[DEPTH])
    }

    /// The 32 siblings of leaf `position`, from the leaf up.
    pub fn path(&self, position: u64) -> Result<Vec<Digest>> {
        if position >= self.len() {
            return Err(Error::input("no leaf at that position"));
        }
        let mut index = position as usize;
        Ok((0..DEPTH)
            .map(|level| {
                let s = self.child(level, index ^ 1);
                index /= 2;
                s
            })
            .collect())
    }

    pub fn leaf(&self, position: u64) -> Option<Digest> {
        self.levels[0].get(position as usize).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_relation() {
        let leaves: Vec<Digest> = (1..=13u32).map(|i| [i, i + 1, 3, 4, 5, 6, 7, 8, 9]).collect();
        let mut t = Tree::new();
        assert_eq!(t.root(), payment::tree_paths(FORMAT, &[], &[]).0);
        for (n, l) in leaves.iter().enumerate() {
            t.append(&[*l]).unwrap();
            let (root, paths) = payment::tree_paths(FORMAT, &leaves[..=n], &[0, n as u32]);
            assert_eq!(t.root(), root);
            assert_eq!(t.path(0).unwrap(), paths[0]);
            assert_eq!(t.path(n as u64).unwrap(), paths[1]);
        }
        for n in [12u64, 7, 4, 1, 0] {
            t.truncate(n);
            let (root, _) = payment::tree_paths(FORMAT, &leaves[..n as usize], &[]);
            assert_eq!(t.root(), root, "truncate to {n}");
        }
        t.append(&leaves[..5]).unwrap();
        assert_eq!(t.root(), payment::tree_paths(FORMAT, &leaves[..5], &[]).0);
        assert_eq!(payment::climb(FORMAT, &leaves[3], 3, &t.path(3).unwrap()), t.root());
    }
}

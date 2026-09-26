//! The pool V3 note tree (`docs/account-bound-note-spec.md` §8.3): `tree.cairo`'s depth-32
//! append-only Poseidon2-M31 tree, fixed to the compress node format (F30), with roots accepted by
//! block height instead of a 256-root ring (F02):
//! - the current root is always accepted, so a quiet pool never freezes;
//! - when an append replaces root `R`, the tree records the block that replaced it;
//! - `R` is then accepted while `block_number − that block ≤ W`, so deposits cannot age it out early;
//! - a root never recorded is unknown.
//! `superseded_at[key(R)]` stores the replacing block plus one, so that 0 always means "never
//! replaced", also at block 0. Storage modes (nodes, frontier) and `insert_two` are `tree.cairo`'s.

pub const TREE_DEPTH: u32 = 32;

#[starknet::interface]
pub trait IM31TreeV3<TState> {
    fn get_root(self: @TState) -> Span<felt252>;
    fn get_leaf_count(self: @TState) -> u64;
    /// Whether a spend may use `root` in this block (§8.3).
    fn root_is_known(self: @TState, root: Span<felt252>) -> bool;
    /// The block that replaced `root`, plus one; 0 if it was never replaced (or never recorded).
    fn get_root_superseded_at(self: @TState, root: Span<felt252>) -> u64;
    /// Stored node, or the empty-subtree digest for its level (nodes mode only).
    fn get_node(self: @TState, level: u32, index: u64) -> Span<felt252>;
}

/// `zeros::zero(COMPRESS, level)`: the compress tree's empty-subtree digests only (F30).
pub fn zero_c(level: u32) -> crate::hash::Digest {
    match level {
        0 => [0, 0, 0, 0, 0, 0, 0, 0, 0],
        1 => [1306867194, 120269754, 1951411018, 284574019, 494546055, 1410872083, 781636342, 1341718767, 2058878658],
        2 => [1970943543, 29634903, 1958983748, 1603236154, 2040049783, 542134675, 1394196116, 1059821722, 1717005978],
        3 => [1010190017, 1610863259, 702158914, 677370523, 2002897149, 1563986427, 1571669105, 1374550737, 309180656],
        4 => [1300667472, 367744091, 925553712, 2048054805, 1936703540, 1414081659, 94993461, 580534571, 792081204],
        5 => [432429835, 149244290, 867499013, 15113480, 1439055544, 1973988755, 126646476, 254061477, 1411171814],
        6 => [1409208116, 1756311914, 97758194, 1131186033, 224184851, 167695620, 1970411659, 2118829608, 878117932],
        7 => [1402870649, 874292697, 57092866, 912889681, 977907318, 30303258, 392930182, 166033837, 1842780604],
        8 => [1755820398, 1504299533, 1406557754, 876396782, 2129492083, 911966070, 282100397, 1775986047, 1900404883],
        9 => [561826839, 1218602455, 1021795918, 1894563307, 369759200, 1687887515, 1563003446, 1984692024, 1951556325],
        10 => [1183656408, 972879532, 694761996, 2115909193, 958215738, 942121550, 1373454602, 1178648693, 375203363],
        11 => [359527088, 1234741213, 14546978, 1873019030, 2091544025, 1080729346, 666715412, 69979998, 381977143],
        12 => [682962644, 749007272, 1271917908, 838731184, 1736035791, 1540560260, 546602935, 1586417133, 1784225341],
        13 => [1861211666, 1623782667, 1428033952, 444594271, 898987772, 877015782, 1431286433, 1330312921, 1507055334],
        14 => [878395665, 2098875565, 2054905984, 1958529917, 1275176445, 848845428, 1245842653, 57903499, 1854855060],
        15 => [1514832868, 564621714, 2074679051, 530252123, 635011014, 858016310, 1007070135, 1279480499, 246419505],
        16 => [1220959032, 1567285355, 1425609627, 143948898, 1814799984, 885344716, 139684530, 1396628577, 1638491425],
        17 => [1141675998, 1553069863, 1886000296, 1587564581, 1211860914, 593251568, 1936624479, 446894483, 362905612],
        18 => [534086516, 300210398, 233980615, 1978326942, 1662768855, 385593061, 982917195, 1959975673, 285469374],
        19 => [1595695338, 787820616, 1925934518, 1582047870, 857020133, 1546259607, 365513821, 973287867, 289279324],
        20 => [2084032654, 1491515923, 2010676568, 410415412, 422040851, 1983192378, 1084458922, 965044616, 731544078],
        21 => [1528527404, 1228060977, 1568983929, 795854682, 1949088636, 1494428506, 1464190590, 1227283697, 367312194],
        22 => [1458870133, 1836559198, 998145408, 620771342, 53334826, 1964319708, 1582725887, 414836913, 1296911668],
        23 => [883992696, 1604862370, 339571823, 311554658, 1410905185, 628603160, 135323645, 1316836223, 255348966],
        24 => [1084417606, 581471847, 637899816, 1336687932, 962393525, 1533362506, 1752717491, 1143952717, 1849025849],
        25 => [1013948472, 1252637220, 1816953608, 647008767, 1359484074, 1117233152, 1082530213, 1078298400, 530322854],
        26 => [1991536881, 2117090005, 2092981451, 1816470761, 23297302, 787424346, 1140904099, 574099757, 792610253],
        27 => [2134030543, 2006542210, 1638260263, 2042378984, 1495971005, 1019066635, 1941101323, 1086021784, 1394236551],
        28 => [1258320356, 231321676, 296936832, 1980890708, 1776676784, 1037599363, 812967599, 5443627, 342846518],
        29 => [104747947, 1741492275, 676387369, 761181316, 632366055, 1771083664, 1920623020, 2100055267, 851730745],
        30 => [211044286, 963055928, 1976636893, 216044621, 794204696, 1081010527, 1342672819, 264773286, 1772286112],
        31 => [1079254076, 1693970156, 960259804, 1943023306, 1978050718, 121727717, 1217876977, 422560348, 1561794476],
        _ => [1244565684, 1195527774, 967783741, 1019005848, 719670019, 1338770198, 442464624, 459316257, 1431180522],
    }
}

/// `hash::node(COMPRESS, …)`: one truncated permutation over `l ‖ r ‖ [TAG, 1, NODE1, level, 0, 0]`.
pub fn node_c(level: felt252, l: crate::hash::Digest, r: crate::hash::Digest) -> crate::hash::Digest {
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8] = l;
    let [r0, r1, r2, r3, r4, r5, r6, r7, r8] = r;
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _] = crate::perm::permutation(
        [l0, l1, l2, l3, l4, l5, l6, l7, l8, r0, r1, r2, r3, r4, r5, r6, r7, r8, crate::hash::TAG, 1, crate::hash::NODE1, level, 0, 0],
    );
    [s0, s1, s2, s3, s4, s5, s6, s7, s8]
}

pub fn node_key(level: u32, index: u64) -> felt252 {
    let level: felt252 = level.into();
    level * 0x10000000000000000 + index.into()
}

#[starknet::component]
pub mod m31_tree_v3_component {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::get_block_number;
    use crate::hash::{Digest, is_zero, key, pack, unpack};
    use super::{TREE_DEPTH, node_c, node_key, zero_c};

    #[storage]
    pub struct Storage {
        pub store_nodes: bool,
        /// nodes mode: node digests keyed by `node_key(level, index)`; absent = empty subtree.
        pub nodes: Map<felt252, (felt252, felt252)>,
        /// frontier mode: the rightmost left child at each level.
        pub frontier: Map<u32, (felt252, felt252)>,
        pub tree_count: u64,
        pub tree_root: (felt252, felt252),
        /// `key(tree_root)`.
        pub tree_root_key: felt252,
        /// `key(R)` → the block that replaced `R`, plus one.
        pub superseded_at: Map<felt252, u64>,
        pub root_window: u64,
    }

    #[embeddable_as(M31TreeV3)]
    pub impl M31TreeImpl<
        TContractState, +HasComponent<TContractState>,
    > of super::IM31TreeV3<ComponentState<TContractState>> {
        fn get_root(self: @ComponentState<TContractState>) -> Span<felt252> {
            let (lo, hi) = self.tree_root.read();
            unpack(lo, hi).span()
        }

        fn get_leaf_count(self: @ComponentState<TContractState>) -> u64 {
            self.tree_count.read()
        }

        fn root_is_known(self: @ComponentState<TContractState>, root: Span<felt252>) -> bool {
            self.root_is_valid(crate::hash::read_digest(root))
        }

        fn get_root_superseded_at(self: @ComponentState<TContractState>, root: Span<felt252>) -> u64 {
            self.superseded_at.read(key(crate::hash::read_digest(root)))
        }

        fn get_node(self: @ComponentState<TContractState>, level: u32, index: u64) -> Span<felt252> {
            assert(self.store_nodes.read(), 'NODES_NOT_STORED');
            let (lo, hi) = self.nodes.read(node_key(level, index));
            if lo == 0 && hi == 0 {
                zero_c(level).span()
            } else {
                unpack(lo, hi).span()
            }
        }
    }

    #[generate_trait]
    pub impl M31TreeInternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of M31TreeInternalTrait<TContractState> {
        /// Fixes the storage mode and the root window `W`; the current root is the empty tree's.
        fn initializer(ref self: ComponentState<TContractState>, store_nodes: bool, root_window: u64) {
            assert(root_window != 0 && root_window <= 0xffffffff, 'ROOT_WINDOW');
            self.store_nodes.write(store_nodes);
            self.root_window.write(root_window);
            let empty = zero_c(TREE_DEPTH);
            self.tree_root.write(pack(empty));
            self.tree_root_key.write(key(empty));
        }

        /// The current root, or one replaced at most `W` blocks ago (§8.3).
        fn root_is_valid(self: @ComponentState<TContractState>, root: Digest) -> bool {
            let k = key(root);
            if k == self.tree_root_key.read() {
                return true;
            }
            let s = self.superseded_at.read(k);
            // Replaced at block `s − 1`: accepted while `block − (s − 1) ≤ W`.
            s != 0 && get_block_number() < s + self.root_window.read()
        }

        /// Appends `leaf`; only funded deposits or verified spends may call this.
        fn insert_leaf(ref self: ComponentState<TContractState>, leaf: Digest) -> u64 {
            assert(!is_zero(leaf), 'ZERO_LEAF');
            let store_nodes = self.store_nodes.read();
            let idx = self.tree_count.read();
            assert(idx < 0x100000000, 'TREE_FULL');
            if store_nodes {
                self.nodes.write(node_key(0, idx), pack(leaf));
            }
            let mut cur = leaf;
            let mut index = idx;
            let mut level: u32 = 0;
            while level < TREE_DEPTH {
                let left_child = index % 2 == 0;
                let sibling = if store_nodes {
                    let sib_index = if left_child { index + 1 } else { index - 1 };
                    let (lo, hi) = self.nodes.read(node_key(level, sib_index));
                    if lo == 0 && hi == 0 {
                        zero_c(level)
                    } else {
                        unpack(lo, hi)
                    }
                } else if left_child {
                    self.frontier.write(level, pack(cur));
                    zero_c(level)
                } else {
                    let (lo, hi) = self.frontier.read(level);
                    unpack(lo, hi)
                };
                cur = if left_child {
                    node_c(level.into(), cur, sibling)
                } else {
                    node_c(level.into(), sibling, cur)
                };
                index = index / 2;
                level += 1;
                if store_nodes {
                    self.nodes.write(node_key(level, index), pack(cur));
                }
            }
            self.record_root(cur, idx + 1);
            idx
        }

        /// Appends `leaf0` and `leaf1` at indices `idx` and `idx + 1` in one pass: both paths are
        /// hashed while they differ (two nodes per level), the node where they meet once, and the
        /// shared path above it once. About 33.5 node hashes on average instead of 64. The final
        /// root equals two `insert_leaf` calls; the intermediate root is never recorded.
        fn insert_two(ref self: ComponentState<TContractState>, leaf0: Digest, leaf1: Digest) -> u64 {
            assert(!is_zero(leaf0) && !is_zero(leaf1), 'ZERO_LEAF');
            let store_nodes = self.store_nodes.read();
            let idx = self.tree_count.read();
            assert(idx + 1 < 0x100000000, 'TREE_FULL');
            if store_nodes {
                self.nodes.write(node_key(0, idx), pack(leaf0));
                self.nodes.write(node_key(0, idx + 1), pack(leaf1));
            }
            // Two nodes at adjacent indices `a` and `a + 1` until their parents coincide.
            let mut c0 = leaf0;
            let mut c1 = leaf1;
            let mut a = idx;
            let mut level: u32 = 0;
            let mut merged = false;
            let mut cur = leaf0;
            while level < TREE_DEPTH && !merged {
                if a % 2 == 0 {
                    // Siblings: their parent is where the paths meet.
                    if !store_nodes {
                        self.frontier.write(level, pack(c0));
                    }
                    cur = node_c(level.into(), c0, c1);
                    merged = true;
                } else {
                    // `a` is a right child, `a + 1` a left child of the next pair.
                    let left = if store_nodes {
                        let (lo, hi) = self.nodes.read(node_key(level, a - 1));
                        if lo == 0 && hi == 0 { zero_c(level) } else { unpack(lo, hi) }
                    } else {
                        let (lo, hi) = self.frontier.read(level);
                        unpack(lo, hi)
                    };
                    if !store_nodes {
                        self.frontier.write(level, pack(c1));
                    }
                    c0 = node_c(level.into(), left, c0);
                    c1 = node_c(level.into(), c1, zero_c(level));
                }
                a = a / 2;
                level += 1;
                if store_nodes {
                    if merged {
                        self.nodes.write(node_key(level, a), pack(cur));
                    } else {
                        self.nodes.write(node_key(level, a), pack(c0));
                        self.nodes.write(node_key(level, a + 1), pack(c1));
                    }
                }
            }
            // The shared path from the meeting node to the root, as `insert_leaf`.
            let mut index = a;
            while level < TREE_DEPTH {
                let left_child = index % 2 == 0;
                let sibling = if store_nodes {
                    let sib_index = if left_child { index + 1 } else { index - 1 };
                    let (lo, hi) = self.nodes.read(node_key(level, sib_index));
                    if lo == 0 && hi == 0 { zero_c(level) } else { unpack(lo, hi) }
                } else if left_child {
                    self.frontier.write(level, pack(cur));
                    zero_c(level)
                } else {
                    let (lo, hi) = self.frontier.read(level);
                    unpack(lo, hi)
                };
                cur = if left_child {
                    node_c(level.into(), cur, sibling)
                } else {
                    node_c(level.into(), sibling, cur)
                };
                index = index / 2;
                level += 1;
                if store_nodes {
                    self.nodes.write(node_key(level, index), pack(cur));
                }
            }
            self.record_root(cur, idx + 2);
            idx
        }

        /// Records `root` as current and the new leaf count; the replaced root starts its window.
        fn record_root(ref self: ComponentState<TContractState>, root: Digest, count: u64) {
            self.superseded_at.write(self.tree_root_key.read(), get_block_number() + 1);
            self.tree_root.write(pack(root));
            self.tree_root_key.write(key(root));
            self.tree_count.write(count);
        }
    }
}

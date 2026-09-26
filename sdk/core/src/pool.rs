//! A pool and its spend relation (`docs/account-bound-note-spec.md` §8, AB-SM1). Pool V2 settles
//! R0 V4 and pool V3 R0 V5, as the network constants record. A pool known to take R0 V4
//! (`KNOWN_V4_POOLS`) is never treated as R0 V5, whatever the caller declares.
use serde::{Deserialize, Serialize};

use crate::felt::{self, Felt32};
use crate::{Error, Result};

/// The spend relation: R0 V4 (pool V2) or R0 V5 (pool V3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Version {
    #[default]
    V4,
    V5,
}

/// Pools known to settle R0 V4 only (chain, pool): refused for R0 V5 whatever the caller says.
pub const KNOWN_V4_POOLS: &[(&str, &str)] = &[("SN_SEPOLIA", "0x2da0011f775d73885cf86c5145feb4cb9149d007f8546959cce32b51b5f37b9")];

/// A pool and the relation it settles, from the network constants. Built only by [`PoolRef::new`],
/// which applies the known-pool check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolRef {
    chain: Felt32,
    pool: Felt32,
    version: Version,
}

impl PoolRef {
    pub fn new(chain: Felt32, pool: Felt32, version: Version) -> Result<PoolRef> {
        felt::check_address(&pool, "pool")?;
        if version == Version::V5 {
            for (c, p) in KNOWN_V4_POOLS {
                if felt::from_short_string(c)? == chain && felt::parse(p)? == pool {
                    return Err(Error::new("wrong_relation", "this pool settles R0 V4 only"));
                }
            }
        }
        Ok(PoolRef { chain, pool, version })
    }

    pub fn chain(&self) -> &Felt32 {
        &self.chain
    }
    pub fn pool(&self) -> &Felt32 {
        &self.pool
    }
    pub fn version(&self) -> Version {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_v4_pools_refuse_v5() {
        let chain = felt::from_short_string("SN_SEPOLIA").unwrap();
        let v2 = felt::parse(KNOWN_V4_POOLS[0].1).unwrap();
        assert!(PoolRef::new(chain, v2, Version::V5).is_err());
        assert_eq!(PoolRef::new(chain, v2, Version::V4).unwrap().version(), Version::V4);
        let v3 = felt::parse("0x7e57b301").unwrap();
        assert_eq!(PoolRef::new(chain, v3, Version::V5).unwrap().version(), Version::V5);
        // The same address on another chain is not the known pool.
        assert!(PoolRef::new(felt::from_short_string("SN_MAIN").unwrap(), v2, Version::V5).is_ok());
        assert!(PoolRef::new(chain, [0; 32], Version::V5).is_err());
    }
}

//! Templar client core (`docs/sdk-spec.md`): every format, derivation, hash, encryption and check
//! of the client side, and the client proof. No I/O and no clock; randomness is passed in; every
//! function returns a `Result` rather than panicking on its input (spec §2).
pub mod address;
pub mod felt;
pub mod keys;
pub mod note;
pub mod pool;
pub mod ohttp;
pub mod result;
pub mod scan;
pub mod sealbox;
pub mod spend;
pub mod store;
pub mod tree;

pub use templar_client_verifier_circuit::payment::Digest;
pub use templar_client_verifier_circuit::{payment4, payment5, payment6};

/// An error with a stable machine-readable code and a message.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}

impl Error {
    pub fn input(message: &str) -> Error {
        Error { code: "invalid_input", message: message.into() }
    }
    pub fn new(code: &'static str, message: impl Into<String>) -> Error {
        Error { code, message: message.into() }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// The M31 modulus.
pub const P: u32 = (1 << 31) - 1;

/// Nine words uniform in `[0, p)` by rejection sampling, not all zero (spec §3.3, HA-M10).
pub fn random_digest(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Digest {
    loop {
        let d: Digest = std::array::from_fn(|_| loop {
            let w = rng.next_u32() & 0x7fff_ffff;
            if w < P {
                break w;
            }
        });
        if d.iter().any(|w| *w != 0) {
            return d;
        }
    }
}

/// Canonical (every word below p) and not all zero.
pub fn digest_ok(d: &Digest) -> bool {
    d.iter().all(|w| *w < P) && d.iter().any(|w| *w != 0)
}

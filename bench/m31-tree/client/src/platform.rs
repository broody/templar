//! Runtime-only adapters: neither time nor memory metrics are mixed into the proof transcript.
use std::time::Duration;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(
    inline_js = "export function membership_now() { return performance.now(); } export function membership_phase(name) { if (typeof globalThis.onMembershipPhase === 'function') globalThis.onMembershipPhase(name); } export function membership_panic(message) { console.error(message); }"
)]
extern "C" {
    fn membership_now() -> f64;
    fn membership_phase(name: &str);
    fn membership_panic(message: &str);
}

pub struct Instant {
    #[cfg(not(target_arch = "wasm32"))]
    value: std::time::Instant,
    #[cfg(target_arch = "wasm32")]
    value: f64,
}
impl Instant {
    pub fn now() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self {
                value: std::time::Instant::now(),
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            Self {
                value: membership_now(),
            }
        }
    }
    pub fn elapsed(&self) -> Duration {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.value.elapsed()
        }
        #[cfg(target_arch = "wasm32")]
        {
            Duration::from_secs_f64((membership_now() - self.value) / 1000.0)
        }
    }
}
pub fn phase(name: &str) {
    #[cfg(not(target_arch = "wasm32"))]
    eprintln!("{name}");
    #[cfg(target_arch = "wasm32")]
    membership_phase(name);
}
pub fn linear_memory_bytes() -> Option<u64> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
    #[cfg(target_arch = "wasm32")]
    {
        Some(core::arch::wasm32::memory_size::<0>() as u64 * 65536)
    }
}
pub fn initialize() {
    #[cfg(target_arch = "wasm32")]
    {
        static INITIALIZED: std::sync::Once = std::sync::Once::new();
        INITIALIZED.call_once(|| {
            std::panic::set_hook(Box::new(|info| membership_panic(&info.to_string())));
            rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .use_current_thread()
                .build_global()
                .expect("single-thread WASM Rayon pool");
        });
    }
}

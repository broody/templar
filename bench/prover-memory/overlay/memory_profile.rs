//! Native-only diagnostics. Counts Rust System-allocator requested bytes, not RSS
//! or C-library allocations. No witness contents or addresses are recorded.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);
pub struct CountingAllocator;
fn add(n: usize) {
    let live = LIVE.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(live, Relaxed);
    TOTAL.fetch_add(n, Relaxed);
}
// SAFETY: delegates every allocation operation to System with the unchanged
// pointer/layout. Counters never allocate, inspect or alter allocated memory.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() { add(layout.size()); }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() { add(layout.size()); }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, n: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, n) };
        if !q.is_null() {
            if n >= layout.size() { add(n-layout.size()); }
            else { LIVE.fetch_sub(layout.size()-n, Relaxed); }
        }
        q
    }
}
pub fn start() -> std::io::Result<()> {
    use std::io::Write;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let Some(path) = std::env::var_os("TEMPLAR_MEMORY_PROFILE") else { return Ok(()) };
    let mut file = std::fs::File::create(path)?;
    writeln!(file, "unix_ms,live_requested_bytes,peak_requested_bytes,total_requested_bytes")?;
    std::thread::spawn(move || loop {
        let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        if writeln!(file, "{ms},{},{},{}", LIVE.load(Relaxed), PEAK.load(Relaxed), TOTAL.load(Relaxed)).is_err() { break; }
        std::thread::sleep(Duration::from_millis(25));
    });
    Ok(())
}

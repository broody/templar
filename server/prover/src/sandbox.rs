//! Per-step isolation (spec §9, PS-6, PS-14): every pre-check, OS run and proof runs as a child
//! process in its own cgroup v2 group (memory, swap, CPU, PIDs) under a delegated subtree; on a
//! timeout or failure the whole group is killed. Steps that need no network run behind the
//! configured no-network prefix (a fresh network namespace).
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::process::Command;

use crate::config::Sandbox;

pub struct Limits {
    pub memory: String,
    pub cpus: u32,
    pub seconds: u64,
    pub network: bool,
}

pub struct Outcome {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub seconds: f64,
    pub peak_memory_bytes: Option<u64>,
    pub timed_out: bool,
}

fn write(path: &Path, value: &str) -> Result<()> {
    std::fs::write(path, value).with_context(|| format!("writing {}", path.display()))
}

/// Creates a child group, returning its path. The subtree must have the memory, cpu and pids
/// controllers enabled for its children (`cgroup.subtree_control`).
fn group(root: &Path, name: &str, limits: &Limits) -> Result<PathBuf> {
    let dir = root.join(name);
    std::fs::create_dir(&dir).with_context(|| format!("creating cgroup {}", dir.display()))?;
    write(&dir.join("memory.max"), &limits.memory)?;
    write(&dir.join("memory.swap.max"), "0")?;
    write(&dir.join("pids.max"), "512")?;
    write(&dir.join("cpu.max"), &format!("{} 100000", limits.cpus as u64 * 100_000))?;
    Ok(dir)
}

/// Kills a step's group and removes it. Runs off the async workers (PI-8).
fn remove(dir: PathBuf) {
    let _ = std::fs::write(dir.join("cgroup.kill"), "1");
    let reap = move || {
        for _ in 0..100 {
            if std::fs::remove_dir(&dir).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) => {
            h.spawn_blocking(reap);
        }
        Err(_) => reap(),
    }
}

/// Removes the group however the step ends, including when its future is dropped (PI-2).
struct GroupGuard(Option<PathBuf>);

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            remove(dir);
        }
    }
}

/// Runs `program args` in its own group with `limits`.
pub async fn run(cfg: &Sandbox, name: &str, program: &Path, args: &[String], envs: &[(&str, String)], limits: Limits) -> Result<Outcome> {
    let dir = group(&cfg.cgroup_root, name, &limits)?;
    let _guard = GroupGuard(Some(dir.clone()));
    let procs = dir.join("cgroup.procs");
    let (bin, mut argv): (PathBuf, Vec<String>) = if limits.network {
        (program.to_path_buf(), vec![])
    } else {
        let (first, rest) = cfg.no_network.split_first().context("no_network prefix is empty")?;
        (PathBuf::from(first), [rest.to_vec(), vec![program.display().to_string()]].concat())
    };
    argv.extend_from_slice(args);
    let mut cmd = Command::new(&bin);
    cmd.args(&argv).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    // Join the group before exec, so everything the step starts is accounted and killable.
    let procs_c = std::ffi::CString::new(procs.display().to_string())?;
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            // "0" moves the writing process itself; nothing is allocated after fork.
            let fd = libc_open(&procs_c)?;
            let r = libc_write(fd, b"0");
            libc_close(fd);
            r
        });
    }
    let start = Instant::now();
    let child = cmd.spawn().with_context(|| format!("starting {}", bin.display()))?;
    let result = tokio::time::timeout(Duration::from_secs(limits.seconds), child.wait_with_output()).await;
    let seconds = start.elapsed().as_secs_f64();
    let peak = std::fs::read_to_string(dir.join("memory.peak")).ok().and_then(|s| s.trim().parse().ok());
    let outcome = match result {
        Ok(Ok(out)) => Outcome { success: out.status.success(), stdout: out.stdout, stderr: out.stderr, seconds, peak_memory_bytes: peak, timed_out: false },
        Ok(Err(e)) => return Err(e).context("waiting for the step"),
        Err(_) => Outcome { success: false, stdout: vec![], stderr: b"timed out".to_vec(), seconds, peak_memory_bytes: peak, timed_out: true },
    };
    Ok(outcome)
}

// Minimal async-signal-safe syscalls for `pre_exec` (no allocation after fork).
fn libc_open(path: &std::ffi::CString) -> std::io::Result<i32> {
    extern "C" {
        fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    }
    const O_WRONLY: i32 = 1;
    let fd = unsafe { open(path.as_ptr(), O_WRONLY) };
    if fd < 0 { Err(std::io::Error::last_os_error()) } else { Ok(fd) }
}

fn libc_write(fd: i32, bytes: &[u8]) -> std::io::Result<()> {
    extern "C" {
        fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    }
    let n = unsafe { write(fd, bytes.as_ptr(), bytes.len()) };
    if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

fn libc_close(fd: i32) {
    extern "C" {
        fn close(fd: i32) -> i32;
    }
    unsafe {
        close(fd);
    }
}

/// Resolves `cgroup_root`. `"self"` means the server's own cgroup is the delegated subtree
/// (systemd `Delegate=yes`, or a container's private cgroup namespace): the server moves itself
/// into a `server` leaf and enables the controllers for its siblings, as cgroup v2's
/// no-internal-process rule requires. Any other value is used as given.
pub fn prepare_root(cfg: &mut Sandbox) -> Result<()> {
    if cfg.cgroup_root.as_os_str() != "self" {
        return Ok(());
    }
    let line = std::fs::read_to_string("/proc/self/cgroup")?;
    let rel = line.lines().find_map(|l| l.strip_prefix("0::")).context("not on cgroup v2")?.trim().to_string();
    let mut root = PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    if root.ends_with("server") {
        // Already moved (a restart inside the same group).
        root.pop();
    } else {
        let leaf = root.join("server");
        std::fs::create_dir_all(&leaf).with_context(|| format!("creating {}", leaf.display()))?;
        write(&leaf.join("cgroup.procs"), "0")?;
    }
    write(&root.join("cgroup.subtree_control"), "+memory +cpu +pids")?;
    // Reserve memory for the front end, so jobs under memory pressure reclaim from each other and
    // not from the server (PI-10).
    let _ = std::fs::write(root.join("server/memory.min"), "256M");
    cfg.cgroup_root = root;
    Ok(())
}

/// Kills and removes step groups left by a previous run (PI-8).
pub fn purge(cfg: &Sandbox) -> Result<usize> {
    let mut n = 0;
    for entry in std::fs::read_dir(&cfg.cgroup_root)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() && ["check-", "os-", "prove-", "selftest-"].iter().any(|p| name.starts_with(p)) {
            let _ = std::fs::write(path.join("cgroup.kill"), "1");
            for _ in 0..50 {
                if std::fs::remove_dir(&path).is_ok() {
                    n += 1;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(n)
}

/// Startup self-test: a group can be created with a memory limit, a process joins it, and the
/// no-network prefix runs. The server refuses to start otherwise (no shared-limit fallback).
pub async fn self_test(cfg: &Sandbox) -> Result<()> {
    let controllers = std::fs::read_to_string(cfg.cgroup_root.join("cgroup.subtree_control"))
        .with_context(|| format!("{} is not a cgroup v2 directory", cfg.cgroup_root.display()))?;
    for c in ["memory", "cpu", "pids"] {
        if !controllers.split_whitespace().any(|x| x == c) {
            bail!("cgroup {}: the {c} controller is not enabled for children (cgroup.subtree_control)", cfg.cgroup_root.display());
        }
    }
    let name = format!("selftest-{}", std::process::id());
    let limits = Limits { memory: "64M".into(), cpus: 1, seconds: 20, network: false };
    // /proc/net/dev lists the interfaces of the step's own network namespace.
    let script = "cat /proc/self/cgroup; tail -n +3 /proc/net/dev | cut -d: -f1";
    let out = run(cfg, &name, Path::new("/bin/sh"), &["-c".into(), script.into()], &[], limits).await?;
    if !out.success {
        bail!("sandbox self-test failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains(&name) {
        bail!("sandbox self-test: the step did not run in its cgroup ({text})");
    }
    let interfaces: Vec<&str> = text.lines().skip(1).map(str::trim).filter(|l| !l.is_empty() && *l != "lo").collect();
    if !interfaces.is_empty() {
        bail!("sandbox self-test: the no-network prefix left interfaces {interfaces:?}");
    }
    Ok(())
}

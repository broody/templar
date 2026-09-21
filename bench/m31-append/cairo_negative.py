#!/usr/bin/env python3
"""Complete-proof Cairo negative runner. Preparation is side-effect free until main()."""
from __future__ import annotations

import argparse, hashlib, json, os, re, shutil, subprocess, sys, time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAIRO = ROOT / "bench/m31-append/cairo"
SCARB = Path("/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb")
FOUNDRY_BIN = Path("/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin")
INPUTS = {
    "single": ROOT / "bench/m31-append/results/native-single-1/proof/cairo-arguments.json",
    "batch": ROOT / "bench/m31-append/results/native-batch-1/proof/cairo-arguments.json",
}
PUBLIC = {k: p.with_name("public-output.json") for k, p in INPUTS.items()}
EXECUTABLE = CAIRO / "target/dev/templar_m31_append_bridge.executable.json"
PRIME = 2**251 + 17 * 2**192 + 1
REJECTION = re.compile(
    r"Panicked with|Run panicked|panic|Proof has invalid structure|Invalid (?:number|First|inner|last)|"
    r"verification failed|INVALID_|TRAILING_|PCS_CONFIG|Proof Of Work|assertion failed",
    re.I,
)
INFRA = re.compile(r"command not found|No such file|Failed to spawn|timed out|oom-kill|out of memory", re.I)


def atom(x): return int(x, 0) if isinstance(x, str) else int(x)
def enc(x): return hex(x % PRIME)
def sha256(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


@dataclass
class Schema:
    a: list[int]
    i: int = 0
    at: dict[str, int] = field(default_factory=dict)
    spans: dict[str, tuple[int, int, int]] = field(default_factory=dict)  # len offset, body start/end

    def scalar(self, name):
        if self.i >= len(self.a): raise ValueError(f"truncated at {name}")
        self.at[name] = self.i; self.i += 1

    def fixed(self, name, n):
        for j in range(n): self.scalar(f"{name}[{j}]")

    def span(self, name, parse_one):
        lo = self.i; self.scalar(name + ".len"); n = self.a[lo]
        if n < 0 or n > 2_000_000: raise ValueError(f"implausible {name} length {n}")
        start = self.i
        for j in range(n): parse_one(f"{name}[{j}]")
        self.spans[name] = (lo, start, self.i)

    def hash(self, name): self.fixed(name, 8)
    def qm31(self, name): self.fixed(name, 4)

    def request(self, n):
        self.span(n + ".input", lambda q: self.scalar(q))
        self.span(n + ".output", lambda q: self.scalar(q))

    def step(self, n):
        self.span(n + ".siblings", lambda q: self.span(q, lambda w: self.scalar(w)))
        self.span(n + ".requests", self.request)

    def sampled_column(self, n): self.span(n, self.qm31)
    def sampled_tree(self, n): self.span(n, self.sampled_column)
    def decommitment(self, n): self.span(n + ".hash_witness", self.hash)
    def fri_layer(self, n):
        self.span(n + ".fri_witness", self.qm31)
        self.decommitment(n + ".decommitment")
        self.hash(n + ".commitment")

    def parse(self, allow_tail=False):
        self.scalar("statement.chain_id"); self.scalar("statement.pool")
        self.scalar("statement.old_count"); self.scalar("statement.new_count")
        self.span("statement.old_root", lambda n: self.scalar(n))
        self.span("statement.new_root", lambda n: self.scalar(n))
        self.span("statement.commitments", lambda n: self.scalar(n))
        self.span("statement.steps", self.step)
        self.scalar("interaction_pow"); self.qm31("claimed_sum")
        self.scalar("pcs.config.pow_bits")
        self.scalar("pcs.config.fri.log_blowup_factor")
        self.scalar("pcs.config.fri.log_last_layer_degree_bound")
        self.scalar("pcs.config.fri.n_queries")
        self.scalar("pcs.config.fri.fold_step")
        self.scalar("pcs.config.lifting_log_size.variant")
        # Cairo core Option is encoded by enum index: Some=0 followed by payload, None=1.
        if self.a[self.at["pcs.config.lifting_log_size.variant"]] == 0:
            self.scalar("pcs.config.lifting_log_size.value")
        self.span("pcs.commitments", self.hash)
        self.span("pcs.sampled_values", self.sampled_tree)
        self.span("pcs.decommitments", self.decommitment)
        self.span("pcs.queried_values", lambda n: self.span(n, lambda q: self.scalar(q)))
        self.scalar("pcs.proof_of_work_nonce")
        self.fri_layer("pcs.fri.first_layer")
        self.span("pcs.fri.inner_layers", self.fri_layer)
        self.span("pcs.fri.last_layer.coeffs", self.qm31)
        self.scalar("pcs.fri.last_layer.log_size")
        if not allow_tail and self.i != len(self.a): raise ValueError(f"unparsed tail: {len(self.a)-self.i}")
        return self


def load(kind):
    raw = json.loads(INPUTS[kind].read_text())
    vals = [atom(x) for x in raw]
    if not vals or vals[0] != len(vals) - 1: raise ValueError(f"bad outer argument length: {kind}")
    schema = Schema(vals[1:]).parse()
    return vals, schema


def set_field(vals, schema, name, value=None):
    out = vals.copy(); p = schema.at[name] + 1
    out[p] = (out[p] + 1) % PRIME if value is None else value
    return out


def resize_span(vals, schema, name, new_items, count=None):
    """Replace a complete Span body and its length; the untouched suffix is byte-for-byte equal."""
    lo, start, end = schema.spans[name]
    out = vals[:]
    out[lo + 1] = len(new_items) if count is None else count
    out[start + 1:end + 1] = new_items
    out[0] = len(out) - 1
    return out


def cases():
    single, s = load("single"); batch, b = load("batch")
    cs = [("valid-single", "single", "accept", single), ("valid-batch", "batch", "accept", batch)]
    def add(name, field): cs.append((name, "single", "reject", set_field(single, s, field)))
    add("chain-id", "statement.chain_id"); add("pool", "statement.pool")
    add("old-count", "statement.old_count"); add("new-count", "statement.new_count")
    add("old-root", "statement.old_root[0]"); add("new-root", "statement.new_root[0]")
    cs.append(("noncanonical-m31-word", "single", "reject",
               set_field(single, s, "statement.old_root[0]", 2**31 - 1)))
    add("statement-commitment", "statement.commitments[0]")
    add("sibling", "statement.steps[0].siblings[0][0]")
    add("request-domain", "statement.steps[0].requests[0].input[2]")
    add("request-wiring", "statement.steps[0].requests[1].input[3]")
    add("request-padding", "statement.steps[0].requests[0].input[13]")
    add("unused-permutation-output", "statement.steps[0].requests[128].output[23]")
    add("interaction-nonce", "interaction_pow"); add("interaction-sum", "claimed_sum[0]")
    add("proof-config", "pcs.config.pow_bits")
    add("populated-pcs-commitment", "pcs.commitments[1][0]")
    add("populated-sample", "pcs.sampled_values[1][0][0][0]")
    add("empty-preprocessing-root", "pcs.commitments[0][0]")
    # These additions remain structurally valid Cairo Spans and retain the exact original suffix.
    cs.append(("nonempty-preprocessing-sample", "single", "reject",
               resize_span(single, s, "pcs.sampled_values[0]", [1, 0, 0, 0, 0], count=1)))
    cs.append(("nonempty-preprocessing-query", "single", "reject",
               resize_span(single, s, "pcs.queried_values[0]", [0])))
    cs.append(("nonempty-preprocessing-witness", "single", "reject",
               resize_span(single, s, "pcs.decommitments[0].hash_witness", [0] * 8, count=1)))
    trailing = single + [0]; trailing[0] += 1
    truncated = single[:-1]; truncated[0] -= 1
    cs += [("trailing-data", "single", "reject", trailing), ("truncated-data", "single", "reject", truncated)]
    lo, start, end = b.spans["statement.commitments"]
    body = batch[start + 1:end + 1]
    swapped = batch.copy(); swapped[start + 1:end + 1] = body[1:] + body[:1]
    cs.append(("batch-commitment-order", "batch", "reject", swapped))
    cs.append(("batch-commitment-omitted", "batch", "reject",
               resize_span(batch, b, "statement.commitments", body[:1])))
    cs.append(("batch-commitment-extra", "batch", "reject",
               resize_span(batch, b, "statement.commitments", body + [body[-1]])))
    return cs


def expected_public(kind): return [atom(x) % PRIME for x in json.loads(PUBLIC[kind].read_text())["public8"]]


def parse_program_output(text):
    # Scarb prints one signed decimal felt per line after this header.
    m = re.search(r"Program output:\s*\n((?:\s*-?(?:0x[0-9a-fA-F]+|\d+)\s*\n?)+)", text, re.I)
    if not m: return None
    nums = re.findall(r"-?(?:0x[0-9a-fA-F]+|\d+)", m.group(1))
    return [int(x, 0) % PRIME for x in nums]


def run_case(out, name, kind, expectation, vals):
    d = out / name; d.mkdir()
    inp = d / "arguments.json"; inp.write_text(json.dumps([enc(x) for x in vals]) + "\n")
    # All non-truncation/trailing cases must round-trip through the enumerated schema.
    schema_ok = True; schema_error = None
    try:
        if vals[0] != len(vals)-1: raise ValueError("outer length mismatch")
        Schema(vals[1:]).parse()
    except Exception as e: schema_ok, schema_error = False, str(e)
    intentional_malformed = name in {"trailing-data", "truncated-data"}
    if not schema_ok and not intentional_malformed: raise RuntimeError(f"generated invalid case {name}: {schema_error}")
    unit = "templar-m31-neg-" + re.sub("[^a-z0-9-]", "-", name) + "-" + str(os.getpid())
    path = f"{SCARB.parent}:{FOUNDRY_BIN}:/usr/bin:/bin"
    inner = ["/usr/bin/time", "-v", str(SCARB), "execute", "--no-build", "-p",
             "templar_m31_append_bridge", "--arguments-file", str(inp), "--output", "none",
             "--print-program-output", "--print-resource-usage"]
    cmd = ["systemd-run", "--user", "--wait", "--pipe", f"--unit={unit}",
           "-p", "MemoryMax=8G", "-p", "MemorySwapMax=0", "-p", "CPUQuota=100%", "-p", "CPUAffinity=0",
           "-p", "RuntimeMaxSec=120", "-p", f"WorkingDirectory={CAIRO}",
           "--setenv", f"PATH={path}", *inner]
    (d / "command.json").write_text(json.dumps(cmd, indent=2) + "\n")
    started = time.time()
    p = subprocess.run(cmd, text=True, capture_output=True)
    (d / "stdout.log").write_text(p.stdout); (d / "stderr.log").write_text(p.stderr)
    show = subprocess.run(["systemctl", "--user", "show", unit,
        "-p", "Result", "-p", "ExecMainCode", "-p", "ExecMainStatus", "-p", "MemoryPeak",
        "-p", "MemorySwapPeak", "-p", "MemoryOOMGroup"], text=True, capture_output=True)
    (d / "cgroup.txt").write_text(show.stdout + show.stderr)
    combined = p.stdout + "\n" + p.stderr + "\n" + show.stdout
    output = parse_program_output(combined)
    infra = bool(INFRA.search(combined)) or "Result=timeout" in combined or "Result=oom-kill" in combined
    if expectation == "accept":
        passed = p.returncode == 0 and output == [8, *expected_public(kind)] and not infra
        reason = "exact Span length and public8" if passed else "control did not return exact serialized public8"
    else:
        explicit = bool(REJECTION.search(combined))
        passed = p.returncode != 0 and explicit and not infra
        reason = "explicit Cairo/verifier rejection" if passed else "not an explicit verifier rejection"
    report = {"name": name, "source": kind, "expectation": expectation, "passed": passed,
              "reason": reason, "returncode": p.returncode, "explicit_rejection": bool(REJECTION.search(combined)),
              "infrastructure_failure": infra, "schema_ok": schema_ok, "schema_error": schema_error,
              "program_output_mod_prime": output, "expected_serialized_public8_mod_prime": [8, *expected_public(kind)] if expectation == "accept" else None,
              "elapsed_wall_seconds": time.time()-started, "input_sha256": sha256(inp), "command": cmd}
    (d / "case-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output_dir", type=Path, help="must not already exist")
    ap.add_argument("--describe", action="store_true", help="print case names only; create/run nothing")
    ns = ap.parse_args()
    ns.output_dir = ns.output_dir.resolve()
    planned = cases()
    if ns.describe:
        print(json.dumps([{"name": x[0], "source": x[1], "expectation": x[2]} for x in planned], indent=2)); return
    if ns.output_dir.exists(): raise SystemExit(f"refusing non-fresh output directory: {ns.output_dir}")
    for p in [SCARB, EXECUTABLE, *INPUTS.values(), *PUBLIC.values()]:
        if not p.is_file(): raise SystemExit(f"missing required artifact: {p}")
    if sha256(EXECUTABLE) != "2255febc4f0c54d461f81fb01724751990a2cd4dd20df982554d034122d6a232":
        raise SystemExit("reviewed executable pin mismatch")
    ns.output_dir.mkdir(parents=True)
    hashes = {str(p.relative_to(ROOT) if p.is_relative_to(ROOT) else p): sha256(p) for p in [
        Path(__file__), SCARB, EXECUTABLE, *INPUTS.values(), *PUBLIC.values(),
        ROOT/"bench/m31-append/client/src/wire.rs", CAIRO/"bridge/src/lib.cairo", CAIRO/"bridge/src/statement.cairo"]}
    reports = []
    for spec in planned:
        r = run_case(ns.output_dir, *spec); reports.append(r)
        if not r["passed"]: break
    summary = {"status": "pass" if len(reports)==len(planned) and all(r["passed"] for r in reports) else "fail",
               "planned": len(planned), "completed": len(reports), "passed": sum(r["passed"] for r in reports),
               "negative_passed": sum(r["passed"] and r["expectation"]=="reject" for r in reports),
               "controls_passed": sum(r["passed"] and r["expectation"]=="accept" for r in reports),
               "hashes": hashes, "cases": reports}
    (ns.output_dir/"report.json").write_text(json.dumps(summary, indent=2)+"\n")
    lines = ["# Cairo complete-proof negative report", "", f"Status: **{summary['status']}**",
             "", f"Completed {summary['completed']}/{summary['planned']}; controls {summary['controls_passed']}/2; explicit negatives {summary['negative_passed']}/{len(planned)-2}.",
             "", "Each case used MemoryMax=8G, MemorySwapMax=0, CPUQuota=100%, RuntimeMaxSec=120 and `/usr/bin/time -v`.", ""]
    lines += [f"- `{r['name']}`: {'PASS' if r['passed'] else 'FAIL'} — {r['reason']}" for r in reports]
    (ns.output_dir/"report.md").write_text("\n".join(lines)+"\n")
    raise SystemExit(0 if summary["status"] == "pass" else 1)


if __name__ == "__main__": main()

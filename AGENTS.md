# Templar agent policy

## Default delegation

Use **Astra** for implementation work. This includes application code,
proof-system code, cryptographic code, protocol logic, architecture changes,
and non-trivial bug fixes. Astra owns the implementation context and integrates
the final change.

Use a **Kimi K3** worker for bounded routine work such as
benchmark execution, test execution, documentation updates, artifact and
measurement collection, formatting, and mechanical maintenance:

```bash
/home/broody/.kimi-code/bin/kimi --model kimi-code/k3 --prompt "<bounded task>"
```

Use noninteractive prompt execution and reuse the relevant session with
`--session <session-id> --prompt "<bounded follow-up>"`. The installed CLI
rejects combining `--prompt` with `--auto`. K3 is an external CLI worker;
do not silently substitute a different model if it is unavailable. Keep
assignments narrow and use scripts for repetitive execution.

Give the worker a bounded task, explicit file ownership, acceptance criteria,
and the relevant repository instructions. K3 must not make design decisions
or modify implementation code unless Astra has reduced the task to an explicit,
mechanical edit. Astra reviews K3's output and diffs before accepting them.
Do not run overlapping agents against the same files.

Keep orchestration, implementation, code review, and final integration with
Astra. For soundness-critical proof-system or cryptographic work, preserve the
independent Math Reviewer step required by nested STWO `AGENTS.md` files. Astra
acts as the Implementer or Crypto Specialist. K3 may act as the Perf
Specialist only for executing an already-defined measurement plan and gathering
results; it must not change algorithms or approve soundness-sensitive changes.
Crypto Specialist work still requires Math Reviewer sign-off before
implementation and review afterward.

## Cost-conscious workflow

- Delegate by milestone, not by conversation turn. Do not automatically wake
  `cairo_perf`, `bounded_pcs`, or another Astra specialist on each user message.
- Give each implementation specialist one bounded assignment with a concrete
  handoff, then leave it idle. Reuse the same specialist only for a specific
  implementation blocker or soundness-sensitive change in its area.
- Route routine follow-up tests, benchmark runs, artifact collection, and docs
  to the single K3 worker. Astra integrates the handoff without repeated
  specialist status requests or duplicate reviews of unchanged code.
- Prefer one Kimi K3 worker for coherent routine benchmark, test, or
  documentation work instead of several overlapping workers.
- Add a separate reviewer only when cryptographic soundness, unsafe arithmetic,
  protocol compatibility, or a consequential architecture decision requires it.
- Route implementation and non-trivial debugging to Astra even when K3 could
  perform part of the work.
- Reuse the same K3 session for follow-up fixes when its context is still
  relevant; avoid repeatedly sending the full project history.
- Keep benchmark processes isolated from builds and other timed workloads.
- Summarize worker findings for the user rather than forwarding verbose agent
  transcripts.

Nested `AGENTS.md` files remain authoritative for their directories. This file
chooses the default worker; it does not weaken their role boundaries, review
requirements, or escalation rules.

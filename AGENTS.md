# Templar agent policy

## Default delegation

Use **Astra** for implementation work. This includes application code,
proof-system code, cryptographic code, protocol logic, architecture changes,
and non-trivial bug fixes. Astra owns the implementation context and integrates
the final change.

Use a **GPT-5.6 Sol** worker for bounded routine work such as
benchmark execution, test execution, documentation updates, artifact and
measurement collection, formatting, and mechanical maintenance:

```bash
/usr/lib/chatgpt/resources/codex -a never exec -m gpt-5.6-sol -c 'model_reasoning_effort="low"' --skip-git-repo-check "<bounded task>"
```

Use noninteractive execution and reuse the returned session with `codex exec
resume <session-id>` for coherent follow-up work. If an in-process delegation
slot is available, it may use the same model and reasoning effort instead.
On this machine, use the app-bundled CLI above: the older Node-installed CLI
earlier on `PATH` does not support GPT-5.6 Sol.
Default to low reasoning for routine execution and mechanical follow-ups. Use
medium only when preparing a new multi-stage harness needs additional reasoning.

Give the worker a bounded task, explicit file ownership, acceptance criteria,
and the relevant repository instructions. Sol must not make design decisions
or modify implementation code unless Astra has reduced the task to an explicit,
mechanical edit. Astra reviews Sol's output and diffs before accepting them.
Do not run overlapping agents against the same files.

Keep orchestration, implementation, code review, and final integration with
Astra. For soundness-critical proof-system or cryptographic work, preserve the
independent Math Reviewer step required by nested STWO `AGENTS.md` files. Astra
acts as the Implementer or Crypto Specialist. Sol may act as the Perf
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
  to the single Sol worker. Astra integrates the handoff without repeated
  specialist status requests or duplicate reviews of unchanged code.
- Prefer one GPT-5.6 Sol worker for coherent routine benchmark, test, or
  documentation work instead of several overlapping workers.
- Add a separate reviewer only when cryptographic soundness, unsafe arithmetic,
  protocol compatibility, or a consequential architecture decision requires it.
- Route implementation and non-trivial debugging to Astra even when Sol could
  perform part of the work.
- Reuse the same Sol session for follow-up fixes when its context is still
  relevant; avoid repeatedly sending the full project history.
- Keep benchmark processes isolated from builds and other timed workloads.
- Summarize worker findings for the user rather than forwarding verbose agent
  transcripts.

Nested `AGENTS.md` files remain authoritative for their directories. This file
chooses the default worker; it does not weaken their role boundaries, review
requirements, or escalation rules.

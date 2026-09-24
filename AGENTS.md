# Templar agent policy

## Default delegation

**Claude** (the main session) owns orchestration, implementation, code review
and final integration. This includes application code, proof-system code,
cryptographic code, protocol logic, architecture changes and non-trivial bug
fixes.

Claude delegates to its own **subagents** (the Agent tool) where that keeps the
main context focused:

- **Routine, bounded work**: benchmark execution, test execution, artifact
  and measurement collection, documentation updates, formatting and mechanical
  maintenance.
- **Read-only exploration**: broad codebase or upstream-source searches where
  only the conclusion is needed.
- **Independent review**: a fresh subagent with no implementation context,
  for soundness, binding or performance reviews.

Give each subagent a bounded task, explicit file ownership, acceptance
criteria and the relevant repository instructions. Subagents doing routine
work must not make design decisions or modify implementation code unless
Claude has reduced the task to an explicit, mechanical edit. Claude reviews
subagent output and diffs before accepting them. Do not run overlapping agents
against the same files; use `isolation: "worktree"` when parallel agents must
edit the same repository.

For soundness-critical proof-system or cryptographic work, preserve the
independent Math Reviewer step required by nested STWO `AGENTS.md` files.
Claude acts as the Implementer or Crypto Specialist. The Math Reviewer is a
separate subagent that did not write the change. It receives the change and the
relevant specs, not the implementer's reasoning. A subagent may act as the Perf
Specialist only for executing an already-defined measurement plan and gathering
results; it must not change algorithms or approve soundness-sensitive changes.
Crypto Specialist work still requires Math Reviewer sign-off before
implementation and review afterward.

## Cost-conscious workflow

- Delegate by milestone, not by conversation turn. Do not spawn or wake
  specialist subagents on each user message.
- Give each subagent one bounded assignment with a concrete handoff. Continue
  the same subagent (SendMessage) only for a specific follow-up in its area
  while its context is still relevant, instead of resending project history.
- Prefer one subagent for coherent routine benchmark, test or documentation
  work instead of several overlapping ones.
- Add a separate reviewer only when cryptographic soundness, unsafe arithmetic,
  protocol compatibility, or a consequential architecture decision requires it.
- Avoid duplicate reviews of unchanged code.
- Keep benchmark processes isolated from builds and other timed workloads.
  Do not run a timed benchmark while another agent is building or proving.
- Summarize subagent findings for the user rather than forwarding verbose
  transcripts.

Nested `AGENTS.md` files remain authoritative for their directories. This file
chooses the default worker; it does not weaken their role boundaries, review
requirements, or escalation rules.

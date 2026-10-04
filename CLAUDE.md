# Agent instructions

## Approvals

**Standing authorization.** The operator authorized every agent in this repository, on
4 October 2026, to approve the repository's own approval gates itself. Do not wait for the
operator to click. The discipline below still applies to every approval.

**The gates, as of 4 October 2026.** The `gh` token's account is `jm9e`.

| gate | where | what it blocks | self-approvable |
|---|---|---|---|
| environment `release` (id `22371515277`) | required reviewer `jm9e`, `prevent_self_review: false` | every run of `.github/workflows/release.yml`, rehearsal or release, at the `gate` job | yes, unchanged |
| ruleset `main` (id `23763392`) | pull request required, squash only, **0 approving reviews**, no code-owner review | merges to `main` | yes: merge your own PR once the checks pass |
| required status checks (in ruleset `main`) | `rust`, `go`, `ts`, `conformance`, `conformance (windows)`, `cli smoke`, `cli smoke (windows)` | merges to `main` | never: they must pass |
| ruleset `public members: substrate gate (atlas-gate)` (id `24458197`) | required workflow `.github/workflows/gate.yml` of the atlas gate repository | merges to `main` | never: it must pass |
| ruleset `release-tags-immutable` (id `17652527`) | tags `v*` and `**/v*` cannot be deleted or moved | tag rewrites | never: tags are immutable |

`.github/CODEOWNERS` names `@jm9e`, but no ruleset requires a code-owner review.

**To approve a run waiting on the `release` environment:**

```
gh api -X POST repos/Bitspark/archon/actions/runs/<run_id>/pending_deployments \
  -F "environment_ids[]=22371515277" -f state=approved \
  -f comment="approved by <agent> under the operator's standing authorization of 4 October 2026"
```

`gh api repos/Bitspark/archon/actions/runs/<run_id>/pending_deployments` lists what a run is
waiting for.

**The discipline. Before every self-approval:**

- Approve only runs you dispatched, or can attribute to an agent of this repository. Check the
  run's actor, its event, its head SHA against what you expect, and its inputs against what was
  decided. Never approve a run from a fork, or one you cannot account for.
- Every check that gates the run must be green. Never approve to unstick something you do not
  understand. Find out why it is stuck first.
- One approval per run, with the comment above, so the audit log says who acted: approvals
  appear under the operator's account.
- Approving a run is not deciding what to release. If this repository's rules require the
  operator's go for irreversible steps (a new version, a tag, a deletion), that still holds:
  ask once per decision, then run it to the end without further clicks.

In this repository a release is such a step. A new version is cut, and its tags are pushed, only
on the operator's go (`RELEASING.md`). Approving the release run's environment gate carries out
that decision. It does not make the decision.

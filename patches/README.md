# Workflow patches waiting for a push with the `workflow` scope

The session that produced these could not push changes under
`.github/workflows/`, because its GitHub token lacks the `workflow` scope.

- `bun-ci-workflow.patch`: the `ci.yml` part of the Bun toolchain switch
  (branch `claude/bun-toolchain`). Apply it on that branch:
  `git apply patches/bun-ci-workflow.patch`.
- `plan-49-sbom-workflows.patch`: commit `a87193a`, the `ci.yml` and
  `release.yml` part of Plan 49 (PR #2, branch `claude/plan-49-sbom`). Apply it
  on that branch: `git am patches/plan-49-sbom-workflows.patch`.

This branch is a carrier only and is not meant to be merged.

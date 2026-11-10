---
name: cgc-scan
description: "Use when a project needs a local security scan and the agent must act on the result: one-shot scan with remediation groups, prioritized next actions, baseline delta and cheap iteration with explain/verify/status/plan. Runs the local cgc-scan CLI, reads its JSON contracts, and respects coverage, trusted validation recipes, toolchain containers and exit codes."
version: 1.3.0
license: Apache-2.0
allowed-tools:
  - Bash(cgc-scan *)
---

# CGC Scan

CGC Scan is a local security scanner. It combines Trivy (dependencies, secrets,
misconfigurations) with language adapters (govulncheck, ESLint, Psalm,
cargo-audit, Bandit) and optional Semgrep CE. It never sends code or results to
CGC; the scan is local. It does not use an AI model and never executes patches,
tests or builds.

## Start here: one command

```bash
cgc-scan agent . --format json
```

`agent` is the one-shot: prepares engines and bases (respecting
`db.refresh_after`), scans with the per-unit cache, builds remediation groups,
priorities and next actions, compares with the baseline (creating it on the
first run) and saves local state. The first run may be slow; a repetition
without changes should take seconds.

When a local Docker daemon is available, the adapters run inside an image
derived from the official language image for the version the project declares.
Do not ask the user to install Go, Node, PHP, Rust or Python in that case: the
first scan builds the image and later scans reuse it. The project is mounted
read-only and the container keeps network access to resolve dependencies, so
those engines report `isolation: configured`. Without Docker, a missing
toolchain is still `requirement_missing` and the coverage is incomplete.

## Toolchains: let the CLI run the engines

`cgc-scan` reads the project version and prepares the engine environment
itself. The detection sources are:

| Language | Version source |
| --- | --- |
| Go | `go.mod` (`go` and `toolchain`) |
| Node/TypeScript | `.nvmrc`, `.node-version`, `engines.node`, `volta.node` |
| PHP | `config.platform.php`, `require.php`, `.php-version` |
| Rust | `rust-version`, `rust-toolchain.toml`, `edition` |
| Python | `requires-python`, `.python-version`, `runtime.txt`, `Pipfile` |

With Docker, the CLI builds `cgc-scan/toolchain:<language>-<version>-<engine>-<engine-version>`
from the official base image and reuses it. The report records the image in
`tools.engines[].image` and the preparation in
`tools.engines[].preparation[]` as `toolchain:<engine>` with the base and its
resolved digest. That base is **not** pinned in `manifest/trust.json`, so the
report declares it as a limitation.

Rules for the agent:

- Do not ask the user to install a language toolchain while Docker is available.
  Run the scan first and read `preparation` and `coverage` before suggesting
  anything.
- Do not claim `enforced` isolation for a containerized adapter: it has network
  access to resolve project dependencies, so the report says `configured`.
- A failed image build is not fatal: the unit falls back to the host toolchain
  and, if that is missing, remains `requirement_missing`. The scan stays
  incomplete; never call the project clean.
- `--offline` and `--no-auto-install` only reuse images that already exist. If
  the image is missing, the adapter falls back or is skipped.
- `CGC_SCAN_TOOLCHAIN=host` forces the host toolchains. Use it only to diagnose
  an image problem, not as a workaround for a missing dependency.
- The container mounts the project read-only. `composer install` or dependency
  installation remains a user step; never write into the project for the scan.

The response is `agent-1.0.0` and contains:

- `summary` — status, coverage, exit code and counts;
- `remediation_groups` — one action per component, ordered by priority;
- `next_actions` — deterministic steps, including blocked validations;
- `delta` — `new`, `persistent`, `resolved`, `not_evaluated` vs baseline;
- `blocked` — missing recipes, toolchains or databases;
- `report_path` — the full canonical JSON (`report-1.1.0`).

Do not read the full canonical report unless you need a specific finding; use
`explain`.

## Cheap iteration

```bash
cgc-scan status . --format json       # last saved result, no scan
cgc-scan plan . --format json         # groups/actions from the last report
cgc-scan explain <fingerprint|grupo>  # full detail: description, refs, evidence
cgc-scan verify <fingerprint|grupo>   # rescan only affected unit+engines
cgc-scan compare --baseline .         # delta without paths or scanning
cgc-scan baseline set .               # fix the baseline explicitly
```

`verify` accepts a fingerprint or a group id (`rg-...`). It returns
`resolved|persistent|partial` per fix and the delta. It never runs recipes. Its
exit code is the focused scan's code, so unrelated findings in the rescan scope
can still return 1; read `status` and `delta`.

## Read a remediation group

```json
{
  "id": "rg-go-golang.org/x/text",
  "kind": "dependency_upgrade",
  "unit": "root",
  "package": { "ecosystem": "Go", "name": "golang.org/x/text", "from": "v0.3.0", "to": "v0.41.0" },
  "fixes": ["0971...", "121e...", "1768...", "31aa...", "80b5..."],
  "max_severity": "high",
  "breaking_risk": "minor",
  "direct": true,
  "commands": {
    "apply": "go get golang.org/x/text@v0.41.0 && go mod tidy",
    "origin": "cgc-scan"
  },
  "verification": { "status": "ready", "recipes": [], "verify": "cgc-scan verify rg-go-golang.org/x/text" }
}
```

Rules:

- Apply one group, not one finding. The target version is the highest fixed
  version that stays in the current major when possible.
- `commands.apply` is a **suggestion**, not a trusted recipe. The CLI never runs
  it. Review it, then run it yourself if it matches the project.
- `breaking_risk` is `patch|minor|major|unknown`; `unknown` means the source did
  not provide comparable versions.
- `direct=false` means a transitive dependency: read `note` and `commands.override`;
  upgrade the direct parent or apply the override. A blind upgrade may not compile.
- `kind=secret_rotation` requires revocation and rotation by the user; a rescan
  only proves the value is gone from files.
- `kind=code_fix`/`config_fix` groups all locations of one rule/file; fix them
  together.

## Follow next_actions

Actions are ordered and deterministic:

1. `confirm_recipes` — validation is blocked. Ask the user before confirming
   with `cgc-scan scan <unit> --confirm-recipes`.
2. `apply_group` — apply the suggested dependency action for the group.
3. `revoke_secret` — `user_required=true`; do not attempt it silently.
4. `fix_code` / `fix_config` — patch the grouped locations.
5. `install_toolchain` / `update_db` — a missing tool, toolchain or base made
   coverage incomplete. Do not declare the project clean. With Docker available,
   `install_toolchain` usually means the image build failed, the base tag does
   not exist or the project lacks a manifest; it does not mean the user must
   install Go, Node, PHP, Rust or Python. Read `tools.engines[].preparation[]`
   and the engine `status` before advising.

## Confirm recipes, then validate

Only confirmed recipes are trusted:

- `verification.recipes` — confirmed by the user;
- `verification.suggested` — detected candidates, **not trusted**;
- `verification.status=blocked` — do not invent commands; ask the user.

```bash
cgc-scan scan <path> --confirm-recipes
```

This only adds missing test/build commands and never overwrites user commands.

After a patch:

1. Run the confirmed test recipe without editing tests.
2. Run the confirmed build recipe.
3. If tests need changes for an incompatible upgrade, stop and ask the user.
4. `cgc-scan verify <group>` and require `resolved` (or `persistent` with an
   explicit reason).

## Exit codes and honesty

| Code | Meaning |
| --- | --- |
| 0 | Complete under threshold |
| 1 | Complete and policy violated |
| 2 | Invalid arguments or configuration |
| 3 | Incomplete/failed execution |
| 130 | Canceled |

- `coverage.partial=true`, `errors` or `blocked` means the project is not clean.
- A finding absent from a partial/failed scan is `not_evaluated`, never
  `resolved`.
- `coverage.limitations` explains how engines ran (for example, a toolchain
  container with network). A limitation alone does not set `partial`; check
  `coverage.partial`, `errors` and each engine `status`.
- Never invent fixed versions, scores, locations or descriptions. Missing means
  the source did not provide it.

## Reduced scope (only when needed)

```bash
cgc-scan scan . --only deps,secrets,code,config
cgc-scan scan . --engines trivy,eslint
cgc-scan scan . --changed          # units changed since the baseline (local Git)
cgc-scan agent . --no-cache        # force a full run
cgc-scan agent . --max-groups 5    # truncation is declared in summary
cgc-scan agent . --min-severity high  # view-only filter; canonical JSON keeps all
```

`--only`, `--engines`, `--changed` and `verify` mark coverage partial and list
what was not evaluated. They never turn missing findings into resolved ones.

## Cache and bases

- Results are cached per unit and engine. `tools.engines[].cache` and
  `coverage.units[].engines[].cache` show `hit|miss|mixed|disabled`.
- Dependency engines invalidate on manifests/lockfiles; code engines on the
  unit source tree; Trivy on both plus the database. The toolchain image and
  the mounts are part of the key, so changing the project language version
  rebuilds the engine environment and invalidates the cached result.
- `db.refresh_after` (default `12h`) reuses bases without network inside the
  window. `cgc-scan update-db` always forces an update.
- Toolchain containers use per-language, per-user volumes
  (`cgc-scan-toolchain-*`). They cache modules and packages, never project
  source. Deleting them only costs a slower next scan.

## Assisted audit (optional)

`cgc-scan audit` runs a deterministic audit protocol. You hunt and verify; the
CLI owns coverage, assignment, independence, budget and reports. It never calls
a model, never executes project code and never contacts the network.

```bash
cgc-scan audit init . --profile standard --budget 12
cgc-scan audit next . --agent hunter-a --format json
cgc-scan audit submit . --file submission.json
cgc-scan audit next . --agent verifier-a --format json
cgc-scan audit submit . --file verification.json
cgc-scan audit report .
```

Rules:

- Use a fresh lowercase `--agent` id per role. A hunter cannot verify its own
  candidate and a verifier cannot repeat a verification.
- Submit exactly the records the task asks for. A `needs_validation` record has
  no severity, execution or remediation: give the exact blocker and a local or
  deployment plan.
- A `confirmed` record needs a complete `entrypoint → sink` trace and a bounded
  `execution.observed_result`. Do not strengthen a crash into execution.
- A verdict promotion (`needs_validation` → `confirmed`) needs a second
  independent verifier; the CLI keeps it in `escalation` until then.
- `findings.json` only contains decided records. If `audit report` returns 3,
  the run is incomplete: read `run_status` and `incomplete_reason`, never call
  the project clean.
- `audit init --prior DIR` shows previous context but never suppresses current
  units. `--out` keeps the run outside the project by default.

## Canonical report (report-1.1.0)

Top-level: `schema_version`, `run`, `target`, `coverage`, `tools`, `isolation`,
`validation`, `findings`, `remediation_groups`, `next_actions`, `delta`,
`policy`, `errors`.

Finding fields worth using: `fingerprint`, `kind`, `severity.normalized`,
`package.version/fixed_version/direct/relationship/via`,
`priority.score/rank/factors`, `locations`, `descriptions`, `references`,
`remediation`, `verification`, `policy.status`.

Engine fields worth using: `tools.engines[].status`, `mode`
(`docker|global|library`), `image`, `isolation`, `db`, `rules`, `cache` and
`preparation[]`. A containerized adapter shows `mode: docker`, an `image`
tag and a `preparation` entry named `toolchain:<engine>`.

`priority.factors` is visible and deterministic: severity, `kev`, EPSS bands,
`reachable`, `fix_available`, `direct`, and `test_path|fixture_path|example_path`
(lowered priority, never hidden).

## Rules

- Do not claim a clean project when coverage is partial, there are errors or
  blocked items remain.
- Do not install project dependencies or run repository hooks as trusted recipes.
- Do not install language toolchains on the host when Docker is available; the
  CLI already prepares the engine image. If an image cannot be built, report the
  preparation error instead of improvising an environment.
- Do not edit tests, snapshots or fixtures to make a patch pass.
- Do not copy secret values into code, patches, logs or messages.
- Prefer `agent` + `verify` over repeated full scans; use `--report-out` only
  when you need an auditable file.
- For CI, pin the CLI and engine manifest, use `scan --format json` and the exit
  code; use `agent` only for interactive agents.

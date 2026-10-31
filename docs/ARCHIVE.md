# Archive — evidence removed in the 3.2.2 cleanup

The 3.0/3.1 release reports (`docs/REPORT-3.0.md`, `REPORT-3.1.md`,
`REPORT-3.2.md`, `REPORT-3.2.1.md`, `AUDIT-3.1.md`, `COMPATIBILITY.md`,
`HARDENING.md`, `MINECRAFT.md`, `VERIFICATION.md`, `PLAN-3.0.md`,
`PLAN-3.1.md`) cite evidence trees that no longer exist in this working copy.
They were deleted on 2026-10-31 to keep the checkout small; the reports are kept
as the historical record and the numbers inside them are unchanged.

## Removed

| Path | Size | Contents |
|---|---|---|
| `qa/results-3.1/` | 9.2 MB | 3.1 acceptance matrix: protected jars, per-case logs, corpus reports |
| `qa/compat/` | 3.1 MB | layout corpus and its edge-case results |
| `qa/minecraft/` | 3.0 MB | Minecraft fixture jars, harness sources, loader runs |
| `qa/audit/` | 1.5 MB | SpotBugs reports, triage tables, CLI probe outputs |
| `qa/passes/` | 0.9 MB | hard-input pass matrix |
| `qa/hardening/` | 0.1 MB | dynamic-attach corpus harness |
| `qa/results-3.2/`, `qa/results-3.2.1/`, `qa/release32/` | 10.0 MB | superseded release binaries |

Earlier in the same cleanup the session's own throw-away artifacts went too:
generated jars under `qa/` (~44 MB), decrypted class dumps and `javap`
transcriptions under `qa/otp-3.2.2/stress/probe/` (~9 MB), temporary build
directories (`build-*`, ~150 MB) and JVM crash dumps (`hs_err_*.log`,
`replay_*.log`).

## Kept, because something still needs it

| Path | Consumer |
|---|---|
| `qa/tools/cfr-0.152.jar` | `DecompilerNoiseTest`, `ProtectionV2Test` (decompiler evidence) |
| `qa/dynamic-attach/` | `DynamicGuardTest` (real attach scenario fixtures) |
| `qa/redblue/run-redblue.ps1` | `docs/HANDOFF.md` §5, `docs/ROADMAP-PORTS.md` §0 |
| `qa/p01/cfr-quality.ps1` | CFR structuring probe (P0-1 acceptance) |
| `qa/gui-redesign/` | screenshots, option audit, geometry dumps for the console |
| `qa/otp-3.2.2/` | stress harness, decrypt probe sources, audit report, intermittent-failure record |
| `qa/snake/SnakeGame.jar` | smoke-test fixture |

## Regenerating

The deleted trees were produced by harnesses that are still in the repository
(`qa/verify.ps1`, `qa/build-demo.ps1`, `qa/build-umbra-dev.ps1`,
`qa/deobfuscate.ps1`) plus the per-area builders that lived under the deleted
directories. Rebuilding the full 3.1 acceptance matrix is possible but not
needed for 3.2.2: current verification is `build.ps1 -Task test`,
`qa/redblue/run-redblue.ps1`, `qa/p01/cfr-quality.ps1` and the console's own
`-Dumbra.fx.selfcheck` / `-Dumbra.fx.audit-options` hooks.

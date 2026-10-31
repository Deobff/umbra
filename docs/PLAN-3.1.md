# Umbra 3.1 — bug hunt + dynamic-protection hardening plan

Baseline: Umbra 3.0.0 (green: 19 suites / 262,641 checks; QA final gate 44/45
corpus PASS + feature PASS + Minecraft PASS, one documented Kotlin/maximum
oversize limitation). Target: **3.1.0** — systematically hunt latent bugs,
fix them, and strengthen runtime/dynamic protection (anti-debug,
anti-instrumentation, anti-dump, runtime integrity) without regressing the
3.0 compatibility model. Java 8 + ASM only, no new runtime dependencies.

Rules: every finding needs a reproducible test/command; every fix needs a
regression test; no fabricated numbers; compatibility (Spring Boot/WAR/MR/
JPMS/agent) must stay green; dynamic checks must not false-positive on normal
launches (JDK 8/21/26).

## A. Bug hunt (systematic)

1. **Static analysis**: run SpotBugs (and javac `-Xlint:all` review) on the
   compiled tree; triage every high/medium finding; fix real ones, justify
   false positives in the audit report.
2. **CLI/config**: missing values, repeated flags, `--set` edge cases
   (empty key/value, duplicate keys, `=` in value), `--inspect` with/without
   `-i/-c`, `--gui` forwarding, exit codes (0/1/2/3), license gate paths,
   relative/absolute path handling, output == input, non-existent parents,
   read-only output, cancelled runs, `--dry-run` no-output guarantee.
3. **YAML/config**: quoting/escapes, lists, duplicate keys, unknown keys,
   booleans/ints overflow, tabs, CRLF, BOM, empty file, preset precedence,
   round-trip ConfigLoader↔ConfigWriter, GUI config round-trip.
4. **Archive/layout edge cases**: empty jar, jar without manifest/classes,
   directory-only entries, duplicate entries, unicode/space names, STORED
   resources, Zip64, malformed manifest continuation lines, signed+MR combo,
   invalid/duplicate module-info, MR with missing base class, `BOOT-INF`
   without manifest, nested jar corruption, huge entry counts, I/O errors
   mid-write (disk full simulation via read-only dir), atomic replace.
5. **Engine/passes**: empty class pools, abstract/native/interface methods,
   records/sealed/enums/inner classes, lambdas/indy/condy, try/finally,
   synchronized, arrays/multidim, huge methods, `StackMapTable` stress,
   annotation retention, reflection keeps, determinism per seed, rollback on
   verifier failure, pass ordering (type-confusion 67 → VM 68), Nocturne
   exclusive/compatible interaction, memory/large-jar stress.
6. **Runtime/guards**: guard template injection on unusual class names,
   watchdog lifecycle/duplicate start, thread leaks, `halt` vs exception
   actions, license/audit report write failures, native DLL temp cleanup,
   concurrent loads, non-ASCII paths/spaces in compiler paths.
7. **GUI**: headless paths, config load/save round-trip, cancel race, resize/
   HiDPI, screenshot determinism, prefs corruption, missing output dir.
8. **Native/VM**: compiler failure paths, missing JNI headers, spaces in
   paths, unsupported opcodes (counted skips), backfill table, anti-dump
   refusal, cross-JDK 8/21/26, JDK 26 restricted `System.load` warning.

Deliverable: `docs/AUDIT-3.1.md` with severity, repro, root cause, fix commit/
file, regression test, and the list of remaining known risks.

## B. Dynamic-protection hardening

Design principle: multiple independent signals, randomized/periodic checks,
fail-loud actions, and **zero false positives on normal launches**. Every
detection is individually try/caught; absent APIs are ignored.

### B1. Java runtime guard (new unified template + pass integration)

* JVM input args: `jdwp`, `-Xdebug`, `-Xrunjdwp`, `-agentlib`, `-agentpath`,
  `-javaagent`, `-XX:+StartAttachListener`, `sun.java.command` agent args.
* Environment: `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`,
  `FRIDA_*`, `GUM_*`, `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` markers.
* Attach detection: `sun.jdwp.listenerAddress`; JDWP thread and
  `Attach Listener` thread; `.attach_pid<pid>`/`.java_pid<pid>` files in
  temp/java.io.tmpdir; JDWP handshake on common + listener-advertised ports.
* Instrumentation: detect JMX remote/agent properties, javaagent on command
  line, `-XX:+EnableDynamicAgentLoading` (JDK 21+) and dynamic attach threads.
* Platform: Linux `/proc/self/status` `TracerPid`, `/proc/self/maps` for
  frida/gum/ptrace loaders; Windows delegated to the native guard.
* Timing/anti-suspend: randomized monotonic-time drift check across
  sleeps/work (debugger pauses produce gaps), with generous thresholds.
* Lifecycle hardening: idempotent install, two randomized watchdogs or a
  scheduler-free re-check hook, no non-daemon thread leaks, action
  `throw|exit|corrupt|log`.
* Entry-point + critical-runtime integration: guard check before class
  decryption, before integrity verification, at VM/interpreter bootstrap;
  loader/helper self-integrity check.
* Tests: child JVM launched with `-javaagent`, `-agentlib:jdwp`,
  `-XX:+StartAttachListener`, env markers, fake listener file; normal launch
  must pass all levels; JDK 8/21 matrix; deterministic unit hooks for timing.

### B2. Class-encryption anti-dump

* Refuse to decrypt/define classes when a runtime guard signal is active
  (same guard template via injected placeholder; no cross-template reference).
* Wipe decrypted byte buffers after `defineClass`; zero key material after
  use; lazy per-class decrypt only at define time.
* Verify per-class digest before define (exists) + re-check guard between
  chunks; tamper a class payload → refusal (test).
* Detect rewritten/partial archives (exists) and self-entry integrity.

### B3. Native guard hardening (Windows first, Linux best-effort)

* Anti-remote-thread: enumerate threads, flag threads whose start address is
  outside all known modules (debugger/Frida-created threads).
* Executable private memory scan: `VirtualQuery` for `MEM_PRIVATE` +
  `PAGE_EXECUTE*` regions outside the image (manual mapping / injected code).
* Memory breakpoints / guard pages in own image; randomized code-section
  byte sampling through the page tables.
* Anti-suspend/timing: native tick drift check, randomized intervals.
* Anti-dump: verify own module file mapping + optional handle-access check
  (`NtQuerySystemInformation` level 3, opt-in); refuse when a debug object
  handle exists (already) and combine signals.
* Linux: `/proc/self/status` TracerPid, `/proc/self/maps` suspicious
  executable mappings, ptrace self-check best-effort (skip when already
  traced by design), Frida env/module markers.
* Keep every check cheap enough for the per-native-method tick; watchdog
  runs the expensive ones.

### B4. Tests / acceptance

* Java guard: detection unit tests + child-JVM integration tests; benign
  launches at levels 1–3 on JDK 8/21/26 must pass; tampered payload refusal.
* Native: existing NativeGuardTest extended; normal runs must not false-
  positive; injected-code/remote-thread simulations where feasible (document
  what cannot be simulated without a debugger/Frida binary).
* Full regression: `build.cmd -Task test` (all suites), demo all presets,
  Spring Boot fat/WAR/MR/JPMS/agent matrix, Minecraft, plugins.
* Re-run QA matrix on the 3.1 release binary; update
  `docs/REPORT-3.0.md` → `docs/REPORT-3.1.md`, `docs/OPTIONS.md`,
  `docs/VERIFICATION.md`, `docs/COMPATIBILITY.md`, release notes, version.

## Workstream ownership

| Area | Owner |
|---|---|
| SpotBugs/static audit, CLI/config/util/GUI bug fixes, `AuditTest` | audit |
| Java runtime guard, anti-dump loader integration, dynamic tests | guard-java |
| Native guard dynamic hardening, native tests | vm |
| Layout/archive edge-case bugs, CompatTest extensions | compat |
| Pass edge-case bugs, ProtectionV2 extensions | protection |
| Engine/CLI cross-cutting fixes, integration, version bump, docs, final QA | Lead |

Write scopes are disjoint; teammates must not edit outside their scope; shared
changes go through the Lead. Every teammate reports: findings, repro, files,
tests, measured evidence, residual risks.

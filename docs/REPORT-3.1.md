# Umbra 3.1.0 — bug-hunt + dynamic-protection release report

Status: **released**. Deliverables: `dist/umbra.jar` (sha256
`546c99f2590ef3f674708c68ecef2aa9f3ed857973c2958d5fc278b91e99cf20`, 1,353,669 B)
and `dist/umbra-3.1.0.zip`; QA verdict PASS-WITH-DOCUMENTED-LIMITATION
(44/45 corpus, dynamic 27/27, feature matrix PASS, Minecraft PASS, plugins
22/22, cross-JDK PASS). Every number is from a command run in this session;
evidence paths are given. Unverified items are listed as limitations, never
claimed.

## 1. Scope

3.1 is a hardening release on top of 3.0.0 (same compatibility model, same
Java 8 + ASM-only runtime, same CLI/GUI/plugins):

* **Systematic bug hunt**: SpotBugs 4.8.6 static analysis over the whole tree
  (108 findings, all triaged), `javac -Xlint:all` review, and targeted
  behavioural probes for CLI, YAML/config, paths, licensing, GUI and the
  archive pipeline.
* **Dynamic-protection hardening**: a new unified Java runtime guard
  (debugger/agent/attach/env/timing signals with watchdog and fail-closed
  class-decryption refusal), Java-side anti-dump buffer wiping and
  re-verification, and a substantially extended native guard (anti-remote-thread,
  executable-private-memory scan, memory-breakpoint/code-sampling, timing,
  module integrity, optional external-handle anti-dump, Linux `/proc` checks).
* **Fixes from acceptance**: the real defects below were found by the new
  probes/tests and fixed with regressions.

## 2. Fixed bugs

### 2.1 Audit (10 findings, `docs/AUDIT-3.1.md`)

| # | Sev | File | Bug |
|---|---|---|---|
| A1 | HIGH | `core/config/ConfigWriter.java` | input/output and advanced-option keys written unquoted → config save→load truncated paths containing `" #"` and broke keys containing `:` |
| A2 | HIGH | `core/config/YamlParser.java` | tab counted as 4 columns but used as character index → tab-indented YAML chopped keys / threw |
| A3 | MED | `core/config/YamlParser.java` | BOM not stripped in `parse()` (BOM license files rejected) |
| A4 | MED | `core/config/YamlParser.java` | single-quoted scalars decoded backslash escapes (`'C:\new\…'` became newline) |
| A5 | LOW | `core/config/ConfigLoader.java` | empty `input:`/`output:` resolved to the config directory |
| A6 | MED | `cli/Main.java` | license-gate holes: config-supplied license ignored with `--require-license -c`; unreadable license exited 1 (now 3); `--license` dropped config publicKey/require; `--require-feature` without a license silently ran unprotected |
| A7 | MED | `gui/GuiMain.java` | headless launch exited 0 although nothing opened |
| A8 | LOW | `gui/GuiMain.java` | missing option values / unknown args silently ignored |
| A9 | LOW | `cli/Main.java` | `-i <root> --dry-run` NPE (`getFileName()` null) |
| A10 | LOW | `cli/Main.java` | unwritable `--compat-report` failed a successful run |

Additional CLI hardening from this release: clean configuration errors for
malformed JARs, missing config files and invalid numeric values; `--allow-in-place`
required to overwrite the input; `--dry-run` works without `-o`; out-of-range
limits rejected before the config builder clamps them silently.

### 2.2 Dynamic-protection fixes

* `antiDebug.action=log` was silently treated as `throw` in 3.0.
* The encrypted-archive level-3 integrity watchdog never started (the loader
  looked the watchdog class up in the wrong loader); fixed (`WATCHDOG-MISSING`
  → `WATCHDOG-PRESENT`).
* Duplicate agent-argument anti-dump check overrode the unified guard's
  configured action/log; delegated to the guard.
* `integrity.action` default in code (`exit`) contradicted the documented
  `throw`; aligned.
* A static guard-resolution cache would bind the first archive's guard across
  multiple loader instances in one JVM; now per instance.
* 3.0 guard level-2 check cost ~1.05 s on Windows (11 × SYN retries); the new
  entry probe checks 5005 + the advertised port (~32–42 ms), full common-port
  scanning runs only in the level-3 watchdog.
* Old guard missed FRIDA environment markers, `-XX:+StartAttachListener` and
  `.attach_pid` artifacts (measured on preserved baseline classes).
* String encryption could push a method over the 64 KB code limit and abort
  the whole run with `Method too large`; now projected budgets keep the method
  valid and count `strings.skipped.methodSize/classLimit`.
* Flow junk insertion could trigger an ASM `SymbolTable.addMergedType` NPE on
  an exotic StackMapTable shape and roll the class back; insertion is now
  frame-aware with a conservative retry (one exotic method remains a
  documented rollback, no corrupt output).
* Native guard: OS-aware library suffix, single-compile generation (was two
  compiles / layout-drift risk), stale-temp cleanup, single-shot concurrent
  load, non-ASCII compiler path verified, JNI symbols for `$`/unicode names,
  `VirtualizationPass` dead condition removed, `CGenerator` dead constants
  removed, `NativeCodePass` null guard.

## 3. Dynamic protection in 3.1

### 3.1 Java runtime guard (`UmbraRuntimeGuard`, shared by all layers)

One seed-derived injected class, called at entry points and before every class
decryption; sticky fail-closed state; actions `throw|exit|corrupt|log`; daemon
randomized watchdog; no false positives on clean JVMs.

| Signal class | Checks |
|---|---|
| JVM / agent arguments | `jdwp`, `-Xdebug`, `-Xrunjdwp`, `-agentlib`, `-agentpath`, `-javaagent`, `-XX:+StartAttachListener`, `-XX:+EnableDynamicAgentLoading`, `sun.java.command` agent args |
| Environment | `JAVA_TOOL_OPTIONS` / `_JAVA_OPTIONS` / `JDK_JAVA_OPTIONS` agent/debug flags, `FRIDA_*`/`GUM_*`, Frida/Gum `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` |
| Attach / debugger | `sun.jdwp.listenerAddress`, `JDWP*` threads, `.attach_pid<pid>`/`.java_pid<pid>`, real `JDWP-Handshake` probe (5005 + advertised at entry, common ports in watchdog) |
| Instrumentation | JMX remote management properties, agent/attach signals above |
| Platform | Linux `/proc/self/status` `TracerPid`, `/proc/self/maps` Frida/Gum/ptrace mappings (Windows delegated to the native guard) |
| Timing | randomized suspend/breakpoint drift check (2.5 s slack) and watchdog interval-drift detection |

Integration: `AntiDebugPass` injects the guard; `IntegrityPass` and the
class-encryption loader call the same guard before verifying/decrypting;
detection makes the loader refuse to decrypt/define and wipes plaintext/key
buffers after `defineClass`.

### 3.2 Native guard extensions

Per-tick: timing/anti-suspend drift, randomized image guard-page/no-access
scan (memory breakpoints), randomized code-section sampling (post-link patched
table). Deep (startup + every 8th tick): anti-remote-thread (thread start
address outside all modules), executable private-memory scan
(MEM_PRIVATE + RX; RWX ignored to avoid HotSpot JIT false positives),
unbacked/manual-mapped module detection, opt-in level-3 external process-handle
scan (`SystemHandleInformation` + `PROCESS_VM_READ`, verified by PID). Linux
branch: `TracerPid`, suspicious maps, one-shot `ptrace(PTRACE_TRACEME)`,
`dladdr` self-path, `clock_gettime` timing. Existing debugger/PEB/DRx/
Frida/backfill checks unchanged.

Options: `antiDebug.remoteThread|execMemoryScan|imageBreakpoints|codeSampling|moduleIntegrity|timing`
default on at level ≥ 2; `antiDebug.handleDump` opt-in at level 3;
`antiDebug.linuxChecks` default true. Cost: one gcc compile per protection
(~10 s) when anti-debug is enabled.

## 4. Verification

### 4.1 Full self-test gate

`build.cmd -Task test` on the release tree: **22 suites, 263,132 checks, exit 0**
(AuditTest 126, CantripTest 9, CompatTest 215, CoreTest 133, CryptoTest 150,
DecompilerNoiseTest 114, DynamicGuardTest 239, FlowTest 260,324, GuiConfigTest
55, GuiSelfTest 208, GuiLayoutTest 9, MinecraftAdapterTest 170,
MixinAnalyzerTest 147, MultiReleaseTest 37, NativeDynamicTest 89,
NativeGuardTest 73, NativeTest 105, NocturneCompatibleTest 14, NocturneTest 101,
ProtectionV2Test 144, Vm3Test 125, VmTest 545). Evidence:
`build-qa/release31-test.log`.

### 4.2 Dynamic-protection evidence

* Clean launches: anti-debug levels 1–3 on JDK 8/21/26 exit 0 with no
  `[umbra-guard]` output; daemon watcher/watchdog never keep the JVM alive.
* Startup instrumentation detected: `-javaagent`, `-agentlib:jdwp`,
  `-Xrunjdwp`, `-XX:+StartAttachListener`, FRIDA/GUM env, fake
  `.attach_pid<pid>`, `sun.jdwp.listenerAddress`; actions
  throw/exit/corrupt/log all verified.
* Real dynamic attach (JDK 8 `com.sun.tools.attach` + `loadAgent`):
  * native-guard build (`--preset maximum`): `[umbra-guard] attach detected
    (agent-load thread)`, target halted, attaching tool blocked — reliable;
  * Java-only build (`--set antiDebug.nativeGuard=false`): **4/4 detections**
    in the release run (earlier loaded-host single-attempt rate 50–75 %;
    documented as best-effort on Windows, native guard recommended).
* Default no port scan (`antiDebug.portProbe=false`): a fake JDWP listener on
  5005 does not flag a clean child.
* Anti-dump: tampered encrypted class payloads refused before define
  (`class decryption refused`), rebuilt native DLL refused by
  fingerprint/backfill challenge; loader refuses decryption after a guard
  signal and wipes plaintext/key buffers.
* Costs: Java guard level-2 entry check 32–42 ms, warm re-check 32–37 µs
  (3.0: ~1.05 s); attach watcher ~2.3 % of one core; native guard adds one gcc
  compile (~10 s) per protection when anti-debug is enabled.

### 4.3 External-artifact acceptance

QA final acceptance on this exact jar (`qa/results-3.1/final/summary.md` +
`summary.json`): **PASS-WITH-DOCUMENTED-LIMITATION**.

| Area | Result |
|---|---|
| Corpus (15 artifacts × light/balanced/maximum, controls re-run) | **44/45 PASS**; runtime 544.5 s. PASS all presets: demo, Java 17 records/sealed, Java 21 pattern switch, Java 26 class file, multi-release (JDK 8 + JDK 21 version), ServiceLoader, JPMS, Java agent (cross-jar attach), signed JAR, Spring Boot 2.7 fat (HTTP), Spring Boot 3 fat (HTTP), executable WAR (HTTP + nested STORED), Maven Shade, Gradle Shadow (`SHADOW-OK`). Residual: `kotlin-app/maximum` `ClassTooLargeException` (documented 3.0 limitation, no per-class rollback). |
| Dynamic protection | **27/27 PASS** — clean launches levels 1–3 × JDK 8/21/26 (no false positives), native guard clean × 3 JDKs, Spring Boot with guard HTTP OK, default no-port-scan FP test, startup `-javaagent`/`-agentlib:jdwp`/`-Xrunjdwp`/`-XX:+StartAttachListener`/`JAVA_TOOL_OPTIONS`/`FRIDA_*`, real dynamic attach (native 1/1; Java-only 1/1 this run, best-effort note), fake `.attach_pid`, encrypted-payload tamper refusal. |
| Feature/regression matrix | **PASS** — 16/16 probes incl. new guard keys, demo presets on JDK 8/21/26, layout modes (SB2/WAR/MR/JPMS/agent), `--inspect`/`--compat-report`/`--mapping`/`--dry-run`/determinism/tamper/`--set` override, GUI screenshot, Audit-3.1 CLI regressions. |
| Minecraft adaptive matrix | **PASS** (5 loader fixtures + controls). |
| Gradle/Maven plugin QA | **22/22 PASS** on the 3.1 CLI (`plugins/qa/SUMMARY.md`). |
| Cross-JDK | Tool runs on 8; protected outputs verified printing OK on JDK 8/21/26. |

Total release-gate runtime ~22 min sequential (QA); one-time 3.0 corpus rebuild
after cache cleanup added ~20 min. Build-test phase is cited from the 22-suite
gate above (QA did not re-run `build.cmd` in the final window; stated in the
summary).

## 5. Known limitations

* Linux native guard code is compiled but not executed on this Windows host
  (Linux `/proc` parsers are unit-tested; no Linux C toolchain here).
* Real debugger/Frida/manual-map/handle-dump scenarios are not simulatable on
  this host; native checks are covered by synthetic test hooks and compiled
  paths. Executable-memory scan ignores RWX regions to avoid JIT false
  positives (single-signal gap).
* Lazy class encryption: tampered payloads for resources the program never
  reads are tolerated (used class payloads are refused).
* Suspend/resume can look like a timing pause; thresholds are 10× interval +
  2 s slack.
* Flow on one exotic StackMapTable shape can still be rolled back (ASM frame
  merge limitation); output stays valid, protection for that class is reduced.
* `--lib` / `--input-mapping` missing paths are warnings, not hard errors.
* Duplicate YAML keys are last-wins; numeric overflow in typed YAML values
  falls back to defaults; YAML anchors/block scalars unsupported.
* Kotlin/ProGuard hard-input fixtures are unavailable on this machine
  (documented gap in `qa/passes`).
* Heavy presets remain CPU/memory intensive; enabling the native guard adds a
  one-time C compile per protection run.

## 6. Reproduction

```bat
build.cmd                                   :: compile + self tests + dist
java -jar dist\umbra.jar --version          :: Umbra 3.1.0
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset maximum --verify
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset maximum ^
  --set antiDebug.level=3 --set antiDebug.nativeGuard=true --verify
plugins\qa\run-qa.cmd
qa\minecraft\verify-mc.cmd -UmbraJar dist\umbra.jar
```

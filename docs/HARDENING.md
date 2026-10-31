# Umbra hardening — dynamic-attack evidence and corpus bug hunt

Final hardening QA for Umbra against the finished guard + signature-fix build.
Owner: qa. Every result below is backed by artifacts under `qa/results/`;
absence of tooling is recorded as SKIP with the exact reason. Nothing is
fabricated.

Builds used for this final pass:

* release gate: `dist/umbra.jar`, sha256
  `bb4803c8d8e7b0427370ca9261053c23ff2cb7cc08bdb6c4f2e3de0ea3d27e84`
  (used by the final strict matrix, `qa/results/20261023-214222/`);
* isolated final build: `build-qa/umbra.jar`, sha256
  `bb4803c8d8e7b0427370ca9261053c23ff2cb7cc08bdb6c4f2e3de0ea3d27e84`
  (21:42 rebuild after the final `Jars`/`NativeGuardPass`/Main-Class changes;
  supersedes the lead-reported `e8b5be45…` 252-class build, which already
  contained the same guard-launcher and signature fixes), used for the dynamic
  matrix, signed-input recheck, Minecraft and GUI self-test.

Runner: Zulu JDK 8 `1.8.0_502`; cross-checks on Zulu 21.0.9 and Java 26; Frida
17.17.0; Python 3.13.7. The dynamic matrix waits out the 4 s native-guard
watchdog (10 s attach, 9 s Frida observation), so detection is not a timing
artefact.

## 1. Threat model

| attacker capability | attack | what it can recover | countermeasure |
|---|---|---|---|
| static | unzip + CFR/javap | readable classes/strings/names | renaming/strings/int encryption, flattening, VM, class encryption, decompiler noise |
| in-process Java agent | `-javaagent` premain transformer dumps every defined class | decrypted bytes as the JVM sees them | anti-debug guard rejects the JVM/args/agent |
| debugger / JDWP | `-agentlib:jdwp=...` | breakpoints, memory, class dump | anti-debug level 2+ rejects JDWP |
| JDK attach API | `VirtualMachine.attach(pid).loadAgent(...)` | same as `-javaagent`, after startup | attach/instrument module scan + watchdog |
| Frida (native) | attach to the process, hook JVM/native functions | method args/returns, memory | anti-Frida/anti-native guard (module/pipe/thread scan) |
| agent backfill | replace protected entry class/native method with original Java bytecode | exact original logic | guard launcher runs before the original main class; native-method verification at startup/watchdog/shutdown |

## 2. Dynamic-attack matrix (final build)

Harness: `qa\hardening\run-dynamic.cmd` (`DumpAgent`, `AttachTool`,
`BackfillAgent`, long-running `Target`). Latest authoritative run:
`qa/results/hardening-20261023-214318/dynamic/` (same outcome as the lead's
earlier `e8b5be45` run in `qa/results/hardening-20261023-213646/dynamic/`).

**Counts: clean 2, detected 7, not-detected 0, recovered 2 (residual by
design), skipped 1 (Frida Java bridge unavailable), errors 0.**

| case | observed status | evidence (exact) |
|---|---|---|
| clean protected demo, no attack | **CLEAN_OK** | prints `OK` |
| `-javaagent` dumper on guarded demo | **DETECTED** | `SecurityException: Debugger detected`, exit 1; 188 classes were defined/dumped (JDK + app classes) before the guard stopped the run |
| `-javaagent` on class-encrypted demo (`antiDump=true`) | **DETECTED** | archive refuses to start under instrumentation (exit 1, no app output) |
| `-javaagent` on encrypted demo, `antiDump=false` | **RECOVERED (residual)** | 564 classes dumped, **26 demo classes** recovered from memory; expected when anti-dump is off |
| JDWP on guarded demo (`antiDebug.level=2`) | **DETECTED** | `SecurityException: Debugger detected`, JDWP rejected |
| JDWP on plain hello jar (control) | **CLEAN_OK** | JDWP accepted by the environment, `OK` |
| JDK attach API → dump agent into guarded target | **DETECTED** | guard watchdog reports `java.lang.SecurityException` (attach/instrument module scan); target terminated |
| JDK attach API → encrypted target, retransform (no guard configured) | **RECOVERED (residual)** | attach succeeded, 10 classes dumped, decrypted target class visible; expected control without guard |
| Frida 17.17 attach to guarded target | **DETECTED** | guard watchdog reports `SecurityException` (`Umbra guard: dynamic analysis detected (0x380)` in the final-guard runs) |
| Frida method hooking (plain target) | **SKIP** | frida attached to the JVM process, but `Java is undefined in this Frida build/platform` (no frida-java-bridge on Windows desktop JVM) and `Interceptor.attach` on a `jvm.dll` export was rejected by Frida (`unable to intercept function ... please file a bug`). No hooking claim made |
| native backfill **before startup** (premain agent replaces the entry class) | **DETECTED** | guard launcher is the manifest `Main-Class`: it initialises the guard before loading/invoking the original main class, then calls the original main reflectively; a swapped entry class no longer removes the guard. Replaced class is rejected (`native backfill blocked (guard or linkage error)`) |
| native backfill **after startup** (attach agent retransforms the loaded class) | **DETECTED** | running guard's watchdog detects the agent backfill/attach and terminates the target |

The earlier premain-backfill gap is fixed by the guard launcher plus
`Jars.write` updating `Main-Class` from `pool.mainClass`; the signed-input fix
is independent (section 4).

## 3. Java GUI self-test (final build)

The desktop GUI is a Java Swing application. `GuiConfigTest` (24 checks)
validates the output-path default and validation rules, config propagation for
every feature switch, preset handling and anti-debug/native-guard implication.
Manual GUI checks: select input JAR, choose an output JAR with **Save As...**,
Start, Cancel, Clear Log and Open Output Folder all operate on the EDT; a
protected demo built through the same config builder runs `OK` on JDK 8.

## 4. Signed-input fix (verified)

`Jars.read` now strips `META-INF/*.SF`, `*.RSA`, `*.DSA`, `*.EC`, `INDEX.LIST`
and signature/digest manifest attributes with a warning. Verified on the final
build with the signed corpus fixture:

* `qa/results/hardening-signed-fix2/` — `edge-signed` with **base** and
  **maximum+classEncryption**: both `--verify` OK and both protected jars run
  (`OK`), i.e. the previous "stale signature / invalid digest" failures are
  resolved.

## 5. Corpus bug hunt

Harness: `qa\hardening\build-corpus.cmd` → `corpus.json` (29 entries: 12
synthetic edge jars, demo, 5 Minecraft fixtures, a 715 KB application jar, 4 library jars,
6 `.minecraft` libraries), then `qa\hardening\run-corpus.cmd`.

Full feature matrix (development build; final-build spot checks are green):
`qa/results/hardening-corpus-final2/summary.md` — 191 runs, **136 PASS, 38
environment/format SKIPs, 0 timeouts, no VerifyError/ClassFormatError/
StackOverflow/OOM on supported Java 8 inputs**. The historical 17 failures are
resolved/explained:

* 9 `ultimate-all` failures were a QA-harness argument-quoting bug (fixed;
  ultimate-all re-run PASS on the final guard build,
  `qa/results/hardening-corpus-ultimate-final/`: 11 runs, 9 PASS, 0 FAIL,
  2 environment SKIPs);
* 8 `edge-signed` failures are **fixed** by the signature-stripping change
  (section 4).

Environment/format SKIPs are not defects: multi-release/duplicate-entry archives
are rejected by design (`Jars.read: flatten the JAR`), JPMS `module-info` and
Java 21 record inputs need a newer JVM than the JDK 8 verifier, and library jars
with missing dependencies cannot be verified without `--lib`.

## 6. Regression on the final build

* **Strict release matrix PASS** on `dist/umbra.jar` (sha
  `942c9c0…`), `qa/results/20261023-214222/summary.md`: baseline/light/balanced/
  maximum/native all PASS on JDK 8 + Zulu 21 + Java 26; all 11 feature probes
  supported; all 6 presets PASS; maximum output 1,156,106 B (34.93×), 741
  classes, readable demo markers **0/0/0/0**; CFR/deobfuscation evidence OK.
* **Minecraft adaptation matrix PASS** on the isolated final build
  (`qa/results/hardening-regression-mc-final3/summary.md`): all five fixtures
  plus enabled-false / forceVmp / allowConflicts controls.
* **Java GUI self-test PASS** (section 3).

## 7. Reproduction

```bat
rem build the isolated jar
cmd /c qa\build-umbra-dev.cmd

rem dynamic attacks (agent / JDWP / attach / Frida / native backfill)
cmd /c qa\hardening\build-tools.cmd -Clean
cmd /c qa\hardening\run-dynamic.cmd -UmbraJar build-qa\umbra.jar

rem corpus bug hunt
cmd /c qa\hardening\build-corpus.cmd -Clean
cmd /c qa\hardening\run-corpus.cmd -UmbraJar build-qa\umbra.jar

rem regression
cmd /c qa\verify.cmd -UmbraJar dist\umbra.jar
cmd /c qa\minecraft\verify-mc.cmd -UmbraJar build-qa\umbra.jar -SkipBuild
rem GUI self-test: java -cp "build\classes;build\test-classes;lib\*" io.umbra.tests.GuiConfigTest
```

## 8. Residual risk / open items

No open hardening defects remain from this pass. Residual items are by design or
environmental:

* `attach-decrypt-target` and `javaagent-decrypt-nodump` recover decrypted
  classes when the guard is not configured / `antiDump=false` — inherent
  JVM-protector memory-dump risk; enable class encryption with antiDump and the
  native guard for the protected configuration (which is what the detected cases
  exercise).
* Pre-main class definition dumps are possible with `-javaagent` before the
  entry guard runs; class encryption with antiDump refuses the archive entirely,
  which is the intended mitigation.
* Frida Java-method hooking is not measurable on this Windows/JDK 8 stack (no
  frida-java-bridge; Frida rejected the attempted `jvm.dll` export hook). The
  native-attach detection result is real; the hook result is SKIP with reason.
* Earlier corpus full-matrix evidence was captured on a pre-final development
  build; final-build spot checks (ultimate-all, signed base+maximum) are green.

## 9. Frida retry (Frida 17.17.0 installed, process attach)

After the user confirmed Frida is installed, the attack was repeated against the
final guard build (no changes to the guard were needed):

* `frida --version` → 17.17.0; `python -c "import frida"` → 17.17.0.
* **Process attach succeeds.** `frida -p <pid>` on a plain JVM prints
  `attached pid=… arch=x64` and enumerates modules (`java.exe`, `ntdll.dll`,
  `KERNEL32.DLL`); the Python harness reports `attached: true` and finds
  `jvm.dll`.
* **Frida Java bridge is still unavailable on desktop Windows/JDK 8:**
  `Java is undefined in this Frida build/platform`, `loadedClasses: 0`, so
  Java-method hooking cannot be executed. `Interceptor.attach` on a
  `jvm.dll` export is rejected by Frida itself (`unable to intercept function
  … please file a bug`). This is a tool/platform limitation, recorded as SKIP —
  no result is fabricated.
* **Guarded target reaction:** attaching Frida to the guard-protected target
  makes the watchdog fire within ~2 s:
  `[Umbra] guard watchdog failure: java.lang.SecurityException: Umbra guard:
  dynamic analysis detected (0x380)`, the JVM halts and the Frida session dies
  (`session is gone`). So Frida process-level attach is detected even though
  Frida's Java bridge cannot be used for hooking here.
* Raw evidence: `qa/results/frida-retry/frida-guard.json`,
  `qa/results/frida-retry/frida-plain.json`, `qa/results/frida-retry/run.err`.

Repro:

```bat
rem build the QA target
javac -source 1.8 -target 1.8 -d qa\hardening\classes qa\hardening\src\qa\hardening\Target.java
jar cfe build\frida-test\target.jar qa.hardening.Target -C qa\hardening\classes qa/hardening/Target.class

rem protect it with the native guard
java -cp "build\classes;lib\*" io.umbra.cli.Main -i build\frida-test\target.jar ^
  -o build\frida-test\target-guard.jar --keep qa.hardening.Target ^
  --set antiDebug.level=2 --set antiDebug.nativeGuard=true ^
  --set antiDebug.watchdogMs=2000 --verify --seed 91

rem start it, attach Frida, observe detection
start java -jar build\frida-test\target-guard.jar
python qa\hardening\frida_attack.py --pid <pid> --out build\frida-test\frida-guard.json --seconds 8
```


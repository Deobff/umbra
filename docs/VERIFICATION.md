# Umbra 3.1 verification

Status: release-candidate verification for **3.1.0**. Every number below is
from a command run in this session; evidence paths are listed in section 9.
Unmeasured items are listed as limitations.

## 1. Environment

| item | value |
|---|---|
| Umbra under test | `dist/umbra.jar`, 3.1.0, sha256 `546c99f2590ef3f674708c68ecef2aa9f3ed857973c2958d5fc278b91e99cf20`, 1,353,669 B |
| JDKs | Zulu 8.0.502 (tool + demo), Zulu 21, Java 26 (output verification) |
| Native compiler | MinGW gcc `E:\1111\bin\gcc.exe` |
| Build | `build.cmd` (JDK 8, vendored ASM 9.11, no network) |
| Plugins | Gradle 8.14, Apache Maven 3.9.9 |

## 2. Full self-test gate

`build.cmd -Task test` — **22 suites, 263,132 checks, exit 0**:

| Suite | Checks | Suite | Checks |
|---|---:|---|---:|
| AuditTest | 126 | MinecraftAdapterTest | 170 |
| CantripTest | 9 | MixinAnalyzerTest | 147 |
| CompatTest | 215 | MultiReleaseTest | 37 |
| CoreTest | 133 | NativeDynamicTest | 89 |
| CryptoTest | 150 | NativeGuardTest | 73 |
| DecompilerNoiseTest | 114 | NativeTest | 105 |
| DynamicGuardTest | 239 | NocturneCompatibleTest | 14 |
| FlowTest | 260,324 | NocturneTest | 101 |
| GuiConfigTest | 55 | ProtectionV2Test | 144 |
| GuiSelfTest | 208 | Vm3Test | 125 |
| GuiLayoutTest | 9 | VmTest | 545 |

Evidence: `build-qa/release31-test.log` (trimmed at packaging; counts above).

## 3. Demo

`demo/demo.jar` protected with every preset: `Verification: OK` and output
prints `OK`. Maximum on the release jar: 2,538 classes, 19.5 s (native guard
compile included).

## 4. Real-artifact acceptance

QA final matrix on this exact jar (`qa/results-3.1/final/summary.md` +
`summary.json`): **PASS-WITH-DOCUMENTED-LIMITATION**.

| Area | Result |
|---|---|
| Corpus 15 artifacts × light/balanced/maximum | **44/45 PASS** (controls 15/15; 544.5 s). Spring Boot 2.7/3 fat, executable WAR, multi-release, JPMS, signed, agent, ServiceLoader, Maven Shade, Gradle Shadow, records/sealed, Java 21/26 class files all PASS. Residual: kotlin-app/maximum `ClassTooLargeException` (documented). |
| Dynamic protection | **27/27 PASS** (see section 5). |
| Feature/regression | **PASS** — 16/16 probes, 6 presets, all layouts, CLI/GUI/determinism/tamper, Audit-3.1 regressions. |
| Minecraft | **PASS** (5 loaders + controls). |
| Plugins | **22/22 PASS**. |
| Cross-JDK | Tool + protected demo PASS on JDK 8/21/26. |

## 5. Dynamic-protection verification

* **Clean launches**: anti-debug levels 1–3 on JDK 8/21/26 — normal exit 0, no
  `[umbra-guard]` output, daemon watchdog/watcher never keeps the JVM alive
  (DynamicGuardTest).
* **Startup instrumentation**: `-javaagent`, `-agentlib:jdwp`, `-Xrunjdwp`,
  `-XX:+StartAttachListener` detected; actions throw/exit/corrupt/log all
  verified.
* **Dynamic attach**: native-guard build (maximum preset) —
  `[umbra-guard] attach detected (agent-load thread)`, target halted, attaching
  tool blocked/killed. Java-only build (`antiDebug.nativeGuard=false`): measured
  **4/4** successful detections in this release run; earlier loaded-host
  single-attempt reliability was 50–75 %, so Java-only Windows attach detection
  is documented as best-effort while the native guard is the reliable path.
* **No port-scan false positive by default**: `antiDebug.portProbe=false`; a
  fake JDWP listener on 5005 does not flag a clean child (DynamicGuardTest).
* **Env/attach artifacts**: FRIDA/GUM markers, `JAVA_TOOL_OPTIONS` agent flags,
  fake `.attach_pid<pid>`, `sun.jdwp.listenerAddress` detected.
* **Anti-dump**: tampered encrypted class payloads refused (throw/log actions),
  rebuilt native DLL refused by fingerprint/backfill challenge; loader refuses
  decryption after a runtime guard signal and wipes plaintext/key buffers.
* **Costs**: Java guard level-2 check 32–42 ms entry / 32–37 µs warm re-check
  (3.0: ~1.05 s); attach watcher ~2.3 % of one core; native guard adds one gcc
  compile (~10 s) per protection when anti-debug is enabled.

## 6. Bug-regression coverage

`AuditTest` (126 checks) reproduces the 10 fixed config/CLI/GUI findings against
a reverse-patched pre-fix snapshot (26 failures pre-fix, 0 post-fix).
`CompatTest` (215 checks) and `qa/compat/unit/edge` cover the 6 layout fixes
(malformed/BOM manifest, invalid module-info, versioned-only main class,
corrupt nested JAR verify error, atomic output, dead collection).
`ProtectionV2Test` (144) covers the near-64 KB string-method guard and
records/sealed/condy preservation. SpotBugs 4.8.6: 105 findings, all triaged
(`qa/audit/spotbugs-triage.tsv`), the actionable ones fixed.

## 7. Minecraft / plugins

* Minecraft adaptive matrix: five loader fixtures PASS on the 3.0 gate; the
  3.1 release re-runs it in the acceptance matrix (`qa/results-3.1/final/`).
* Gradle/Maven plugin sample builds → protect → run: 22/22 PASS on the 3.1 CLI
  (re-run in the acceptance matrix).

## 8. Known limitations

See `docs/REPORT-3.1.md` sections 3–5 and `docs/AUDIT-3.1.md`: Java-only
Windows dynamic attach is best-effort; Linux native checks compiled but not
executed here; real debugger/Frida scenarios not simulatable (synthetic hooks
only); RWX executable-memory regions ignored to avoid JIT false positives;
`antiDebug.portProbe` diagnostic/off; lazy encrypted payloads for never-read
resources tolerated; one exotic StackMapTable flow rollback; Kotlin/ProGuard
hard-input fixtures unavailable on this machine.

## 9. Evidence index

| Evidence | Path |
|---|---|
| Full test log | `build-qa/release31-test.log` (trimmed at packaging) |
| QA acceptance | `qa/results-3.1/final/summary.md` + `summary.json` |
| Audit report / SpotBugs | `docs/AUDIT-3.1.md`, `qa/audit/` |
| Pass hard-input matrix | `qa/passes/results-3.1/` |
| Layout edge matrix | `qa/compat/unit/edge/results/` |
| Dynamic attach fixtures/logs | `qa/dynamic-attach/`, `build-qa/ws9-smoke/` |
| GUI evidence | `qa/results-3.0/gui/` (GUI unchanged in 3.1) |
| Release report | `docs/REPORT-3.1.md` |

## 10. Reproduction

```bat
build.cmd                                   :: compile + 22 suites + dist
java -jar dist\umbra.jar --version          :: Umbra 3.1.0
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset maximum --verify
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset maximum ^
  --set antiDebug.level=3 --verify
plugins\qa\run-qa.cmd
qa\minecraft\verify-mc.cmd -UmbraJar dist\umbra.jar
```

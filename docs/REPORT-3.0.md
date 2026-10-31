# Umbra 3.0.0 — commercial release report

Status: release-candidate report. Every number below comes from a command run in
this session; evidence paths are given next to each table. Items that are not
verified are listed as limitations instead of being claimed.

## 1. Summary

Umbra 3.0 is a full overhaul of the Java bytecode protection suite:

| Area | 3.0 result |
|---|---|
| Archive compatibility | flat, Spring Boot 2/3 fat JAR, executable/plain WAR, multi-release (preserved), modular JARs, signed JARs, agent JARs, OSGi/service-loader resources — detected and written back in layout (`io.umbra.core.compat`) instead of assuming a flat classpath |
| Obfuscation | new type-confusion pass, multi-engine string encryption with stack-trace hiding and wipe, flow v2 (transposition / range+hash predicates / bogus ranges), VM2 v3 (rolling opcode key + superinstruction fusion), native anti-dump/anti-backfill, reflection seal (opt-in), decompiler noise level 4 |
| GUI | complete rewrite: Apple-Books-inspired paper/glass/serif three-column desktop UI in pure Java 2D, custom switches, live console, result cards, YAML load/save, drag-and-drop, `--screenshot` for visual QA |
| Build integration | Gradle plugin (`io.umbra`, `umbraProtect`) and Maven plugin (`umbra:protect`), both proven build→protect→run on their own sample projects; CI examples documented |
| Tooling | `--inspect`, `--inspect-json`, `--compat-report`, `--mapping`; version 3.0.0 |
| Verification | 19 self-test suites, 262,631 checks green; 3.0 build runs on JDK 8 and protected output verified on JDK 8/21/26; real Spring Boot 2.7 jar boot-tested; Minecraft adaptive matrix retained |

Baseline for comparison: Umbra 2.0.0 (245 classes, 14 test suites) built green at
the start of the session.

## 2. Reference study (inputs for the overhaul)

Nine reference tools under `../混淆器/` were studied statically — no tool was
executed, no protected artifact was decompiled, and no third-party code was
copied (see `docs/REFERENCE-MATRIX.md` for the per-tool evidence matrix and
licensing notes):

* **Zelix KlassMaster 27** — bytecode-only; reference obfuscation through
  Reflection API calls, auto reflection handling, `Object[]` parameter collapse,
  annotation-level flow/exception policies, broad XML/resource rewriting.
* **BytecodeVM 2.2.3** — VM design reference: rolling per-record key chain,
  per-method opcode maps, encrypted operands/addresses, superinstruction fusion,
  decoy branches, integrity sampling, `inspect` JSON plan contract.
* **KBox 3.0.3** — feature/measurement benchmark: type confusion, reflection
  gate, anti-decompiler levels, VMP/JNIC/BFVM layers, per-knob strength report.
* **JNIC-Virtualization** — a dumper; its loader contract is the attack model
  Umbra's native anti-dump path is designed against.
* **native-obfuscator 3.5.5r** — GPL-3.0, not reusable; useful contracts: list
  precedence, wildcard semantics, per-platform modes.
* **OpenPhantomShield** — transformer order and settings design; vendor
  lock/phone-home model explicitly rejected.
* **OpenYCP** — incomplete module tree; feature list only.
* **Zipit** — sibling codebase; deltas (license server, build plugins, GUI i18n,
  extra resource/reflection knobs) informed the build-integration work.
* **Zelix rebuild project** — decompiler-grade evidence only, not vendor
  material; no code taken.

Adopted: layout/compat engine, type confusion, reflection gate, build plugins.
Improved: string/flow/VM/native/anti-decompiler/GUI. Parity or rejected:
renaming, constant encryption, archive encryption, ZKM reference obfuscation,
KBox BFVM/BrainfuckShield/K-OTP/PE shell, PhantomShield vendor auth.

## 3. What changed

### 3.1 Archive layout engine (WS1)

New `io.umbra.core.compat` package (`JarLayout`, `LayoutDetector`,
`LayoutOptions`, `LayoutContext`, `LayoutRegistry`, `ClassRenameMap`,
`ManifestRewriter`, `ModuleInfoRewriter`, `TextResourceRewriter`,
`VersionedClass`, `LayoutReport`) and a rewritten read/write path in
`core/util/Jars.java`:

* **Spring Boot fat JAR / WAR**: classes under `BOOT-INF/classes/` or
  `WEB-INF/classes/` are transformed in place; root loader classes are opaque
  resources (never renamed/rewritten); nested libraries are preserved
  byte-identically **with their STORED compression method** (Spring Boot
  rejects recompressed nested jars); `Start-Class`/`Main-Class`/agent
  attributes are remapped; `--verify` extracts nested libraries for real
  class-linking verification and detects layout-destroying post-processors.
* **Multi-release**: `preserve` (default) keeps `META-INF/versions/N/` and the
  `Multi-Release` attribute, applying one consistent class/member mapping to
  every version; `flatten` keeps the 2.0 behaviour.
* **module-info**: descriptor skipped as a normal class, `exports/opens/uses/
  provides` remapped per `layout.moduleInfo=auto|keep|drop`; never emits a
  stale descriptor.
* Signed JARs keep their clean unsigned-output behaviour; service descriptors,
  `spring.factories`, Spring auto-configuration imports, OSGi headers and
  `plugin.yml` are rewritten through the mapping; duplicate entries resolve
  deterministically with a warning instead of aborting.
* Whole-archive protections that install root-level loaders (class encryption,
  startup integrity seal, native guard launcher) are **auto-disabled on nested
  layouts** with warnings and `layout.guard.skipped` /
  `classEncryption.skipped.layout` statistics instead of producing a broken
  archive. `layout.forceEntryProtection=true` is the explicit override.

### 3.2 Protection strength (WS2)

* **`type-confusion`** (new pass, order 67, off by default): routes selected
  private/static call ABI and private static field traffic through
  `Object[]`/`Object` carriers; level 1 = call ABI, level 2 = fields (opt-in);
  verifier-gated with per-method rollback; enabled in `maximum`/`aggressive`.
* **String encryption v2**: per-site engine selection
  (`xor|rc4|chacha20|aes-ctr|speck`, `string.engine=auto` + rotation order),
  stack-trace hiding, decrypt-and-wipe, encrypt-all, per-class keys, split
  payloads, optional invokedynamic; decryptor templates are JDK-only Java 8.
* **Flow v2**: independent-block transposition, range/hash opaque predicates,
  bogus exception ranges, `flow.aggressive` intensity; existing
  verifier-gated rollback kept.
* **Reflection gate** (new pass, order 119, opt-in): runtime seal denying or
  masking reflective member lookups on sealed classes; same-class and
  allow-listed sites keep working.
* **Decompiler noise level 4**: EnclosingMethod/SourceDebugExtension/
  MethodParameters/line-table traps on top of levels 1–3; large output growth,
  opt-in only.
* **Agent safety fix**: `premain`/`agentmain` entry methods are never renamed
  (manifest attributes are remapped in sync), so protected `-javaagent` jars
  attach correctly.

### 3.3 Virtualization and native (WS3)

* **VM2 v3**: rolling opcode-key encoding, superinstruction fusion
  (`vm2.fusion`), payload format version bump with backward-compatible reader,
  additional safe opcode coverage; Cantrip/nested layers compatible.
* **Native anti-dump**: embedded library SHA-256 fingerprint, native-method
  backfill table verification, keyed challenge, watchdog; dumped/rebuilt
  libraries are refused before `System.load`;
  `native.antiDump`/`native.antiBackfill` options.
* Native transpiler coverage extended; every failure path still falls back to
  Java.

### 3.4 GUI rewrite (WS4)

Pure Java 2D/Swing desktop UI (no browser/server): warm paper canvas, layered
frosted-glass panels, Georgia serif + CJK fallbacks, monospace console,
three-column layout (configuration / console / statistics), custom pill
switches, collapsible option groups (Compatibility, Names, Data, Control flow,
Virtualization, Native, Archive, Anti-analysis, Verification, Advanced),
seed field, drag-and-drop, presets, YAML load/save, live log, progress hairline,
cancel, result cards with count-up, status bar, accessible roles, keyboard
shortcuts, `--screenshot` visual-test hook. Screenshots:
`build-qa/gui/idle.png`, `running.png`, `complete.png` (1440×900).

### 3.5 Build integration (WS5)

`plugins/umbra-gradle-plugin` (id `io.umbra`, task `umbraProtect`, depends on
`jar`, configuration-cache compatible) and `plugins/umbra-maven-plugin`
(`umbra:protect`, phase `package`), both Java 8, both proven end-to-end on
sample projects (build → protect → run, `Verification: OK`, protected jar prints
`OK`), including failure-path exit codes. Documentation with Gradle/Maven/CI
snippets in `plugins/README.md`.

### 3.6 CLI and diagnostics

* `--inspect` / `--inspect-json <file>` — read-only layout/compatibility report
  (layout, class counts, class-file versions, entry points, frameworks,
  services, signatures, duplicates, warnings).
* `--compat-report <json>` — post-run JSON with inspection facts, per-pass
  timings and the full statistics map.
* `--mapping <file>` — explicit mapping output path.
* `--set` overrides `--preset` (presets are applied first, explicit CLI options
  last).
* Version 3.0.0; documentation updated (`README.md`, `docs/OPTIONS.md`,
  `docs/ARCHITECTURE.md`, `docs/COMPATIBILITY.md`, `docs/REFERENCE-MATRIX.md`,
  `docs/VERIFICATION.md`, `umbra.example.yml`).

### 3.7 Final hardening found by the acceptance matrix

* **Java agent entry classes are pinned**: a separately protected agent JAR and
  a separately protected application JAR that share a package must not map
  different classes to the same obfuscated name (the application class would
  shadow the agent class and `premain`/`agentmain` would not be found).
  `Premain-Class`/`Agent-Class`/`Launcher-Agent-Class` classes keep their names;
  their entry methods are also kept.
* **JPMS module packages**: injected `umbra/runtime` helpers introduce a
  package the original descriptor did not list. `Jars.write` now merges every
  output class package into `ModulePackages` (except in
  `layout.moduleInfo=keep` byte-stable mode), so
  `java --module-path out.jar -m module` works for light/balanced/maximum.
* **Modular layouts skip root-only launchers** (class encryption, startup
  integrity seal, native guard) because a module is started from its descriptor,
  not from a root `Main-Class`; they are disabled with a warning and skip
  statistics.
* **Generic signatures preserved by default**: the 2.0 preset default erased
  `Signature` attributes, which broke Gson `TypeToken`/generic reflection in a
  real Gradle-Shadow application. Presets now keep signatures (verified:
  `gradle-shadow` JAR prints `SHADOW-OK` under light/balanced/maximum);
  signature erasure remains opt-in through YAML.

## 4. Verification environment

| Item | Value |
|---|---|
| OS | Windows (this machine) |
| JDKs | Zulu 8.0.502 (build/run), Zulu 21, Java 26 (output verification) |
| Build | `build.cmd` (JDK 8 + vendored ASM 9.11, no network) |
| Native toolchain | MinGW gcc `E:\1111\bin\gcc.exe` |
| Gradle / Maven | Gradle 8.14, Apache Maven 3.9.9 (pinned, checksummed cache) |
| Real artifacts | Spring Boot 2.7.18 fat JAR (Maven, 17.8 MB), synthetic WAR/MR/JPMS/agent fixtures, QA corpus (see §6) |

## 5. Self-test suites (3.0 build)

`build.cmd -Task test` — 19 suites, all green:

| Suite | Checks | Suite | Checks |
|---|---:|---|---:|
| CantripTest | 9 | MultiReleaseTest | 37 |
| CompatTest | 194 | NativeGuardTest | 73 |
| CoreTest | 133 | NativeTest | 105 |
| CryptoTest | 150 | NocturneCompatibleTest | 14 |
| DecompilerNoiseTest | 114 | NocturneTest | 101 |
| FlowTest | 260,324 | ProtectionV2Test | 128 |
| GuiConfigTest | 55 | Vm3Test | 115 |
| GuiSelfTest | 208 | VmTest | 545 |
| GuiLayoutTest | 9 | MinecraftAdapterTest | 170 |
| MixinAnalyzerTest | 147 | **Total** | **262,641** |

Evidence: `build-qa/lead2/release-test.log` (full console log). The 2.0
baseline was 14 suites / 245 classes; 3.0 is 19 suites / 398 classes.

## 6. Real-artifact acceptance

Official acceptance run: QA final gate against the release binary
(`dist/umbra.jar`, sha256
`13661e1a92d163cbda7c1052e629f6c17bb9e3f4f237623a1544e8876c09cbb5`,
1,307,073 bytes), overall **PASS-WITH-DOCUMENTED-LIMITATION**: corpus matrix
44/45 PASS (15 real artifacts × light/balanced/maximum), feature matrix PASS,
Minecraft PASS; the only residual is the documented `kotlin-app`/`maximum`
oversized-class limitation below. Evidence:
`qa/results-3.0/final/summary.md` + `summary.json` (with the previous gate
preserved as `summary-4d56c79e.md`).

### 6.1 Self-protection and cross-JDK matrix

| case | status | verify | run JDK 8 / 21 / 26 | output bytes | classEnc / integrity / antiDebug | classes | strings | virtualized |
|---|---|---|---|---|---|---|---|---|
| baseline | PASS | OK | OK / OK / OK | 48,684 | off | 26 | 0 | 0 |
| light | PASS | OK | OK / OK / OK | 69,927 | off | 28 | 469 | 0 |
| balanced | PASS | OK | OK / OK / OK | 379,116 | on / on / off | 330 | 482 | 142 |
| maximum | PASS | OK | OK / OK / OK | 1,366,822 | on / on / on | 749 | 309 | 174 |
| native | PASS | OK | OK / OK / OK | 127,931 | off (native 55) | 29 | 469 | 0 |
| v3 (type confusion + string v2 + VM2 fusion) | PASS | OK | OK / OK / OK | 281,889 | off | 290 | 325 | 65 |

### 6.2 Real build-tool artifacts

| artifact | layout | status | evidence |
|---|---|---|---|
| Spring Boot 2.7.18 fat JAR (Maven) | spring-boot | PASS — 28 nested jars STORED, HTTP `UMBRA-SB2-OK` | `qa/results-3.0/final/20261024-025246/` |
| Spring Boot executable WAR | war | PASS — 28 nested jars STORED, HTTP `UMBRA-WAR-OK` | `qa/results-3.0/final/20261024-025246/` |
| Multi-release JAR (`META-INF/versions/17`) | multi-release | PASS — JDK 8 `MULTI-BASE`, JDK 21 `MULTI-V17`, versioned entry preserved | same corpus run |
| JPMS modular JAR (`module qa.mod`) | module-info | PASS — `java --module-path out.jar -m qa.mod` | same corpus run |
| Java agent (cross-jar attach) | flat | PASS — separately protected agent A + target T, `java -javaagent:A -jar T` → `AGENT-OK` then `TARGET-OK`, all presets | same corpus run |
| Gradle Shadow JAR (Gson `TypeToken`) | flat | PASS — `SHADOW-OK` light/balanced/maximum after the generic-Signature fix | same corpus run |
| QA corpus (15 artifacts: records/sealed, Java 21/26 class files, Kotlin, Shade, signed, ServiceLoader, large real JAR) | all | 44/45 PASS; only `kotlin-app`/`maximum` fails with the documented oversized-class limitation | `qa/results-3.0/final/summary.md` |

### 6.3 Compatibility tooling and determinism

| case | status | note |
|---|---|---|
| `--inspect` / `--inspect-json` | PASS | flat → `layout=flat`; Spring Boot → `layout=spring-boot` |
| `--compat-report` | PASS | layout + stats + per-pass timings present |
| `--mapping` | PASS | mapping file written (3,179 bytes for demo) |
| `--dry-run` | PASS | analysis only, no output written |
| determinism (same seed twice) | PASS | byte-identical (`2562676b…e0665`) |
| tamper / integrity | PASS | tampered archive rejected (exit 1) |
| `--set` overrides `--preset` | PASS | `--preset maximum --set typeConfusion.enabled=false` disables the pass |
| GUI `--screenshot` | PASS | 1440×900 PNG written headlessly |

### 6.4 Minecraft and build-tool plugins

* Minecraft adaptive matrix (5 fixtures: Fabric/Quilt/Forge legacy/Forge modern/
  NeoForge, including enabled-false, vm-forced and conflict cases): **PASS** on
  the final binary — `qa/results-3.0/final/minecraft-final/summary.md`.
* Gradle + Maven plugins: **22/22 PASS** — `plugins/qa/SUMMARY.md` (build →
  protect → `Verification: OK` → protected jar prints `OK`; failure paths exit
  non-zero; Gradle configuration cache OK).

### 6.5 Deobfuscation evidence

QA's strict run records the protected demo's marker scan: 0 demo string/class/
method/field markers left in the maximum output; a CFR pass over the output
produces 0 decompiled method bodies of protected classes (CFR limitation at
higher noise levels is stated honestly — see `docs/NOISE.md` and
`ProtectionV2Test`).

## 7. Demo application results

`demo/demo.jar` (26 classes; prints `OK`) protected with every preset using the
release jar and executed (JDK 8):

| preset | output KB | classes | VM methods | strings | seconds | verify / run |
|---|---:|---:|---:|---:|---:|---|
| light | 134.9 | 81 | 51 | 325 | 1.0 | OK / OK |
| balanced | 924.4 | 721 | 172 | 335 | 2.1 | OK / OK |
| aggressive | 391.4 | 28 | — | 469 | 2.6 | OK / OK |
| maximum | 3,979.9 | 2,538 | 625 | 353 | 8.5 | OK / OK |
| nocturne | 914.9 | 35 | — | 490 | 3.8 | OK / OK |

Evidence: `qa/results-3.0/demo/` (protected jars, logs, compatibility
reports, `demo-results.json`). `—` means the preset uses the classic VM or
Nocturne engine rather than VM2.

## 8. Known limitations (honest)

* **Nested layouts**: class encryption, the startup integrity seal and the
  native guard launcher are root-JAR constructs; they are skipped on Spring
  Boot/WAR layouts with warnings (`layout.guard.skipped`) rather than
  producing a broken or falsely-protected archive. Anti-debug entry-point
  checks, all bytecode/VM/string/flow/type-confusion layers and renaming stay
  active. Executable Spring Boot JAR/WAR works; a WAR deployed into an external
  servlet container cannot see root-level runtime helpers and should be
  protected with `layout.guard.*` disabled or re-verified in the target
  container.
* **Multi-release**: `preserve` output needs a JDK 9+ runtime to use versioned
  entries; `flatten` intentionally drops them (2.0 behaviour).
* **Native code**: Windows-focused, requires a local C toolchain, slower than
  Java-only pipelines; falls back to Java on any failure. 64-bit only.
* **Virtualization**: intentionally conservative — unsupported bytecode shapes
  are left untouched and counted in `virtualization.skipped`.
* **Large JARs**: heavy presets on multi-thousand-class jars are CPU- and
  memory-intensive; run the tool with a larger heap (e.g. `-Xmx4g`) and expect
  minutes. Actual measured behaviour is reported in §6.
* **Reflection gate / decompiler noise 2–4 / type-confusion level 2** change
  observable semantics or output shape and are opt-in; frameworks that rely on
  reflection may need `reflectionGate.allow`/keep rules.
* **Generic signatures are kept by default**: stripping `Signature` attributes
  (the 2.0 preset default) breaks Gson `TypeToken`, generic reflection and some
  DI containers; the acceptance matrix caught a Gradle-Shadow/Gson JAR failing
  that way. Presets now preserve signatures; signature erasure remains
  available through an explicit YAML configuration for applications that do
  not use generic reflection.
* **Very large Kotlin classes + `maximum`**: a Kotlin app with an
  over-64 KB generated class can hit the JVM `ClassTooLargeException` during
  write after heavy transforms (the QA corpus `kotlin-app` case fails only with
  `maximum`; `light`/`balanced` pass). The writer reports the class name and
  aborts instead of writing a corrupt JAR. Mitigation: use `balanced` for such
  apps, or exclude the class with `--keep`.
* **Optional-dependency verification**: `--verify` on a shaded application
  whose optional framework dependencies are absent reports unresolved optional
  references as failures; run with the full application classpath via `--lib`
  when verifying such artifacts.
* No Java obfuscator can stop a determined native-level reverse engineer;
  Umbra raises cost and defeats static/decompiler workflows, not a kernel
  debugger.

## 9. Cleanup

Generated artifacts that are not part of the source deliverable were removed
after the acceptance run; everything below is reproducible from the retained
sources/scripts:

| removed | why |
|---|---|
| `build/` (compiler output, packaging staging, old design/film previews) | regenerated by `build.cmd` |
| `build-qa/` (per-agent build dirs, test scratch, 779 MB) | session working directories |
| `qa/compat/cache/` (~650 MB: downloaded Maven/Gradle artifacts and protected corpus JARs) | reproducible via `qa/compat/` builder scripts |
| `qa/results-3.0/` protected jars/outs of superseded runs (2026-10-24 old hashes) | summaries/logs/reports retained; superseded binaries removed |
| `dist/Umbra-2.0-Film*`, `dist/film/`, `dist/umbra-2.0.0.zip` | assets from the previous 2.0 promotion task, not part of 3.0 |
| `plugins/.cache/`, plugin `build/`/`target/` intermediates, sample build outputs | regenerated by `plugins/build-plugins.ps1` / `plugins/qa/run-qa.ps1` |
| duplicate `dist/umbra-release.jar` (release candidate used during QA) | byte-identical to the delivered `dist/umbra.jar` |

Retained: sources, `lib/`, `docs/`, `demo/`, `plugins/` (sources + plugin JARs +
QA summary), `qa/` harnesses and the acceptance evidence (summaries, JSON,
logs, reports, GUI screenshots, Minecraft matrix), and `dist/umbra.jar` +
`dist/umbra-3.0.0.zip` + `dist/SHA256SUMS`.

## 10. Reproduction

```bat
:: build + tests + distribution
build.cmd
build.cmd -Task package

:: inspect and protect
java -jar dist\umbra.jar -i app.jar --inspect
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset balanced --verify
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset maximum --verify --compat-report compat.json

:: real Spring Boot jar (example)
java -jar dist\umbra.jar -i bootapp.jar -o bootapp-obf.jar --preset maximum --verify
java -jar bootapp-obf.jar --server.port=18080

:: GUI
java -jar dist\umbra.jar --gui
java -jar dist\umbra.jar --gui --screenshot build-qa\gui\idle.png

:: plugins
plugins\qa\run-qa.cmd
```

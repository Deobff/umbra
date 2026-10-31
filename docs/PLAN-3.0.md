# Umbra 3.0 — overhaul plan

Status: executed in this session. Baseline: Umbra 2.0.0 (build green: 245 classes,
14 test suites, dist/umbra.jar 0.98 MB). References studied under
`../混淆器/`: Zelix KlassMaster 27 (`zkm27.jar`,
`ZelixKlassMaster-27-27.0.1/`), `BytecodeVM-2.2.3/`,
`JNIC-Virtualization-main/`, `kboxObfuscator-3.0.3/`,
`native-obfuscator-3.5.5r/`, `OpenPhantomShield-main/`, `OpenYCP-main/`,
`Zipit/`. Reference material is design input only: no third-party code is
copied into Umbra, no dependency is added, and no result is claimed without
running it.

## Product goal

Umbra 3.0 is a commercial-grade Java bytecode protection suite: one
self-contained jar (JDK 8 + vendored ASM 9.11 only), CLI + desktop GUI, that

1. **never breaks a valid input** — any JAR produced by Gradle, Maven,
   Spring Boot, Kotlin, javac/records/sealed, multi-release, signed, agent,
   shadow/fat jars, WAR layouts, or Minecraft mod loaders keeps working after
   protection unless the user explicitly asks for a destructive option;
2. **raises protection strength** with new engines and better existing ones,
   each proven by counts on the demo and by decompiler evidence;
3. **is usable as a product** — rewritten GUI, build-tool plugins, stable
   CLI/YAML, audit/report output, deterministic builds, docs.

Hard constraints: Java 8 language level for Umbra sources; ASM is the only
runtime dependency; protected output must run on JDK 8 through current JDKs;
no fabricated verification results; source and QA evidence retained.

## Workstreams

### WS1 — Archive layout + compatibility engine (compat)

The current loader assumes a flat classpath. Add a real layout model:

| Layout | Detection | Required behaviour |
|---|---|---|
| flat JAR | default | current behaviour |
| Spring Boot 2/3 fat JAR | `BOOT-INF/classes/`, `BOOT-INF/lib/`, `Main-Class=...JarLauncher`/`WarLauncher`, `Start-Class`/`Start-Class` | transform classes under `BOOT-INF/classes/`, preserve nested libs byte-identically, keep loader/Start-Class, rewrite `Start-Class`, `Main-Class`, `Class-Path` correctly; optional `--set layout.springBoot=false` escape hatch |
| WAR | `WEB-INF/classes/`, `WEB-INF/lib/` | transform `WEB-INF/classes/`, preserve `WEB-INF/lib`/static resources |
| multi-release JAR | `META-INF/versions/N/` + `Multi-Release: true` | transform every version with one consistent mapping, keep directory structure + attribute (replaces current flattening; flattening stays available via `layout.multiRelease=flatten`) |
| module JAR | `module-info.class` | keep `module-info` valid: update `exports/opens/uses/provides` through the mapping, or drop it with a warning when renaming would invalidate it (`layout.moduleInfo=auto|keep|drop`) |
| executable/agent JAR | manifest attrs `Main-Class`, `Premain-Class`, `Agent-Class`, `Launcher-Agent-Class`, `Start-Class`, `Bundle-Activator`, `Add-Exports`, `Add-Opens`, `Class-Path` | rewrite class-name attributes at write time |
| signed JAR | `META-INF/*.SF/.RSA/.DSA/.EC`, digests in manifest | strip signature cleanly (already), never emit half-signed archives |
| duplicate entries / Zip64 / weird names | duplicate non-versioned class | warn + deterministic resolution instead of hard failure; Zip64 writer path |
| JAR index | `META-INF/INDEX.LIST` | regenerate or drop (drop is safe) |

Also:
* `META-INF/services/*`, `spring.factories`,
  `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`,
  OSGi `Export-Package`/`Import-Package`/`Bundle-Activator`,
  `META-INF/native-image/*` text resources: rewrite class names.
* `UmbraVerifier` verifies the produced archive according to its layout
  (nested/multi-release aware) and reports per-layout.
* Stats: `layout.kind`, `layout.springBoot.*`, `layout.war.*`,
  `layout.multiRelease.*`, `layout.moduleInfo`, `layout.services`,
  `layout.manifest.rewritten`.
* New tests: `CompatTest` (synthetic Spring Boot/WAR/MR/module-info/agent
  fixtures, byte-level assertions, run the produced app), update
  `MultiReleaseTest` for preserved layout (flattening mode still tested).
* Escape hatches documented in OPTIONS.md (Lead updates docs).

Acceptance: all synthetic layouts round-trip and execute; a real Spring Boot
fat JAR and a real WAR built by Maven/Gradle are protected and run; all
previous tests still pass; multi-release output keeps `META-INF/versions`
intact.

### WS2 — Obfuscation strength (protection)

New/upgraded passes, all deterministic, verifier-gated, per-method defensive:

1. **Type confusion** (`typeConfusion.*`, KBox parity): route selected
   private/static call ABI and field traffic through `Object[]`/`Object`
   carriers, boxing primitives where legal, so decompilers lose static types;
   `typeConfusion.level` 1..2; refused for constructors, `<clinit>`, methods
   whose descriptors are externally observed.
2. **String engine v2** (`string.*`): per-site engine selection
   (`xor`, `rc4`, `chacha20`, `aes-ctr`, `speck`), optional
   `string.engineOrder`, stack-trace hiding (`string.stackTraceHide`),
   decrypt-and-wipe (`string.wipe`), `string.encryptAll`, keep existing
   split/cache/indy/per-class-key semantics; decryptor templates stay
   Java 8 and JDK-only.
3. **Flow v2** (`flow.*`): code transposition of independent blocks,
   range/hash opaque predicates in addition to the current forms, bogus
   exception ranges, `flow.aggressive` intensity, keep the existing
   verifier-gated rollback.
4. **Reflection gate** (`reflectionGate.*`, KBox parity, opt-in): install a
   runtime seal so reflective member lookup on sealed classes is denied or
   masked; default off because it changes observable semantics.
5. **Anti-decompiler v2** (`decompilerNoise.*`): level 4 profile targeting
   current CFR/Procyon/FernFlower/JD behaviour, still JVM-legal, with
   evidence in `DecompilerNoiseTest`.
6. **Evidence**: `scan_strings.py` extended to report per-engine plaintext
   leakage, new stats keys, new test suite `ProtectionV2Test` proving each
   pass changes bytes, keeps demo output `OK`, and is deterministic.

Acceptance: demo prints `OK` with all presets; every new pass has a non-zero
statistic and a test; `--verify` passes; decompiler evidence recorded.

### WS3 — Virtualization + native hardening (vm)

1. **VM2 v3**: rolling opcode-key encoding of the instruction stream,
   superinstruction fusion (LOAD+LOAD+ADD style) behind `vm2.fusion`, more
   opcode coverage (e.g. `lookupswitch`, multi-dim arrays where safe),
   lower call overhead; payload format bumped with backward-compatible reader.
2. **Anti-dump native** (JNIC parity): at load time verify the embedded
   library's integrity/fingerprint and the native method backfill table
   (extend the existing native guard), refuse dumped/rebuilt libraries,
   optional encrypted method table.
3. **Native coverage**: raise transpiler opcode coverage, constructors and
   string/lambda bridges where safe; keep graceful Java fallback.
4. Tests: `VmTest`, `NativeTest`, `NativeGuardTest` green; new `Vm3Test`
   for fusion/encoding; counts reported.

Acceptance: VM2 and native counts on the demo increase or stay equal with
better protection; no verification skips beyond documented classes; output
runs on JDK 8/21/26.

### WS4 — Desktop GUI rewrite (gui)

Replace the current stock-Swing form with the "Apple Books" visual system
from `混淆器/gui设计.txt` (warm paper canvas, layered frosted glass, Georgia
serif UI, three columns, quiet motion), implemented in pure Java 2D/Swing so
the product stays a single jar with no browser or web server:

* top bar: brand, seed field (mono), Start/Cancel primary button with
  progress hairline; drag-and-drop zone for input jar;
* left column: grouped, collapsible configuration (Input/Output, Preset,
  Names, Data, Flow, Virtualization, Native, Archive, Anti-analysis,
  Verification, Advanced key=value editor) with custom pill switches;
* center: frosted console with timestamped log and empty state;
* right column: four statistic cards (classes, protected methods, encrypted
  strings, elapsed); count-up animation on completion;
* bottom status bar: state text + job facts;
* behaviour: explicit output path, config YAML load/save, presets, cancel,
  open folder, verify toggle, mapping path, headless-safe entry point,
  `--screenshot <png>` for automated visual QA, all labels English;
* keyboard shortcuts (Ctrl+O, Ctrl+S, Ctrl+Enter, Esc) and accessible
  roles/names for the custom components.

Acceptance: GUI launches on the desktop, a full protect run completes from
the GUI, screenshots captured and reviewed for layout/typography/contrast,
`GuiConfigTest` updated and green, no regression to CLI headless runs.

### WS5 — Build-tool integration (integration)

"Any build program" means the tool can sit inside the normal builds:

* `plugins/umbra-gradle-plugin`: `io.umbra` Gradle plugin providing an
  `umbra { }` extension and `umbraProtect` task that depends on `jar`,
  consumes the project jar, writes the protected artifact + mapping, fails
  the build on errors; tested with a sample Gradle 8 project (local Gradle
  distribution) end-to-end: build → protect → run.
* `plugins/umbra-maven-plugin`: Maven Mojo (`umbra:protect`) bound to
  `package`, using the same CLI contract; tested with a local Maven 3.9
  install and a sample project.
* Shared CLI-runner code that works with `dist/umbra.jar` or a configured
  tool path, preserves the full CLI option surface, and never hides errors.
* Local-install helper (POM/plugin descriptors, README, CI snippets).
* Evidence: sample projects + logs under `plugins/qa/`.

Acceptance: both plugins build and run a real protect cycle in this
environment; docs show copy-paste usage; no new Umbra runtime dependency.

### WS6 — QA matrix, bug fixing, evidence (qa)

1. Build a compatibility corpus under `qa/compat/` from real toolchains
   (network permitted, versions pinned and cached):
   Spring Boot 2.7 (Java 8) and 3.x fat jars, a WAR, Kotlin app,
   Java 17 records/sealed, Java 21/26 class files, multi-release library,
   ServiceLoader/JPMS app, javaagent, signed jar, Maven Shade and Gradle
   Shadow jars, Minecraft fixtures (already present), large real jar.
2. For each: protect with presets (`balanced`, `maximum`), run the
   *protected* artifact, compare output/HTTP/marker with the control;
   record PASS/FAIL with evidence and logs.
3. Extend `qa/verify.ps1` cases for new features (layout modes, type
   confusion, string engines, reflection gate, VM fusion, native anti-dump,
   GUI config), and a single entry point that rebuilds from source.
4. Triage every failure into an owner task; re-run to green; keep the
   matrix and logs in `qa/results-3.0/`.
5. Explicitly report environmental limitations (e.g. no Docker) instead of
   skipping silently.

Acceptance: matrix covers all listed layouts/toolchains; every FAIL has an
identified cause and either a fix + re-run PASS or a documented limitation
with reproduction steps.

### WS7 — Integration, docs, report, cleanup (Lead)

* Wire new passes/layout engine into `UmbraEngine`, config, CLI (`--inspect`,
  `--compat-report`, layout options), version bump 3.0.0, presets include
  new engines where safe.
* Update README, OPTIONS, ARCHITECTURE, MINECRAFT, VERIFICATION,
  RELEASE_NOTES; write `docs/REPORT-3.0.md` (what changed, measured
  results, known limitations) and `docs/COMPATIBILITY.md` (tested
  toolchains/layouts with reproducible commands).
* Rebuild `dist/umbra.jar` + `dist/umbra-3.0.0.zip` + SHA256SUMS, final
  regression, cross-JDK run, demo, Minecraft, GUI screenshots.
* Clean generated junk (temp dirs, stale previews, build intermediates,
  duplicate archives), keep sources/QA evidence/deliverables; list every
  removed item in the report.

## Execution order

```
phase 0  baseline recon + plan + task board (Lead)                    done
phase 1  WS1 layout engine, WS2 passes, WS3 VM/native, WS4 GUI,
         WS5 plugins, WS6 corpus build (parallel teammates)
phase 2  Lead wires engine/config/CLI, builds, reports compile breaks
phase 3  QA matrix run #1 -> bug tickets -> owners fix -> run #2     loop
phase 4  version bump + docs/report + final packaging + cleanup
```

Write ownership is disjoint: compat owns `core/util/Jars.java`,
`core/compat/*`, verifier; protection owns its pass files/runtime ciphers;
vm owns VM2/native files; gui owns `gui/*`; integration owns `plugins/*`;
qa owns `qa/*`. Lead owns engine/config/CLI/build/docs. Shared edits go
through the Lead.

## Honest acceptance criteria

* `build.cmd` green (all suites), `dist/umbra.jar` runs on JDK 8, 21, 26.
* Demo protected with every preset prints `OK`; `--verify` OK.
* Every layout in WS1 executes after protection (real artifacts where
  possible).
* Every new feature has stats + tests + evidence; no claimed number without
  a run.
* Report lists residual limitations (native toolchain availability, JDK
  version ceilings, framework cases not covered) rather than hiding them.

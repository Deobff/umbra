# Umbra

**Umbra** is a commercial-grade Java bytecode protection suite: renaming,
encryption, control-flow, virtualization, native-code and anti-analysis layers
with a desktop GUI, a scriptable CLI, and Gradle/Maven build integration. It is
written in Java 8, depends only on ASM, and ships as one executable jar.
**Current release: 3.2.2** (one-time program state + `--set` reaches every typed section).

```bat
Umbra.cmd                         :: desktop console (JavaFX)
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset maximum --verify
```

## Capabilities

| Layer | Techniques |
|---|---|
| Compatibility | Spring Boot 2/3 fat JAR and WAR layouts, plain WAR, multi-release JARs (preserved or flattened), `module-info` remapping, signed-JAR stripping, agent manifests, OSGi headers, service/`spring.factories` rewriting, duplicate-entry tolerance, STORED nested-jar preservation; `--inspect` compatibility report and `--compat-report` JSON |
| Names | class/method/field renaming with hierarchy-correct overrides, package repackaging, dictionary and length control, mapping export/import, stable incremental mappings, reflection-aware keeps, annotation keep rules, framework presets |
| Data | per-site multi-engine string encryption (XOR / RC4 / ChaCha20 / AES-256-CTR / Speck), randomized per-class site indices, per-artifact domain salt, per-class keys, split payloads, optional `invokedynamic` bootstrap, decrypt-and-wipe and stack-trace hiding by default (plaintext cache is opt-in and off by default), encrypt-all; integer/long constant encryption, MBA arithmetic rewriting, metadata erasure |
| Control flow | opaque predicates (value/range/hash invariants), branch inversion, junk/dead blocks, independent-block transposition, bogus exception ranges, state-machine flattening with shuffled dispatchers, synthetic exception handlers, method splitting, wrapper indirection |
| Virtualization | method bodies translated into a custom instruction stream executed by an injected stack-machine interpreter; hardened VM2 engine with rolling-key opcode encoding, superinstruction fusion, encrypted split payloads, try/catch dispatch, per-thread state, nested dispatch, invokedynamic bridges and constructor bodies; optional Cantrip second layer |
| Native | eligible methods transpiled to C, compiled into a JNI library, bound back as `native` methods, loaded from an embedded DLL; anti-dump fingerprint + native-method backfill verification; graceful Java fallback on every failure path |
| Archive | whole-jar class/resource encryption (index v3) with a plaintext bootstrap loader, sample-bound master key (random site seed + ZIP comment + entry count), per-entry nonce in the KDF, HMAC-keyed class/resource/loader digests, anti-dump checks, sampled payload watchdog, minimized manifest |
| Anti-analysis | **unified Java runtime guard** (agent/attach/env/timing/JDWP/JMX signals, dynamic-attach watcher, watchdog, fail-closed class decryption) plus a hardened native guard (debugger/PEB/DRx, anti-remote-thread, executable-memory scan, memory-breakpoint/code-sampling, timing, module integrity, opt-in handle anti-dump, Linux `/proc` checks), self-integrity, keyed challenges, reference hiding via `invokedynamic`, reflection analysis and optional reflection seal, anti-LLM decoy/wrapper walls, watermarks, audit reports |
| Dynamic protection | runtime attach/debugger detection at entry points, before integrity checks and before every encrypted class decrypt; sticky fail-closed state; watchdogs with randomized intervals; plaintext/key buffer wiping; native DLL fingerprint + backfill challenge |
| Type confusion | static call ABI and private static field traffic routed through `Object[]`/`Object` carriers (KBox-style decompiler confusion, opt-in levels) |
| Metadata | decompiler/AI hardening levels 1–4: unknown attributes, contradictory debug tables, bogus signatures, phantom inner classes, class-level `Code` trap, EnclosingMethod/SourceDebugExtension/MethodParameters traps — JVM-legal and verifier-safe |
| Original engine | **Nocturne**: polymorphic keyed-argument method shadows with per-method ARX-encoded parameters and runtime-selected equivalent bodies |
| Delivery | deterministic seeds, keep rules, presets, incremental builds, mapping diff/trace, HTML/JSON audit reports, JVM verification, JavaFX desktop console, CLI + YAML + Gradle/Maven plugins |
| Mod containers | automatic Minecraft adaptation: Fabric/Quilt, Forge legacy/modern, NeoForge, mixin configs, access wideners/transformers and coremod manifests; keeps entry points, `@Mod`, Mixin classes/targets and referenced members |

## Quick start

```bat
:: GUI (JavaFX console, needs a JDK 8 with JavaFX)
Umbra.cmd
java -jar dist\umbra.jar --gui

:: CLI
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset balanced --verify
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset maximum --seed 23303
java -jar dist\umbra.jar -c umbra.example.yml --dry-run

:: inspect an input before protecting it (read-only)
java -jar dist\umbra.jar -i app.jar --inspect
java -jar dist\umbra.jar -i app.jar --inspect-json inspection.json
```

Presets: `library`, `spring-boot`, `jackson`, `service-loader`, `micronaut`,
`light`, `balanced`, `aggressive`, `maximum`, `nocturne`.

## Input handling

Any JAR produced by a normal build tool is accepted:

* **Spring Boot fat JAR / WAR** — classes under `BOOT-INF/classes/` (or
  `WEB-INF/classes/`) are transformed in place, nested libraries are preserved
  byte-identically (including their STORED compression), root loader classes are
  never renamed or rewritten, `Start-Class`/`Main-Class` are remapped, and the
  archive still boots. Whole-archive class encryption, the startup integrity
  seal and the native guard launcher are flat-JAR constructs and are skipped on
  nested layouts with an explicit warning.
* **Multi-release JARs** — `META-INF/versions/N/` and the `Multi-Release`
  attribute are preserved with one consistent mapping
  (`layout.multiRelease=preserve`, default); `flatten` returns a plain JAR.
* **Modular JARs** — `module-info` exports/opens/uses/provides are remapped
  (`layout.moduleInfo=auto|keep|drop`).
* **Signed JARs** — signatures are stripped; re-sign the output if needed.
* **Agents / OSGi / ServiceLoader** — `Premain-Class`/`Agent-Class` attributes,
  OSGi headers and `META-INF/services/*` are rewritten through the mapping.
* Duplicate entries are resolved deterministically instead of aborting.

See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for the layout model and the
tested input matrix.

## Minecraft mods

Mod containers are detected and adapted automatically (default on). Entry
classes/methods, `@Mod` classes, Mixin classes/targets/configs and referenced
target members are kept; mixin/target method bodies are exempted; conflicting
protections are downgraded automatically.

```bat
java -jar dist\umbra.jar -i mymod.jar -o mymod-obf.jar --verify
java -jar dist\umbra.jar -i mymod.jar -o mymod-obf.jar --set minecraft.forceVmp=true
java -jar dist\umbra.jar -i mymod.jar -o mymod-obf.jar --set minecraft.enabled=false
```

Details: [docs/MINECRAFT.md](docs/MINECRAFT.md).

## Build

Requirements: JDK 8+ (built with Zulu 8), Windows PowerShell 5.1 or newer.
ASM is vendored under `lib/`; no network access is needed.

```bat
build.cmd                    :: compile + self tests + dist\umbra.jar
build.cmd -Task compile      :: fast compile
build.cmd -Task test         :: compile + self tests
build.cmd -Task dist         :: executable jar
build.cmd -Task package      :: executable jar + distribution zip + SHA-256 sums
```

Linux/macOS: `pwsh build.ps1 -Task dist`.

## GUI

A JavaFX desktop console, shipped as `umbra-gui-fx.jar` next to the engine jar
(the engine jar itself stays JavaFX-free so it runs on any JDK 8). Launch it with
`Umbra.cmd` or `umbra-fx.cmd`; a JDK 8 that ships JavaFX is required (set
`JFX_JAVA_HOME` to point at one). Self-drawn window chrome, a configuration rail
grouping every switch and value the engine accepts, three views (Options /
Command / Output) in one segmented control, a targets band for input and output,
a preset selector that loads the engine's own effective values, live log,
progress, cancel, and an About window with the version and jar locations.

The engine jar no longer carries the old Swing console: `java -jar umbra.jar`
looks for `umbra-gui-fx.jar` next to itself and starts the console as a child
process, and prints the command line help when either the console jar or a
JavaFX-capable JVM is missing.

## CLI

```bat
java -jar dist\umbra.jar -i app.jar -o app-obf.jar ^
  --keep "com.example.Main" --preset aggressive ^
  --flatten --virtualize --anti-llm --verify --seed 23303
```

Advanced modules are configured through `--set`:

```bat
java -jar dist\umbra.jar -i app.jar -o app-obf.jar ^
  --set typeConfusion.enabled=true ^
  --set string.engine=auto --set string.wipe=true ^
  --set vm2.enabled=true --set vm2.fusion=true ^
  --set nocturne.enabled=true ^
  --set classEncryption.enabled=true --set classEncryption.resources=true ^
  --set integrity.enabled=true ^
  --set native.enabled=true --set native.compiler=E:/mingw64/bin/gcc.exe
```

Every key is documented in [docs/OPTIONS.md](docs/OPTIONS.md). Additional CLI
flags include `--inspect`, `--inspect-json`, `--compat-report`, `--mapping`,
`--report`/`--report-json`, `--input-mapping`, `--trace-watermark`,
`--diff-mapping`, `--license*`.

## Gradle / Maven

The official plugins live under `plugins/` and run the Umbra CLI as part of a
normal build, failing the build on any protection error:

```groovy
// build.gradle
plugins { id 'io.umbra' version '3.0.0' }
umbraProtect {
    toolJar = file("tools/umbra.jar")
    preset  = "balanced"
    verify  = true
}
```

```xml
<!-- pom.xml -->
<plugin>
  <groupId>io.umbra</groupId>
  <artifactId>umbra-maven-plugin</artifactId>
  <version>3.0.0</version>
  <executions><execution><goals><goal>protect</goal></goals></execution></executions>
</plugin>
```

Full parameter tables, CI examples and troubleshooting: [plugins/README.md](plugins/README.md).

## Repository layout

```
Umbra/
  build.ps1 / build.cmd / Umbra.cmd / umbra-cli.cmd
  lib/                       ASM
  src/main/java/io/umbra/    annotations, cli, core (api/config/compat/engine/
                             model/pass/runtime/rules/util), gui (control model)
  gui-fx/                    JavaFX console sources (separate jar, needs JavaFX)
  src/test/java/io/umbra/tests/
  plugins/                   Gradle + Maven plugins, samples, QA runner
  demo/  qa/  docs/  dist/
```

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes the pass pipeline and
core APIs; [docs/REFERENCE-MATRIX.md](docs/REFERENCE-MATRIX.md) records the
capability analysis of the tools studied for 3.0; [docs/REPORT-3.0.md](docs/REPORT-3.0.md)
is the 3.0 release report; [docs/REPORT-3.1.md](docs/REPORT-3.1.md) covers the
3.1 bug-hunt/dynamic-protection release and [docs/AUDIT-3.1.md](docs/AUDIT-3.1.md)
is the full audit findings table.

## Safety and scope

Umbra is a defensive engineering tool for protecting your own software. Only
apply it to code you own or are authorized to modify. Some techniques (native
code, encrypted loaders, anti-debug) are intentionally detectable by endpoint
security products; validate licensing, distribution and legal requirements
before shipping protected artifacts.

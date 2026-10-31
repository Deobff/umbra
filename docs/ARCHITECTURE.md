# Umbra Architecture

Umbra is a Java bytecode protector (obfuscator) written in Java 8 and built on
vendored ASM 9.11. It ships as one executable jar that runs either as a
command-line tool or with a desktop Java Swing GUI.

This document is the contract for everyone working on the project. If a change
crosses a boundary described here, coordinate with the Lead first.

## Repository layout

```
Umbra/
  build.ps1 / build.cmd        build, test, dist, package (no Gradle/Maven needed)
  lib/                         vendored ASM 9.11 jars (asm, tree, commons, analysis, util)
  src/main/java/io/umbra/
    annotations/               keep / transform annotations available to protected code
    cli/                       command-line front end, InspectTool (--inspect/--compat-report)
    core/
      api/                     Pass, PassContext, OutputPostProcessor, RuntimeSupport, ProgressListener
      compat/                  layout model: JarLayout, LayoutDetector/Options/Context/Registry,
                               ManifestRewriter, ModuleInfoRewriter, TextResourceRewriter, LayoutReport
      config/                  UmbraConfig (+ advanced options map), YAML loader/writer, presets
      engine/                  UmbraEngine (pipeline), Stats, MappingSet, verifier, incremental cache
      enterprise/              license, audit/risk reports, mapping tools, watermark tracer
      jni/                     C/JNI transpiler, compiler, guard generator
      minecraft/               mod-container detection and adaptation
      model/                   ClassPool (entry prefixes), Hierarchy, UmbraClassWriter
      pass/impl/               one class per transformation (order in the pipeline table below)
      runtime/                 template classes injected into protected programs (crypto/, vm2/)
      rules/                   keep-rule matching
      util/                    AsmUtil, Cipher, Jars (layout-aware read/write), Log, names, mapping
    gui/                       rewritten desktop GUI: GuiMain/GuiRoot/GuiConfig/GuiPresets/GuiSelfTest,
                               theme/ (tokens, aurora glass, icons), ui/ (all custom components)
  src/test/java/io/umbra/tests/                plain-main test harness classes (*Test)
  plugins/                     Gradle plugin, Maven plugin, samples, plugin QA runner
  demo/                        sample program used by the verification scripts
  qa/                          end-to-end harnesses and evidence (compat/, minecraft/, results-3.0/)
  docs/                        this file, OPTIONS.md, COMPATIBILITY.md, REPORT-3.0.md, ...
  dist/umbra.jar               packaged output
```

Main class: `io.umbra.cli.Main` (no args / `--gui` opens the GUI).

## Pipeline

`Jars.read` detects the archive layout through `io.umbra.core.compat`
(flat, Spring Boot fat JAR/WAR, plain WAR, multi-release, module-info) and
attaches a `LayoutContext` to the `ClassPool`; classes keep their physical
entry prefix and are addressed by internal name. Spring Boot loader classes at
the archive root are copied as opaque resources and never enter the class pool.

`UmbraEngine` then runs the mod-container adapter (see `docs/MINECRAFT.md`):
when the input carries Fabric/Forge/NeoForge/Quilt metadata, mixin
configurations or access wideners, it adds keep rules and body-transform
exemptions and downgrades conflicting features before any pass runs. Ordinary
jars are unaffected.

Whole-archive protections that install a root-level loader (class encryption)
are disabled on nested layouts with an explicit warning, unless
`layout.forceEntryProtection=true` overrides it; the same applies to the
startup integrity seal and the native guard launcher (they register root-level
launchers that a nested container loader would bypass).

Then it sorts passes by `Pass.order()` and runs each enabled pass once.

```
 12 reflection-analysis    analyse reflective call sites, add keep rules
 15 member-trim            remove unused private members
 20 field-initialization  move static constants into <clinit>
 30 debug-info            erase SourceFile/line numbers/locals/signatures
 40 member-shuffle        shuffle member declaration order
 45 invoke-wrapper        wrapper indirection for selected invokes
 48 parameter-obfuscation unused parameters
 50 rename                class/method/field/package renaming + mapping
 55 anti-llm              decoy methods, wrapper walls, shield
 58 resource-path-obf     rename resource paths (assets/...)
 60 method-virtualization  VM bytecode virtualization (classic engine / VM2)
 65 reference-obfuscation  hide static/virtual/field/constructor references (indy)
 67 type-confusion         static call ABI/field traffic through Object carriers
 70 string-encryption      multi-engine string encryption, stack-trace hiding, wipe
 80 integer-encryption     encrypt integer/long constants
 85 mba                    mixed boolean-arithmetic rewriting
 90 flow-obfuscation       opaque predicates, transposition, bogus ranges, junk
 92 control-flow-flattening opaque state-machine flattening
 95 exception-obfuscation  synthetic catch-all handlers
100 junk-members           add unused methods/fields
105 native-code            transpile eligible methods to C/JNI (anti-dump/anti-backfill)
106 nocturne               polymorphic keyed-argument method shadows
110 watermark              embed customer watermark
114 native-guard           native anti-debug/anti-tamper guard (flat layouts)
115 anti-debug             startup debug-agent guard
117 integrity              tamper/integrity guard (flat layouts)
118 auth-gate              optional server-backed authorization gate
119 reflection-gate        optional runtime reflection seal
120 resource-rewrite       rewrite class names inside text resources
200 class-encryption       register archive post-processor (flat layouts, after write)
```

After `Jars.write` (which returns a `LayoutReport` merged into the run
statistics) the engine runs every `OutputPostProcessor` registered on
`PassContext.postProcessors()` (archive-level encryption, integrity manifests).
`--verify` then loads the produced archive's classes — including
`BOOT-INF/classes`/`WEB-INF/classes` and nested library extraction — to force
JVM verification and layout structural checks.

## Core APIs

### Pass

```java
public interface Pass {
    String name();                     // stable id, appears in logs/stats
    int order();                       // pipeline position
    boolean enabled(PassContext ctx);  // cheap, option/config driven
    void run(PassContext ctx) throws Exception;
}
```

Rules:

* Passes must be **defensive**: catch per-method failures, log with
  `ctx.log().debug(...)`, and leave that method untouched. A pass failure must
  never abort an entire run because one exotic class was met.
* Passes must be **deterministic** for a given `ctx.config().seed()`; use
  `ctx.random()` only.
* Do not transform classes where `ctx.classes().isGenerated(name)` or
  `isFrozen(name)` is true, or where `!ctx.rules().transformClass(node)`.
  Generated/frozen classes are Umbra runtime helpers and kept boundaries.
* Report numbers via `ctx.stats().add("namespace.key", value)` and one info log
  line per pass: `ctx.log().info("pass-name: <what happened>")`.
* Never write files except explicitly documented outputs (mapping, report).
* New knobs go into the advanced options map (see OPTIONS.md) so the CLI,
  YAML and GUI share them. Read them with `ctx.config().optionBool/Int/...`.

### PassContext

Configuration, `ClassPool`, `Hierarchy`, `RuleSet`, `RuntimeSupport`,
`MappingSet`, `Stats`, `Log`, `Random`, `ProgressListener`, and the
`postProcessors()` list. Add new shared state only through the Lead.

### ClassPool

Mutable map `internalName -> ClassNode` plus resources and original bytes.
Helpers: `addGenerated(node)` (marks generated/frozen), `freeze(name)`,
`putRawOutput(name, bytes)` (raw archive entry, bypasses class writing),
`putResource`, `remove*, `setMainClass`, `mainClass()`.

### Hierarchy / UmbraClassWriter

`Hierarchy` answers common-superclass and member lookups for frame
computation; it knows input classes, libraries and the running JDK. Always let
`Jars.write`/`UmbraClassWriter.toBytes` compute frames (`COMPUTE_FRAMES`) after
your transformation; do not hand-write `StackMapTable` frames.

### RuntimeSupport / TemplateInjector

Runtime helpers are **ordinary classes inside the Umbra jar**
(`io.umbra.core.runtime.*`) compiled by the build. A pass copies one into the
protected pool under a random name with:

```java
String helper = TemplateInjector.inject(ctx.classes(), UmbraVM.class,
        "umbra/runtime/V", ctx.config().seed(), replaceMapOrNull);
```

The helper is renamed, mark-generic/synthetic and self-references are remapped.
Constraints: template classes must not declare nested or anonymous classes, and
must not reference other Umbra classes (inject references as remapped names via
the placeholder map or generated bytecode). JDK-only dependencies.

### OutputPostProcessor

For archive-level work: inside `run`, call
`ctx.postProcessors().add(processor)`. The engine invokes it after the writer,
before stats. Rewrite the jar atomically (write sibling temp file, then
`Files.move(..., ATOMIC_MOVE/REPLACE_EXISTING)`).

## Advanced options

`options:` in YAML and `--set key=value` on the CLI (also `-D key=value`).
The desktop GUI builds the same map from its controls. Keys are namespaced per
feature; see `docs/OPTIONS.md`. New keys are added by the owning pass, no config
schema edit needed.

## Build and test

```
build.cmd -Task compile     # javac src/main/java -> build/classes
build.cmd -Task test        # compile + run src/test/java runners
build.cmd -Task dist        # build/classes + lib -> dist/umbra.jar
build.cmd                   # all
```

The JDK is JDK 8 (`C:\Program Files\Zulu\zulu-8`). Plain `powershell -File
build.ps1` is blocked by execution policy; always use `build.cmd`.

Smoke test:

```
build.cmd -Task dist
java -jar dist/umbra.jar -i demo/demo.jar -o demo/out.jar --verify --virtualize --flatten
java -jar demo/out.jar
```

`demo/demo.jar` is a small Java 8 program with strings, loops, try/catch,
lambdas and fields; it prints `OK` on success. Use it for every change.

## Conventions

* Java 8 language level. No new dependencies, no reflection on JDK internals
  unless the feature is explicitly about it (native/Unsafe paths must degrade
  gracefully).
* Keep `-Xlint` clean; code must compile with the build script.
* Log lines are English; GUI labels are English.
* Test numbers are part of the deliverable: every new protection must show a
  non-zero count on the demo and the demo must still print `OK`.
* The output jar must stay runnable on JDK 8 and on a current JDK (21/25), and
  Umbra itself must run on JDK 8.

## File ownership (avoid concurrent edits)

| Area | Owner |
|---|---|
| build scripts, engine, config model, CLI, desktop GUI, docs, packaging | Lead |
| string/constant crypto, class encryption, integrity/anti-tamper | crypto |
| MBA, flow obfuscation, CFF, exception obfuscation | flow |
| virtualization pass + VM runtime | vm |
| native C/JNI pass + loader | native |
| desktop GUI | Lead |
| demo/qa harness, verification reports | qa |

Only the Lead edits: `UmbraEngine`, `PassContext`, `UmbraConfig`,
`ConfigLoader/Writer`, `cli/Main.java`, `gui/*`, `build.ps1`, this doc.
Everyone else edits their own pass/runtime/test files and may add new files.
If a shared edit is required, send the Lead a message with the exact change.

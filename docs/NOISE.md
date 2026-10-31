# Decompiler-noise metadata hardening

`decompiler-noise` (pass order 35) adds JVM-legal but analyst-hostile metadata.
The JVM verifier, loader and linker ignore everything it writes; decompilers,
disassemblers, AI-assisted reverse engineering and "clean up this class file"
automation waste time on conflicting debug tables, phantom generic signatures
and attributes with impossible names or locations.

It is **not** a security boundary: bytecode semantics do not change, so a
determined analyst with a tolerant toolchain can still recover the program. It
raises cost and lowers the quality of automated output.

Implemented by `DecompilerNoisePass` plus the helpers in
`io.umbra.core.pass.impl.noise` (`ClassNoise`, `NoiseGenerator`,
`NoiseBudget`, `NoiseAttribute`).

## Options

| key | type | default | meaning |
|---|---|---|---|
| `decompilerNoise.enabled` | bool | `true` | run the pass |
| `decompilerNoise.level` | int 1..3 | `1` | cumulative strength; values outside 1..3 are clamped |

Example:

```
java -cp "build\classes;lib\*" io.umbra.cli.Main -i demo\demo.jar -o out.jar \
  --seed 424242 --set decompilerNoise.level=3 --verify
java -jar out.jar
```

## Levels

Levels are cumulative. Every level is deterministic per seed and bounded (see
below).

### Level 1 - safe (default)

Only metadata that the JVM never inspects functionally:

* 2-5 **unknown class attributes** with random names and random/zero-length
  payloads, some named like other tooling (`ScalaSig`, `TastyHeader`,
  `Kotlin.Metadata`, ...); plus unknown attributes on fields and methods;
* an **oversized, truncated `SourceDebugExtension`** (256-768 bytes, ending in
  non-printable bytes mid-record), typically a fake SMAP for a `.kt`/`.java`
  file that does not exist;
* contradictory, duplicated and unordered **`LineNumberTable`** rows with
  random line numbers (0 and 65535 included) pointing at real opcode offsets;
* the **`LocalVariableTable`** is replaced with rows whose names contain
  invisible Unicode characters and whose descriptors do not match the real
  values; slot indices and descriptor widths remain legal;
* odd **`MethodParameters`** names (invisible characters) for Java 8+ class
  files;
* synthetic empty attributes.

Class loading, verification, linking and execution are unchanged. Reflection
still works; only debug names change.

### Level 2 - strong

Adds metadata that the JVM still ignores at load time but that reflection and
decompilers parse:

* generic **`Signature`** attributes are replaced on classes, methods and
  fields with syntactically valid signatures that reference missing classes or
  undeclared type variables, e.g. `<T:Lnoise/Ab/Def;>(TT;)TT;`;
* phantom **`InnerClasses`** rows for classes that do not exist (with a
  non-resolvable outer class, so `getDeclaredClasses()` is not affected);
* denser line-number/local-variable noise and wrong-location
  `ConstantValue` method attributes.

Generic reflection on affected members fails
(`TypeNotPresentException` / `GenericSignatureFormatError`), so level 2 is
opt-in for libraries that rely on generic introspection (serialization
frameworks, dependency injection, some ORMs).

### Level 3 - hostile

Adds the decompiler traps:

* a **class-level attribute named `Code`** - the JVM only recognises `Code`
  inside a method, so it is silently ignored there; CFR 0.152 drops the whole
  class when it sees it;
* **wrong-location method attributes** (`LineNumberTable`, `StackMapTable`,
  `LocalVariableTable`, `ConstantValue`, `SourceFile` on the method), which the
  JVM skips but many parsers do not expect;
* **large junk attributes** (class- and method-level blobs, bounded);
* **fake declared exceptions** from the JDK (`java.lang.RuntimeException`,
  `Exception`, `Error`) - resolvable, so the VM links fine, but
  `getExceptionTypes()` reports exceptions the method never throws;
* heavy tables: up to ~112 line-number rows and up to 14 local-variable rows
  per method, plus a fake `SourceFile`.

A whole archived class still loads and runs normally; CFR no longer produces
source for it.

## Bounds and determinism

| level | per-class payload budget | global payload budget |
|---|---|---|
| 1 | 1 KB | 512 KB |
| 2 | 8 KB | 1 MB |
| 3 | 24 KB | 4 MB |

Budget accounting is payload bytes plus a small per-attribute header estimate.
Once a budget is exhausted the remaining attributes are skipped, so output
stays deterministic: the same input + seed + configuration produce a
byte-identical archive; a different seed produces different noise.

## What is never touched

* classes where `context.classes().isGenerated(...)` or `isFrozen(...)` is true;
* classes kept by the rule set (`!rules.transformClass(node)`);
* **body-skip classes** (`rules.skipBodyTransform`): Mixin classes and their
  targets must keep their exact bytecode shape, so the pass skips them;
* `module-info` (rigid attribute set, no benefit);
* bytecode instructions: only labels, line numbers and metadata are added, no
  opcode is added, removed or reordered.

When anti-LLM wrapping is enabled, methods that `AntiLlmPass` could wrap do not
receive method attributes (that pass skips methods with custom attributes);
debug-table noise is still added to them. This keeps the two features from
cancelling each other.

## JVM legality constraints (found empirically)

These were verified while implementing the pass; each one shaped the design:

| attempt | observed JVM behaviour |
|---|---|
| `LineNumberTable` start_pc pointing at `code_length` | `ClassFormatError: Invalid pc in LineNumberTable` - line numbers must reference a real opcode |
| `LocalVariableTable` index >= `max_locals` (or descriptor width overflow) | `ClassFormatError: Invalid index N in LocalVariableTable` |
| invalid local-variable descriptor (`Q`) | `ClassFormatError: Field ... has illegal signature "Q"` |
| duplicate `SourceFile` | `ClassFormatError: Multiple SourceFile attributes` |
| duplicate `SourceDebugExtension` | accepted by JDK 8, rejected by JDK 21/26 (`Multiple SourceDebugExtension attributes`) - not emitted |
| duplicate `Signature` / `InnerClasses` / `Code` | rejected by JDK 21/26 - not emitted |
| fake `Exceptions` entry for a missing class | `NoClassDefFoundError` **at class load** (HotSpot resolves them eagerly) - only real JDK exception classes are used |
| truly malformed `Signature` (`"["`, `"("`) | JVM ignores it, but ASM's `ClassRemapper` crashes in the rename pass - only grammar-valid signatures are emitted |
| class-level attribute named `Code` | ignored by JDK 8 / 21 / 26 (unknown attribute rule), but CFR drops the class |
| method-level `LineNumberTable`/`StackMapTable`/`LocalVariableTable`/`ConstantValue`/`SourceFile` | ignored by JDK 8 / 21 / 26 |
| invalid `MethodParameters` names (`"1bad name\u200b"`, `"<>"`) | accepted by JDK 8 / 21 / 26 |

Not emitted on purpose: `NestHost`/`NestMembers` (nest-based access control could
throw `IllegalAccessError`), duplicate standard attributes, and anything that
makes the loader resolve a missing class.

## Verified evidence

Environment: Windows, Zulu JDK 8, JDK 21.0.10, JDK 26.0.1; CFR 0.152
(`qa/tools/cfr-0.152.jar`); `demo/demo.jar` obfuscated with its normal pipeline
plus the noise pass, seed 424242, `--verify`.

| noise | engine exit | jar size | noise stats | JDK 8/21/26 `java -jar` | CFR `.java` files |
|---|---|---|---|---|---|
| off | 0 | 60,130 B | - | OK / OK / OK | 23 |
| level 1 | 0 | 78,861 B | 25 classes, 700 attributes, 22,611 B | OK / OK / OK | 23 (functional) |
| level 2 | 0 | 127,269 B | 25 classes, 2,634 attributes, 102,908 B | OK / OK / OK | 23 + 73 "Ignored method signature" warnings |
| level 3 | 0 | 486,591 B | 25 classes, 10,567 attributes, 601,222 B | OK / OK / OK | 3 (only skipped classes remain) |

Notes on the CFR column (from `--outputdir` and `summary.txt`):

* level 1: CFR decompiles every class exactly like the baseline; the noise is
  visible in `javap -v` (`Error: unknown attribute`, `SourceDebugExtension:`,
  contradictory debug tables) but not fatal.
* level 2: CFR still emits all classes, but every method signature is rejected
  (`Ignored method signature, as it can't be verified against descriptor`), so
  the generic structure in its output is gone.
* level 3: all 22 obfuscated application classes are dropped by CFR; the 3
  files it still produces are the classes this pass deliberately skips (the
  reflection-kept `demo.ReflectionProbe` and two generated Umbra runtime
  helpers). `java -jar` still prints `OK` on all three JDKs.

`javap -v` on a level-1 class shows `SourceDebugExtension:` and several
`Error: unknown attribute` lines; on a level-3 class it additionally shows
`Exceptions:` entries the source never declares. These are class-file
attributes only; the JVM executes the same code.

Stats are reported by the pass and appear in the engine report:

```
decompiler-noise: level=1, 25 classes, 700 attributes, 22611 bytes
```

(`noise.level`, `noise.classes`, `noise.attributes`, `noise.bytes` in stats.)

## Test coverage

`src/test/java/io/umbra/tests/DecompilerNoiseTest.java` (plain-main runner, part
of `build.cmd -Task test`):

* builds ASM `ClassNode`s (static methods with int/long/String arguments) and
  applies every level, asserting the expected attribute kinds are present and
  the per-class budget is respected;
* serializes through the production `UmbraClassWriter`, re-parses with ASM,
  defines the class in a class loader and executes it - proving JVM legality;
* checks that level 2+ breaks generic reflection and level 3 exposes fake
  declared exceptions;
* verifies determinism (same seed -> identical bytes, different seed ->
  different noise);
* verifies the pass skips frozen/generated/kept/body-skip classes and reports
  the `noise.*` stats;
* runs the full engine on `demo/demo.jar` at every level in-process (no child
  JVM/classpath dependency), verifies every class with `UmbraVerifier`, runs
  `java -jar` on JDK 8 and, when present, JDK 21/26;
* measures CFR: level 1 must keep decompiling, level 3 must lose the majority
  of classes.

The full suite (10 runners) is green with this test at 114 checks.

## Limitations

* Effects are decompiler-specific. CFR 0.152 is measured; Procyon, Fernflower,
  JD-CLI and AI assistants were not part of the matrix. A tool that ignores
  unknown attributes can still decompile level-3 classes.
* Level 2+ breaks generic reflection on affected members; do not use it for
  libraries whose consumers introspect generics.
* Level 1 replaces the local-variable table: stack traces keep line numbers but
  local variable names in debuggers become junk. `MethodParameters` names are
  visible through `java.lang.reflect.Parameter#getName`.
* Level 3 increases the archive size substantially (about +0.6 MB for the 60 KB
  demo archive); use it for delivery builds, not for tight jars.
* Mixin classes/targets and kept classes are skipped, so their metadata stays
  clean (intentional - they must keep their exact shape).
* `refmap`/`@At`-style external references are not relevant to this pass, but
  remember that renaming still runs after it: mixin analysis keeps referenced
  names through the existing keep rules.
* The pass does not encrypt code or hide control flow; pair it with the other
  protections.

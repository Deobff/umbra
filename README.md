# Umbra

Umbra is a commercial-grade Java bytecode protection suite. It is written in
Java 8, depends only on ASM, and ships as a single executable JAR with a
desktop GUI, a scriptable CLI, YAML configuration, and Gradle/Maven build
integration.

## Features

### Archive compatibility
- Spring Boot 2/3 fat JARs and executable WARs, plain WARs, multi-release JARs,
  modular (JPMS) JARs, signed JARs, Java agents, OSGi bundles.
- Preserves nested class prefixes, Spring Boot nested libraries (including
  STORED compression), `module-info` descriptors, Multi-Release output,
  `spring.factories` / `AutoConfiguration.imports`, ServiceLoader metadata and
  framework manifests.
- Layout inspection, compatibility reports and a verifier that loads every
  emitted class.

### Renaming and metadata
- Hierarchy-correct class/method/field renaming, package repackaging,
  dictionary and length control, mapping export/import, incremental mappings.
- Reflection-aware keeps, annotation keep rules, framework and Minecraft
  presets; optional package/API preservation.
- Debug metadata erasure (source file, line numbers, local variables), member
  shuffling, junk members and watermarking.

### Data protection
- Per-site string encryption with XOR, RC4, ChaCha20, AES-256-CTR and Speck,
  randomized per-class site indices, per-artifact domain salt, per-class keys,
  split payloads, optional `invokedynamic` bootstrap, stack-trace hiding,
  decrypt-and-wipe and encrypt-all modes; plaintext caching is opt-in and off
  by default.
- Integer/long constant encryption, MBA arithmetic rewriting, array/constant
  obfuscation.

### Control flow
- Opaque predicates (value/range/hash invariants), branch inversion, dead/junk
  blocks, block transposition, bogus exception ranges, synthetic exception
  handlers, state-machine flattening, method splitting, wrapper indirection.

### Virtualization
- Custom stack-machine interpreter for eligible method bodies.
- Hardened VM2 engine: rolling-key opcode encoding, superinstruction fusion,
  encrypted split payloads, try/catch dispatch, per-thread state, nested
  dispatch, invokedynamic bridges and constructor bodies.
- Optional Cantrip second virtualization layer.

### Native code
- Eligible methods transpiled to C, compiled into an embedded JNI library and
  bound back as `native` methods.
- Anti-dump fingerprints, native-method backfill verification, keyed
  challenges, constructor-body extraction and graceful Java fallback.

### Class and archive encryption
- Whole-JAR class/resource encryption with a plaintext bootstrap loader,
  sample-bound master key (random site seed + ZIP comment + entry count),
  per-entry nonce in the key derivation, HMAC-keyed class/resource/loader
  digests, sealed index, anti-dump checks and a sampled payload watchdog.
- Startup integrity manifests and runtime re-verification.

### Dynamic protection
- Runtime guard for debuggers, agents, dynamic attach, JDWP, JMX, heap-dump
  flags, environment markers, instrumentation and timing anomalies.
- Java and native anti-analysis guards: debugger APIs, PEB, debug registers,
  Frida modules/pipes/threads/environment, module and memory integrity,
  memory breakpoints, code-section sampling, watchdog checks.
- Sticky fail-closed state, configurable actions (`throw`, `exit`, `corrupt`,
  `log`), encrypted-class refusal and plaintext/key buffer wiping.

### Decompiler and analysis hardening
- Type confusion via `Object`/`Object[]` carriers for static calls and private
  static fields.
- Decompiler/AI noise levels: unknown attributes, contradictory debug tables,
  bogus signatures, phantom inner classes, code-attribute traps.
- Reference hiding through `invokedynamic`, reflection gate and anti-LLM decoy
  methods/wrapper layers.
- Nocturne polymorphic method shadows with keyed arguments and runtime-selected
  equivalent bodies.

### Build and tooling
- Deterministic seeds, presets (`light`, `balanced`, `aggressive`, `maximum`,
  `nocturne`, framework presets), keep rules and incremental builds.
- Desktop GUI with per-mode detailed option sheets (names, data, flow,
  virtualization, native, archive encryption, anti-debug, type confusion,
  compatibility, output) and animated sliders for every numeric option.
- Smooth 60 fps UI animations (switches, chips, group expand/collapse, buttons,
  status/console fades) with a deterministic off switch for screenshots.
- CLI, YAML configuration, mapping diff/trace, HTML/JSON audit reports and JVM
  verification.
- Gradle plugin (`io.umbra`) and Maven plugin (`umbra:protect`).
- Automatic Minecraft mod-container adaptation: Fabric/Quilt, Forge
  legacy/modern, NeoForge, mixins, access wideners/transformers and coremod
  manifests.

# Umbra advanced options

Umbra has two configuration layers:

1. The typed sections (`renamer:`, `stringEncryption:`, ...) used by the core
   pipeline. These are stable and documented in `umbra.example.yml`.
2. The **advanced option map**, used by newer protection modules. Same map in
   YAML (`options:`), CLI (`--set key=value`, alias `-D key=value`) and the GUI
   JSON payload. Values are strings; consumers parse them with
   `UmbraConfig.optionBool/optionInt/optionLong/optionDouble/option`.

```yaml
options:
  vm2.enabled: "true"
  vm2.encryptPayload: "true"
  native.enabled: "true"
  native.compiler: "E:/1111/bin/gcc.exe"
  classEncryption.enabled: "true"
  mba.enabled: "true"
```

```bat
java -jar dist\umbra.jar -i in.jar -o out.jar ^
  --set vm2.enabled=true --set native.enabled=true
```

Unknown keys are preserved and round-trip through YAML, so a newer GUI can
drive an older engine without losing settings.

## Keys

### `mba.*` — mixed boolean-arithmetic constants (flow)

| key | type | default | meaning |
|---|---|---|---|
| `mba.enabled` | bool | false | rewrite arithmetic constants through MBA identities |
| `mba.depth` | int 1..4 | 2 | number of nested rewrites per expression |
| `mba.ints` | bool | true | rewrite int/long arithmetic |
| `mba.floats` | bool | false | also rewrite float/double via bit tricks |
| `mba.maxPerMethod` | int | 400 | cap rewritten expressions per method |

### `vm2.*` — next-generation virtualization engine (vm)

| key | type | default | meaning |
|---|---|---|---|
| `vm2.enabled` | bool | false | use the hardened VM engine instead of the classic safe subset |
| `vm2.maxInstructions` | int | 2000 / 4000 | per-method instruction budget; the presets set 2000 (`balanced`) / 4000 (`maximum`) |
| `vm2.encryptPayload` | bool | true | encrypt the VM payload with a per-method key |
| `vm2.opcodeMap` | bool | true | permute opcode numbers per program |
| `vm2.trys` | bool | true | virtualize methods with try/catch tables (translated handler dispatch) |
| `vm2.news` | bool | false | support `new`/`<init>` (Unsafe allocation; opt-in) |
| `vm2.nested` | bool | true | protect the interpreter with an outer encrypted dispatch layer |
| `vm2.holders` | int 1..8 | 2 | payload block holder classes per method (plus one outer-program holder when `vm2.nested`) |
| `vm2.fusion` | bool | true | superinstruction fusion (format v4 rolling opcode key; format v3 payloads remain readable) |
| `vm2.dispatchShardSize` | int 128..8192 | 1024 | payloads per generated dispatcher class. A single dispatch method grows by ~13 bytes per payload (one switch case plus one invokestatic) and would hit the 64 KiB JVM method limit near 5,000 virtualized methods, so the table is split across generated classes; the interpreter entry maps `id` to its shard with one division. Lower values mean more classes, higher values fewer classes but a bigger method |
| `vm2.constructors` | bool | false | extract constructor bodies after `super()` into virtualizable helpers |
| `vm2.indy` | bool | true | generate invokedynamic bridges so lambda/string-concat methods can be virtualized |

### `cantrip.*` - Cantrip second VM layer (vm)

| key | type | default | meaning |
|---|---|---|---|
| `cantrip.enabled` | bool | false | reconstruct VM2 payload chunks with the injected Cantrip dialect interpreter |
| `cantrip.level` | int 1..2 | 1 | level 1 wraps payload chunks; level 2 also wraps the VM2 map/meta holder |
| `cantrip.seal` | bool | true | substitute the dialect through a per-build opcode table and ChaCha20-encrypt the program text (the artifact carries base64 blobs instead of `~value;.` programs); `false` keeps the plain dialect layer |

Requires `methodVirtualization.enabled=true` and `vm2.enabled=true`. See
[CANTRIP.md](CANTRIP.md).
### `native.*` — C/JNI code generation (native)

| key | type | default | meaning |
|---|---|---|---|
| `native.enabled` | bool | false | transpile eligible methods to C and bind them back with JNI |
| `native.compiler` | path | auto | C compiler (`gcc`/`clang`/`cc`); auto-detected when empty |
| `native.compilerFlags` | string | "" | extra flags appended to the compile command |
| `native.maxInstructions` | int | 400 / 800 / 1600 | per-method bytecode budget; the presets scale it with the tier |

The four instruction ceilings are eligibility thresholds ("never transform a body larger
than this"), and `light` / `balanced` / `maximum` scale them:

| ceiling | light | balanced | maximum |
|---|---|---|---|
| `flowObfuscation.maxInstructions` (flow, flattening, exceptions) | 2000 | 4000 | 8000 |
| `methodVirtualization.maxInstructions` | 1000 | 2000 | 4000 |
| `vm2.maxInstructions` | - | 2000 | 4000 |
| `native.maxInstructions` | 400 | 800 | 1600 |

A single shared value made `light` as expensive per method as `maximum` on large
methods; the ladder keeps each tier's promise. Every value can still be overridden
per build with `--set`.
| `native.maxMethodsPerClass` | int | 0 | cap; 0 = unlimited |
| `native.methods` | glob list | `*` | methods eligible (`Class#method`) |
| `native.exclude` | glob list | "" | methods excluded |
| `native.keepDll` | bool | false | keep the generated source/library next to the output jar |
| `native.target` | enum | windows | `windows`, `linux`, `macos` |
| `native.arch` | enum | auto | `x86_64`, `aarch64`, `x86` |
| `native.atomic` | bool | true | fall back to Java if compilation fails |
| `native.antiDump` | bool | true | embed a SHA-256 fingerprint of the compiled library and refuse a dumped/rebuilt/patched payload before `System.load` |
| `native.antiBackfill` | bool | true | XOR-encrypted native-method backfill table + JNI_OnLoad self-check + keyed challenge; refuses foreign/backfilled bindings |
| `native.constructors` | bool | true | extract constructor bodies after `super()` into native helpers |
| `native.indy` | bool | true | generate invocation bridges for lambda/string-concat methods |

Native anti-dump is hardening, not cryptographic authentication: the
fingerprint/key material necessarily ships inside the artifact, so a determined
attacker who patches both the Java loader and the library can bypass it. It
defeats the standard "dump the DLL and rebind it with a costume loader" attack.

### `string.*` — string protection strength (crypto)

| key | type | default | meaning |
|---|---|---|---|
| `string.algorithm` | enum | chacha20 | legacy single-engine selector: `xor`, `chacha20`, `aes-ctr` |
| `string.engine` | enum | auto | `auto` picks a per-site engine from `string.engineOrder`; or force `xor`, `rc4`, `chacha20`, `aes-ctr`, `speck` |
| `string.engineOrder` | list | chacha20,aes-ctr,rc4,speck | per-site engine rotation order for `string.engine=auto`; unknown tokens are ignored and counted |
| `string.siteSalt` | number/text | derived from seed | per-artifact domain salt for the v3 string schedule (decimal/hex number, other text is SHA-256-hashed); random per build by default |
| `string.perClassKey` | bool | true | derive a key per class instead of per site |
| `string.split` | bool | true | split payloads across several constants |
| `string.indy` | bool | false | decrypt through `invokedynamic` (bootstrap) instead of a helper call |
| `string.cache` | bool | **false** | memoize decrypted strings per call site; opt-in only (a plaintext cache is a heap-dump target, so the default decrypts and wipes per call) |
| `string.splitParts` | int 1..4 | 2/3 | payload fragments when `string.split=true` (preset-dependent) |
| `string.strength` | int 1..3 | 2 | composite preset: 1 = xor/no-split/no-cache, 2 = chacha20/split2/no-cache, 3 = chacha20/split3/no-cache/minLength 1 |
| `string.stackTraceHide` | bool | false | also encrypt throwable/stack-trace helper strings that leak method names; sanitizes decryptor failures (empty message/stack) |
| `string.otpEngines` | bool | false (`balanced`, `maximum`, `aggressive`: true) | store two ciphertexts per selected site under two different engines and let the injected one-time state (`carrier()` low bit) pick one per call, so consecutive calls at the same site take different decryption paths; indy sites, XOR sites, short literals and sites above the cap stay single-engine |
| `string.otpMaxSites` | int | 16 (`maximum`, `aggressive`: 32) | per-class cap on dual-ciphertext sites (bounded size growth: `sites × length`, about +33 % after base64 per converted site) |
| `string.wipe` | bool | false | decrypt into a temporary buffer and wipe it after the value is copied |
| `string.encryptAll` | bool | false | encrypt every string constant regardless of length/known-safe heuristics |

### `classEncryption.*` — archive encryption + bootstrap loader (crypto)

| key | type | default | meaning |
|---|---|---|---|
| `classEncryption.enabled` | bool | false | encrypt every class file and swap the entry point to a loader |
| `classEncryption.algorithm` | enum | chacha20 | `chacha20`, `aes-ctr` |
| `classEncryption.integrity` | bool | true | verify decrypted classes/resources with HMAC-keyed digests; encrypted archives always run at integrity level ≥ 2 (per-class keyed digest on every decrypt/define) |
| `classEncryption.antiDump` | bool | true | refuse loading from rewritten/partial archives (agent-arg detection is delegated to the unified runtime guard when anti-debug is enabled) |
| `classEncryption.loaderClass` | internal name | auto | fixed loader name (for tooling); empty = random |
| `classEncryption.entry` | class#method | auto | explicit entry point for the loader |
| `classEncryption.masterBinding` | enum | sample | `sample` = master key bound to a random 32-byte `siteSeed`, the ZIP comment and the archive entry count (two builds differ; editing the comment or adding/removing an entry makes every payload unreadable). `seed` = documented diagnostic fallback (no comment/entry-count binding) |
| `classEncryption.watchdogMs` | int | 4000 | sampled payload-watchdog base interval; every tick re-verifies ~1/20 of the class/resource payloads, level 3 does a full pass every 20th tick; a heartbeat lets the decrypt path fail closed if the watchdog thread is suspended |

When `antiDebug.level > 0` the loader resolves and calls the same injected
unified runtime guard before decrypting or defining any class: a guard signal
makes it refuse the decrypt/define (fail-closed, also for `action=log`), decrypted
class bytes and per-class key buffers are wiped after `defineClass`, and per-class
keyed digests are still verified. The guard class itself is an encrypted payload
resolved through the loader.

Archive format is **index v3**: per-entry keys mix the payload nonce into the KDF
(`HMAC(master, "c:"+name || nonce)`), class/resource/loader digests are
HMAC-keyed (`HMAC(master, "d:c:"+name || plaintext)` etc.) so a dumped payload
cannot be validated offline without the master key, `readString` lengths are
bounded (1 MiB) and payload algorithms are restricted to ChaCha20/AES-CTR (no dead
XOR branch). Runtime failures are silent (empty stack trace, no fixed
`[umbra-guard]` prefix; a random short log token is used for `action=log` and
diagnostics only with `-Dumbra.debug=true`), and injected runtime templates are
stripped of `SourceFile`/`LineNumberTable`/`LocalVariableTable`. Archives built by
3.0/3.1-pre (index v2) are not loadable by the v3 loader.

Finding P0-3 from the demo-obf analysis (moving detection into native code and
mixing a runtime environment fingerprint into the class-encryption KDF) is
**design-only for 3.2** and intentionally not implemented in 3.1: a
fingerprint-dependent KDF changes payload bytes per environment and needs the
native guard to be a hard build dependency. 3.1 delivers the P0-1/P0-2/P1-4/P1-6
and P2 items above instead; no `classEncryption.fingerprintBinding` option is
wired yet (documented gap, not a no-op option).

### `integrity.*` — startup tamper guard (crypto)

| key | type | default | meaning |
|---|---|---|---|
| `integrity.enabled` | bool | false | install the startup integrity guard |
| `integrity.level` | int 1..3 | 1 (2 for class encryption) | 1 = archive digest, 2 = + per-class digests, 3 = eager hashing + watchdog re-check. For encrypted archives the value is clamped to ≥ 2 (per-class keyed digest cannot be disabled); `classEncryption.integrity=false` is the explicit opt-out |
| `integrity.action` | enum | throw | `exit`, `throw`, `corrupt`. Kept at `throw`: a tampered payload must fail loudly for legitimate users, so `corrupt` is opt-in per release |
| `integrity.antiDump` | bool | true | detect dumped/rewritten class bytes |

With `integrity.antiDump=true` the integrity pass reuses the injected unified
runtime guard (the same seed-derived class the anti-debug pass uses) and runs it
before trusting the archive digests; when anti-debug is disabled the guard is
injected at level 2 for this purpose. The integrity guard and its log messages
report the shared class (`runtimeGuard` in the run stats/log).

### `antiDebug.*` — debugger / instrumentation checks (crypto)

| key | type | default | meaning |
|---|---|---|---|
| `antiDebug.level` | int 0..3 | 2 | 0 = off, 1 = JVM args + agent args, 2 = + attach detection (JDWP listener property, `JDWP*` threads, `.attach_pid<pid>`/`.java_pid<pid>`, real dynamic-attach watcher), env markers, JMX remote, Linux `/proc` tracer/module checks and timing drift, 3 = + randomized daemon watchdog (suspend/interval drift) |
| `antiDebug.enabled` | bool | false | enables level 2 when `level` is absent (alias for `protection.antiDebug`) |
| `antiDebug.action` | enum | throw | `exit`, `throw`, `corrupt`, `log`. `corrupt` (poison later work instead of a loud exception) is recommended for offline releases but is not the default: it must be gray-released because a legitimate trigger then fails quietly |
| `antiDebug.thread` | bool | true | background randomized watchdog thread at level 3 (daemon, single instance) |
| `antiDebug.jvmti` | bool | true | detect JVMTI agents (`-javaagent`/`-agentlib`/`-agentpath`/`-Xrun*`, dynamic-agent-loading flag) and remote JMX management properties |
| `antiDebug.attach` | bool | true | attach detection family: `sun.jdwp.listenerAddress`, `JDWP*` threads, attach-pid artifacts; enables the dynamic-attach watcher |
| `antiDebug.attachWatch` | bool | true | daemon attach watcher at level ≥2: `WatchService` on `java.io.tmpdir` for transient `.attach_pid<pid>`/`.java_pid<pid>` create/delete (50 ms scan fallback) plus a high-frequency attach-thread sample for a live `sun.instrument`/`loadAgent` frame (real dynamic attach) and a new `JDWP*`/`Attach Listener` thread compared with the install-time snapshot; on a hit a random-token `attach detected` log (log action) and the configured action |
| `antiDebug.portProbe` | bool | false | opt-in diagnostic JDWP `JDWP-Handshake` probe of the advertised ports and the common debug ports (5005, 8000–8009). OFF by default: a foreign local JVM on a common debug port must not flag a clean protected process; startup JDWP is already detected via JVM args/property |
| `antiDebug.env` | bool | true | flag `FRIDA_*`/`GUM_*` variables, agent/debug flags in `JAVA_TOOL_OPTIONS`/`_JAVA_OPTIONS`/`JDK_JAVA_OPTIONS`, and Frida/Gum `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` |
| `antiDebug.timing` | bool | true | randomized timing / anti-suspend check at level 2 (2 s slack) and watchdog interval-drift check at level 3 |
| `antiDebug.watchdogMs` | int | 4000 | randomized watchdog base interval (± up to 50 % jitter); shared with the native guard |

Additional level-2 signals from analysis finding P2-6 (each probe individually
try/caught, no clean-JVM false positives): `-XX:+HeapDumpOnOutOfMemoryError` /
`-XX:+HeapDumpBeforeFullGC` (a heap dump would expose decrypted classes) and
`jdk.attach.allowAttachSelf=true` (self-attach debugger path). Live
HotSpotDiagnosticMXBean heap-dump invocation and SIGQUIT handler inspection are
not observable from pure Java without altering JVM state, so they remain native/
JVMTI-side gaps (see audit notes).

The anti-debug pass injects the unified `UmbraRuntimeGuard` template once under a
seed-derived name; the integrity pass and the encrypted-archive loader reuse the
same injected class (one detector, no duplicate code). A clean launch stays
silent: an `Attach Listener` daemon thread exists in every clean HotSpot JVM and
is deliberately not a signal by itself (only a later appearance or a live
`sun.instrument` frame on it counts). A background attach signal cannot be thrown
into the program's main thread, so `antiDebug.action=throw` halts with exit code 1
there (same fail-loud rejection as `exit`).

### `flow.*` / `exception.*` — extra knobs (flow)

| key | type | default | meaning |
|---|---|---|---|
| `flow.maxBlocks` | int | 512 | skip flattening methods with more basic blocks |
| `flow.aggressive` | bool | false | aggressive profile: enables transposition + bogus exception ranges (defaults to true for the `aggressive` preset) |
| `flow.transpose` | bool | =aggressive | transpose independent basic blocks to break source order |
| `flow.bogusRanges` | bool | =aggressive | add verifier-safe bogus exception range entries |
| `flow.reorder` | bool | false (`balanced`, `maximum`, `aggressive`: true) | method-level block scheduling: lift independent blocks out of the body, append them in shuffled order and repair every fall-through edge with a `GOTO` (the ZKM `MethodFlowAnalyzer` idea) |
| `exception.level` | int 1..3 | 2 | amount of synthetic handler/dead-throw noise |

Current MBA coverage: int/long ADD/SUB/XOR/AND/OR plus integer constants;
`mba.floats` is accepted but currently ignored, and IMUL/array sizes/indexes,
switch selectors and multi-dimension sizes are left literal on purpose.

### `otp.*` — one-time program state (flow, opt-in)

| key | type | default | meaning |
|---|---|---|---|
| `otp.enabled` | bool | false (`balanced`, `maximum`, `aggressive`: true) | advance a shared one-time state at the entry of every protected method |
| `otp.native` | bool | true | hand the advance to the generated native guard when one is built |

When `otp.enabled` is on, `FlowObfuscationPass` injects the
`UmbraOtp` runtime template (randomized name, like the decryptor/VM helpers) and
replaces the method-entry carrier with `carrier()`: a 64-bit xorshift state that
advances on every protected call. Bit 0 of the carrier strictly alternates, and
the injected entry branch uses exactly that bit to choose between two
semantically identical instruction paths (the junk block is stack-neutral and
touches no local). Two calls with identical arguments therefore do not execute
the same guard path, so an execution trace recorded by a red team does not
describe the next call, and a patched branch that "always skips" is visible as a
hot-path change on the following invocation.

With `otp.native=true` (the default) and a native guard in the build,
`GuardCodeGenerator` also emits `umbra_native_otp` and registers it as
`nativeNext(J)J` on the injected OTP class from `JNI_OnLoad`, so the state
transition itself runs in the guard library and folds in the per-build secret.
The class name is encoded exactly like the guard class name, and the entry point
stays out of the magic-located function table (that table drives the prologue
hashes, so growing it would invalidate every existing guard). If the guard is
absent, cannot be loaded, or the OTP class is not resolvable at `JNI_OnLoad`
(encrypted payload), the advance stays on the Java path; the runtime retries the
binding a bounded number of times and then keeps the Java path for good.

The string-slot re-keying half of K-OTP (per-call re-encryption of the decrypted
constants) is still open (see `docs/ROADMAP-PORTS.md`). Thread safety: the
advance is a single synchronized block, so concurrent calls never receive the
same value.

### `renamer.*` — class and package names

| option | type | default | effect |
|---|---|---|---|
| `renamer.enabled` | bool | true | rename classes/methods/fields |
| `renamer.repackage` | bool | false (`maximum`, `aggressive`: true) | rewrite the package part of class names |
| `renamer.repackagePackage` | string | "" (`maximum`, `aggressive`: `*`) | `*` = one random package derived from the seed, so the archive shows no original package tree; a fixed name (`com/acme/x`) = put every renamed class there |
| `renamer.repackageKept` | glob list | "" | classes that keep their original package even when repackaging |
| `renamer.dictionary` | string | a-zA-Z | characters used for generated names |
| `renamer.minimumNameLength` | int | 1 | shortest generated name |

Repackaging is why `--preset maximum` output has no `com/yourcompany/...` tree: every renamed class
ends up in one short random package, while the generated runtime helpers use their own seed-derived
package (`runtime.package`). Zelix KlassMaster reaches the same goal by moving everything into the
default package; the difference is cosmetic, both remove the vendor package structure from the listing.
Classes frozen by keep rules, the loader manifest entry point and module descriptors are never moved.

Note: `--set renamer.*` (and the other typed sections, e.g.
`--set flowObfuscation.level=normal`) reaches these typed options during the CLI's configuration
assembly. Precedence is preset < `--set` < explicit switch, so `--no-flow`, `--no-rename`,
`--no-string`, `--no-integer`, `--no-shuffle`, `--no-junk`, `--no-watermark` and `--flatten` always
win over a `--set` of the same section. The translation is CLI-only: a typed key placed in a YAML
`options:` block stays inert, the YAML typed sections (`renamer:`, `flowObfuscation:`, ...) still
decide their own values, and a typed section without a matching `--set` key keeps the YAML/preset
value.

### `minecraft.*` — mod-container auto-adaptation

Detected when the input jar carries Fabric/Quilt (`fabric.mod.json`,
`quilt.mod.json`), Forge (`META-INF/mods.toml`, legacy `mcmod.info`, `@Mod`
annotations), NeoForge (`META-INF/neoforge.mods.toml`), mixin configurations,
access wideners/transformers or loader manifest attributes. Adaptation runs
before the pipeline; it adds keep rules, body-transform exemptions and
downgrades conflicting features. Defaults are safe for ordinary jars: without
metadata nothing changes. See [MINECRAFT.md](MINECRAFT.md) for the full policy
and verified loader matrix.

| key | type | default | meaning |
|---|---|---|---|
| `minecraft.enabled` | bool | true | auto-detect mod containers and adapt |
| `minecraft.forceVmp` | bool | false | keep virtualization enabled for mod jars (mixin/target classes stay exempt) |
| `minecraft.allowConflicts` | bool | false | do not downgrade conflicting features (class encryption/native/resources/...) |

Automatic downgrade when a container is detected: `classEncryption.enabled`,
`integrity.enabled`, `native.enabled`, reference obfuscation, resource path/content
rewriting, member trimming and (unless `minecraft.forceVmp`) virtualization are
turned off. Renaming, string/integer encryption, flow/exception/MBA obfuscation,
anti-LLM decoys and watermarks stay enabled for classes that are not Mixin
classes or Mixin targets.

### `nocturne.*` — original exclusive method-shadow engine

Nocturne is Umbra's own body-obfuscation design (polymorphic keyed-argument
method shadows). By default it is exclusive and switches the other method-body
rewrites off. With `nocturne.compatible=true` (or `nocturne.exclusive=false`)
it runs after the classic body passes and wraps their output instead; native
methods keep priority, and the remaining Java methods are shadowed. Name/data
layers remain available in both modes. See [NOCTURNE.md](NOCTURNE.md).

| key | type | default | meaning |
|---|---|---|---|
| `nocturne.enabled` | bool | false | turn on the Nocturne body engine |
| `nocturne.compatible` | bool | false | wrap classic body passes instead of disabling them (implies `nocturne.exclusive=false`) |
| `nocturne.exclusive` | bool | true | explicit exclusivity switch; set false for compatible mode |
| `nocturne.encoding` | enum | arx | `arx` (add-rotate-xor, per-method constants) or `xor` (legacy) |
| `nocturne.variants` | int 2..4 | 3 | number of semantically equivalent shadow variants per method |
| `nocturne.maxInstructions` | int | 4000 | per-method bytecode budget; larger methods stay unchanged |
| `nocturne.maxMethods` | int | 0 | per-class cap; 0 = unlimited |

### `decompilerNoise.*` — metadata hardening (mc-mixin)

| key | type | default | meaning |
|---|---|---|---|
| `decompilerNoise.enabled` | bool | true | add JVM-legal but analyser-hostile metadata |
| `decompilerNoise.level` | int 1..4 | 1 | 1 = safe attrs/debug-table noise, 2 = malformed signatures, 3 = large junk attributes, 4 = level 3 + EnclosingMethod/SourceDebugExtension/MethodParameters/line-table traps (large output growth; opt-in) |

Level 1 keeps the JVM and common reflection working; level 2/3/4 can break tools
that parse generic signatures or debug tables and are opt-in. Level 4 grows the
demo artifact from ~33 KB to ~1.4 MB, so it is not enabled by any preset.

### `typeConfusion.*` — static call ABI carriers (protection)

| key | type | default | meaning |
|---|---|---|---|
| `typeConfusion.enabled` | bool | false | route selected static/private call ABI through `Object[]` carriers |
| `typeConfusion.level` | int 1..2 | 1 | 1 = call ABI trampolines; 2 = also private static field `Object` carriers (more invasive, opt-in) |
| `typeConfusion.maxPerMethod` | int | 64 | rewrite budget per method |
| `typeConfusion.methods` | glob list | `**` | target selector (`Class#method` or class; Ant globs, `**` crosses packages) |

### `reflectionGate.*` — runtime reflection seal (protection, opt-in)

| key | type | default | meaning |
|---|---|---|---|
| `reflectionGate.enabled` | bool | false | seal protected classes against reflective member lookup at runtime |
| `reflectionGate.action` | enum | deny | `deny` throws, `mask` returns empty/neutral results |
| `reflectionGate.sealed` | glob list | `**` | classes to seal |
| `reflectionGate.allow` | glob list | "" | reflection call sites that must keep working (dotted class names) |
| `reflectionGate.maxPerMethod` | int | 64 | rewrite budget per method |

The gate is off by default because it intentionally changes reflection
semantics; same-class self-reflection and allow-listed sites keep working.

### `classEncryption.resources` — resource encryption (crypto)

| key | type | default | meaning |
|---|---|---|---|
| `classEncryption.resources` | bool | true | encrypt non-class archive entries and serve them through the loader |
| `classEncryption.resourceIntegrity` | bool | true | include resource digests in the sealed index / integrity checks |
| `classEncryption.minResourceSize` | int | 0 | resources smaller than this stay readable (metadata compatibility) |
| `classEncryption.manifestMinimal` | bool | true | strip nonessential manifest attributes (Main-Class stays readable) |
| `classEncryption.constantPool` | bool | true | store every encrypted class with its `CONSTANT_Utf8` payloads XOR-encrypted and patch them in memory only on the define path, so a payload recovered from the loader is not decompilable (`javap` and CFR both fail). Lengths and constant-pool indexes are unchanged, so `StackMapTable` and every other attribute stay valid. Requires `classEncryption.enabled=true` (there is no patch point without the custom loader) |

### `antiLlm.*` — decoy and forwarding walls (protection)

| key | type | default | meaning |
|---|---|---|---|
| `antiLlm.enabled` | bool | preset | add semantic decoys, guarded call sites and forwarding walls |
| `antiLlm.decoyMethodsPerClass` | int | 2 (3 for `maximum`) | decoy methods added per class |
| `antiLlm.decoyCallSitesPerClass` | int | 2 | methods that receive a guarded decoy call |
| `antiLlm.wrapperLayers` | int 0..4 | 1 (2 for `maximum`) | forwarding layers in front of a moved method body |
| `antiLlm.maxWrappedMethodsPerClass` | int | 12 | cap on wrapped methods per class |
| `antiLlm.shieldVirtualization` | bool | true | emit a decoy shield around the VM entry |

Generated members are named through the same generator and dictionary as the
renamer, so a decoy cannot be told apart from a renamed program member (no fixed
prefixes, no semantic identifiers). Decoy bodies use one of four shapes
(`int`, `long`, `boolean` and `String` results) and reuse a string constant that
already exists in the same class instead of shipping a decoy vocabulary. Each
decoy is referenced from the class's static initializer behind a predicate whose
seed comes from `System.nanoTime()`, so a static analyser cannot fold the branch
away; the decoy chain also references the next decoy. The pass runs after
renaming and before string encryption and virtualization.

### `vm2.indy` / `vm2.constructors` — virtualization coverage (vm)

| key | type | default | meaning |
|---|---|---|---|
| `vm2.indy` | bool | true | generate indy bridges so methods with lambdas/string concat can be virtualized |
| `vm2.constructors` | bool | false | extract constructor bodies after `super()` into virtualizable helpers |
| `vm2.holders` | int 1..8 | 2 | payload holder classes per virtualized method; 0 = default |

### `antiDebug.nativeGuard` / `antiDebug.frida` — native guard (native)

| key | type | default | meaning |
|---|---|---|---|
| `antiDebug.nativeGuard` | bool | true | build/load the native anti-tamper guard when anti-debug is requested |
| `antiDebug.frida` | bool | true | enable Frida/instrumentation markers (modules, pipes, thread names, env) |
| `antiDebug.nativeHash` | bool | true | hash the guard's code section at load and on checks |
| `antiDebug.watchdogMs` | int | 4000 | periodic re-check interval (shared by the native guard and the Java runtime guard; randomized jitter is applied) |
| `antiDebug.action` | enum | throw | `throw`, `exit`, `corrupt`, `log` on detection |

### `layout.*` — archive layout compatibility (compat)

Umbra 3.0 detects how the input was packaged and preserves the container
layout instead of assuming a flat classpath.

| key | type | default | meaning |
|---|---|---|---|
| `layout.enabled` | bool | true | detect and preserve non-flat layouts; `false` restores the 2.0 flat-only behaviour |
| `layout.springBoot` | bool | true | transform classes under `BOOT-INF/classes/` in place; keep `BOOT-INF/lib/` byte-identical |
| `layout.war` | bool | true | transform classes under `WEB-INF/classes/` in place; keep `WEB-INF/lib/` and static resources intact |
| `layout.multiRelease` | enum | preserve | `preserve` keeps `META-INF/versions/N/` and the `Multi-Release` manifest attribute; `flatten` emits a plain JAR (2.0 behaviour) |
| `runtime.package` | string | auto | package of the generated runtime helpers (VM interpreter, payload holders, guards, loaders). `auto` derives a short package from the seed, so the artifact carries no vendor name and the fingerprint changes per build. `invokedynamic` still has to name the host class, so the name cannot be hidden, only made unattributable. Example: `--set runtime.package=com/acme/internal` |
| `layout.moduleInfo` | enum | auto | `auto` remaps `module-info` exports/opens/uses/provides through the mapping; `keep` leaves the descriptor untouched; `drop` removes it with a warning |

Layout statistics: `layout.kind` (text: `flat`, `spring-boot`, `war`,
`multi-release`), `layout.springBoot.classes`, `layout.war.classes`,
`layout.multiRelease.classes`, `layout.multiRelease.mode`,
`layout.moduleInfo` (+ text `layout.moduleInfo.action`), `layout.services`,
`layout.manifest.rewritten`, `layout.duplicates`, `layout.preserved.entries`,
`layout.classPrefix`.

Entry-point protection launchers (class encryption, the startup anti-debug
guard, the integrity launcher and the auth gate) are root-JAR constructs. A
nested loader would bypass them, so on non-flat layouts they are skipped with a
warning and a `layout.guard.skipped` statistic instead of silently producing a
broken archive; use a flat JAR if you need those layers.

## CLI compatibility tools

```bat
:: read-only inspection before protecting (no output written)
java -jar umbra.jar -i app.jar --inspect
java -jar umbra.jar -i app.jar --inspect-json inspection.json

:: protect and write a machine-readable layout + statistics report
java -jar umbra.jar -i app.jar -o app-prot.jar --preset balanced ^
  --compat-report compat.json
```

`--inspect` reports the detected layout, transformable/versioned class counts,
class-file versions, entry points (`Main-Class`, `Start-Class`, agent
attributes), framework hints (Spring/Spring Boot, Kotlin, Scala, Groovy,
Micronaut, Quarkus, OSGi, JPMS, java agents), service descriptors, signature
files, duplicate entries and layout-specific warnings. It exits `0` for a
readable archive and `1` for configuration errors; it never transforms or
writes class bytes.

`--compat-report` runs after a normal (or `--dry-run`) protection run and
writes JSON with the inspection facts, per-pass timings, the full statistics map
and warnings — suitable for CI artifacts and audit trails.

### Other existing keys

The typed sections are documented in `umbra.example.yml`:
`renamer.*`, `stringEncryption.*`, `integerEncryption.*`, `flowObfuscation.*`,
`debugInfo.*`, `memberShuffle.*`, `invokeWrapper.*`, `watermark.*`,
`mapping.*`, `report.*`, `junkMembers.*`, `reflection.*`, `trim.*`,
`parameterObfuscation.*`, `methodVirtualization.*`, `antiLlm.*`,
`resources.*`, `referenceObfuscation.*`, `exceptionObfuscation.*`,
`incremental.*`, `protection.antiDebug`.

## Ownership

New keys are owned by the pass that reads them. Add the key here when you
implement it (row in the matching table) and make sure `--set`/YAML/GUI all work
through the option map without further changes.

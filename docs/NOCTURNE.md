# Nocturne — Polymorphic Keyed-Argument Method Shadows

Nocturne is Umbra's own method-body obfuscation engine. It has two modes:

* **Exclusive (default, `nocturne.compatible=false`).** Enabling
  `nocturne.enabled=true` switches off the other body rewrites (flow,
  control-flow flattening, exception obfuscation, MBA, classic/VM2
  virtualization, native conversion, reference hiding, anti-LLM wrappers,
  parameter and junk-member mutation). Data/name layers (rename, string and
  integer encryption, metadata cleanup, watermark, integrity, class encryption)
  remain available. This mode is reported at startup:
  ```
  nocturne: exclusive mode - flow/flattening/exception/MBA/VM/native/
  reference-hiding/anti-LLM/parameter/junk passes disabled
  ```
* **Compatible (`nocturne.compatible=true`, or `nocturne.exclusive=false`).**
  Nocturne runs after the classic Java body passes and after native conversion,
  then shadows every remaining eligible Java method. The result is a genuine
  stack: flow/flattening/MBA/VM/exception/reference/anti-LLM transformations
  are inside the bodies that Nocturne wraps, while native methods keep priority
  (Nocturne only shadows methods that still have a Java body). Data/name and
  archive layers stay available in both modes.

Compatible mode is opt-in so the default output shape stays the isolated
Nocturne engine. Combined runs are heavier and may exceed decompiler limits
faster, but they are verifier-safe and deterministic.

## Algorithm

For every eligible method `M` (concrete body, not `<init>`/`<clinit>`, not
`synchronized`, not kept, not frozen/generated/body-skipped, no jsr/ret, body
within `nocturne.maxInstructions`):

1. **Shadow clones.** Create `N` (`nocturne.variants`, 2..4, default 3) private
   synthetic methods `M$<hex>`. Their descriptor is `M`'s descriptor with a
   trailing `J key`: `(IJ)V` becomes `(IJJ)V`. Each clone contains a deep copy
   of `M`'s body (fresh `LabelNode`s, copied exception table) whose free local
   slots are shifted by a random 2..3 slot delta, preceded by a **decode
   prefix** that restores the original `int`/`long` arguments.
2. **ARX argument transcoding (default).** A single `arg ^ key` is trivially
   invertible, so the call boundary uses a two-round Add-Rotate-Xor permutation
   whose constants are derived from the per-invocation key and a per-method
   build salt:
   ```
   // encode (int)
   x += (int)key;  x ^= (int)(key >>> 32);
   x = Integer.rotateLeft(x, rot1);
   x += c1;        x ^= (int)(key >>> 17);
   x = Integer.rotateLeft(x, rot2);
   // decode = exact reverse (rotateRight, subtract, xor in reverse order)
   ```
   `long` arguments use the same construction with `Long.rotateLeft/Right` and
   a 64-bit method constant. `rot1`, `rot2`, `c1`, `longC1` are derived from the
   build seed + method salt, so no two methods share a transform; the runtime
   key changes every invocation. `nocturne.encoding=xor` keeps the old scheme
   only for compatibility/measurement.
3. **Keyed dispatcher.** `M`'s body is replaced by:
   ```
   long key = ThreadLocalRandom.current().nextLong() ^ classSecret;
   switch ((int)(key ^ salt) & 0x7FFFFFFF % N) {     // tableswitch 0..N-1
     case i: return M$i(this, encode(arg1, key), encode(arg2, key), ..., key);
     default: throw new IllegalStateException();
   }
   ```
   `classSecret` is derived deterministically from the build seed and the class
   name; `salt` is a per-method seed-derived constant. Every call site therefore
   crosses a keyed, method-specific transform boundary and executes one of `N`
   equivalent bodies; the original body is no longer reachable from the caller
   without going through the dispatcher.

Only `int`-category parameters (`boolean/byte/char/short/int`) and `long`
parameters are encoded. `float`/`double`/reference/array arguments are passed
through unchanged, which keeps every descriptor verifier-safe. Return
types are handled generically (`RETURN/IRETURN/LRETURN/FRETURN/DRETURN/ARETURN`).

The JVM recomputes stack map frames; Nocturne never hand-writes them.

## Verification and rollback

Nocturne injects new methods and replaces whole bodies, so a single bad
dispatch/shadow pair could emit an unverifiable class. Each class is transformed
transactionally:

1. all transformations are built against deep copies while the original method
   nodes are kept untouched;
2. the class is temporarily assembled with the new methods and serialized with
   `COMPUTE_FRAMES` using the program's own `Hierarchy`;
3. `CheckClassAdapter` type-checks the result with a class loader backed by the
   current `ClassPool`;
4. only a successful class is committed; otherwise every method of the class is
   restored and the class is counted as a skip.

This is the same "transform on a copy, verify, commit or roll back" discipline
used by the flow passes; a Nocturne bug can reduce coverage but cannot break
`java -jar` / `--verify`.

## Behaviour preserved

- static/instance dispatch, virtual overrides and recursion (recursive calls go
  through the dispatcher);
- `void`/primitive/reference/array returns and parameters, long/double slot
  widths;
- try/catch/finally inside the body (exception table is copied per shadow; the
  dispatcher itself has no handlers and does not catch/clobber exceptions);
- thrown exception type, instance and message;
- method annotations, parameter annotations, `throws`, `strictfp` flag;
- constructors and class initialisers are untouched;
- `@Keep`, keep rules, body-skip (Minecraft Mixin) classes, frozen and generated
  classes are skipped.

## Determinism

All build-time choices (class secret, per-method salt, shadow names, local-slot
deltas, variant selection constants) come from `ctx.random()` seeded by
`config.seed()`. The only runtime randomness is the emitted
`ThreadLocalRandom.current().nextLong()`; it does not affect class bytes. Two
runs with the same seed and `--fixed-time` produce byte-identical class entries
(this is asserted by `NocturneTest`).

## Options

| key | type | default | meaning |
|---|---|---|---|
| `nocturne.enabled` | bool | false | enable Nocturne |
| `nocturne.compatible` | bool | false | run after classic body/native passes instead of disabling them |
| `nocturne.exclusive` | bool | true | explicit exclusivity switch; false implies compatible mode |
| `nocturne.encoding` | enum | arx | `arx` (default, two-round add-rotate-xor) or `xor` (legacy) |
| `nocturne.variants` | int 2..4 | 3 | number of shadow clones per method |
| `nocturne.maxInstructions` | int | 4000 | per-method body budget; larger bodies are skipped |
| `nocturne.maxMethods` | int | 0 | per-class transformed-method cap; 0 = unlimited |

Stats reported by the pass: `nocturne.methods` (dispatchers), `nocturne.variants`
(shadow methods), `nocturne.instructions` (instructions in generated shadows +
dispatchers), `nocturne.skipped`, `nocturne.classes`.

## Measured on `demo/demo.jar` (JDK 8, seed 777)

```
nocturne: shadowed 69 methods with 207 keyed variants (19,806 instructions)
          across 21 classes; 3 skipped
Verification: OK     (java -jar demo output prints OK, ~1.1 s end-to-end)
```

The instruction count grew versus the legacy XOR mode (15,684) because each
int/long argument now carries the two-round ARX encode/decode prologue; the
built jar remains fully deterministic for a given seed.

Skips were: one `synchronized` method, one `@Keep`/keep-rule method, and the
`main` entry point (UMBRA's default keep rule). No class needed a verifier
rollback on the demo.

## Performance

- Build time: ~160 ms for the 69-method demo (plus ~0.4 s of the remaining
  pipeline). Verification adds one `COMPUTE_FRAMES` + type-check serialization
  per transformed class.
- Output size: the demo grows by 69 dispatchers + 207 shadows (~15.7k
  instructions). Each method body is present `N` times by design; the
  `nocturne.maxInstructions`/`nocturne.maxMethods` caps bound the blow-up.
- Runtime: one `ThreadLocalRandom.current().nextLong()` + one tableswitch +
  encoded argument push/pop + one `invokespecial/invokestatic` per call. Int and
  long arithmetic in the body is unchanged on the shadow side. This is a
  constant-factor slowdown, not a JIT-hostile transform; hot loops remain JIT
  compilable because each shadow is a normal method.

## Threat model and limitations

Raises cost for:

- static call-graph/body analysis: every method body is duplicated and the real
  body is only reachable through a keyed dispatcher; cross-references to `M` no
  longer land in the body;
- decompiler "follow the real method" intuition: all `N` variants are
  semantically equivalent, so picking one is not enough to bypass behaviour;
- simple pattern patchers: changing one shadow or the dispatcher breaks that
  call site without being obvious from the method listing.

**Not** claimed:

- it is not encryption: a determined analyst can read all `N` bodies; the key
  affects argument passing, not code storage;
- it does not defeat a Java agent/JVMTI that dumps classes or instruments
  `ThreadLocalRandom`/`invokespecial` (see Umbra's anti-debug/native-guard
  layers for that);
- runtime stack traces and `Thread.getStackTrace()`/`StackWalker` show the
  synthetic `M$xxxx` frames instead of `M`; exception messages/types are
  preserved but frame names differ;
- reflection that enumerates `getDeclaredMethods()` sees the extra private
  synthetic shadow methods (the original method with its original descriptor is
  kept, so reflection lookups by name/descriptor keep working);
- methods with `synchronized`, `jsr/ret`, constructors, initialisers,
  kept/frozen/body-skipped classes are skipped; the per-class verifier rollback
  can skip a whole class if any injected method fails ASM's type checker;
- a debug/analysis build with `umbra.nocturne.stack`/`umbra.nocturne.dump`
  prints verifier diagnostics (no effect on normal runs).

## Tests

`src/test/java/io/umbra/tests/NocturneTest.java` (plain `main *Test`, 101
checks): synthetic Java 8 class with int/long/String/int[]/float/double
parameters, static/instance/void/returning methods, loop/switch/recursion,
exceptions, try/catch and field writes; ASM `CheckClassAdapter` + real JVM
verification; behaviour compared with Java reference implementations; variant
counts 2/3/4; skip/limit/`@Keep`/`synchronized`/body-skip/frozen cases; byte
determinism for the same seed; and an end-to-end CLI run on `demo/demo.jar`
(`--set nocturne.enabled=true --verify`) that asserts the exclusive-mode log, the
absence of the other body-pass log lines, `OK` output, presence of keyed shadow
methods in the archive, and byte-identical class entries across two seeded runs.

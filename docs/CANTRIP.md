# Cantrip

Cantrip is an optional **second protection layer for VM2 payloads**. It does not
change which methods are virtualized; it changes how the VM2 payload classes are
reconstructed when they are first used.

## Design

1. VM2 (`method-virtualization` pass, `vm2.enabled=true`) translates eligible
   methods into its instruction stream and encrypts the payload with a
   per-program ChaCha20 key. The encrypted values are split across synthetic
   holder classes.
2. With Cantrip enabled, each payload chunk is emitted as a **Cantrip dialect
   program** instead of a plain decode loop:
   - classic commands `> < + - . [ ]` are supported by the interpreter;
   - the dialect command `~<int>;` assigns a signed integer to the current cell;
   - the generated program is `~value;.` per payload value.
3. The holder's `<clinit>` calls the injected interpreter
   `UmbraCantrip.run(String[])`; the interpreter produces the `int[]` that VM2
   then decrypts/executes normally. The class file contains no plain array
   initializer for the payload values.

So the layers are: **VM2 opcode VM + ChaCha20 payload encryption** (inner), then
**Cantrip dialect reconstruction** (outer). The Cantrip program only contains the
already-encrypted VM2 values.

## Options

```bat
--virtualize ^
--set vm2.enabled=true ^
--set cantrip.enabled=true ^
--set cantrip.level=1
```

| key | default | meaning |
|---|---|---|
| `cantrip.enabled` | false | enable the second layer |
| `cantrip.level` | 1 | 1 = payload chunks; 2 = payload chunks + VM2 map/meta holder |

Requires `methodVirtualization.enabled=true` and `vm2.enabled=true`; otherwise
the pass logs a warning and leaves the output unchanged.

## Evidence (demo, seed 911)

```
method-virtualization[vm2]: virtualized 52 methods (2499 instructions, ...)
cantrip: 9420 values reconstructed from 164 chunks by 156 Cantrip dialect programs
Verification: OK
java -jar output.jar -> OK
```

The output is deliberately larger: each payload int becomes a short dialect
token (`~N;.`) plus a holder class; `--verify` still passes and the protected
program runs on JDK 8/21/26.

## Interaction with other techniques

- **Nocturne compatible mode**: VM2 + Cantrip run before Nocturne; Nocturne then
  wraps the remaining Java methods. Both layers coexist.
- **Native code**: native conversion does not translate Umbra-generated holder
  classes; the Cantrip holders stay Java and continue to feed VM2.
- **String/resource/class encryption**: Cantrip holders are generated classes, so
  string encryption leaves their program chunks as-is; the chunks already
  contain ChaCha20 ciphertext, and class/resource encryption still covers the
  archive.
- **Minecraft / Mixin**: mixin and target bodies are exempt from virtualization
  by the Minecraft adaptation, so Cantrip does not touch them.

## Limitations

- Cantrip is a second layer, not a full Java-to-bytecode compiler: it encodes VM2
  payload ciphertext in a Cantrip dialect, it does not replace VM2 semantics.
- Program size grows roughly 3-8x over the VM2 payload; level 2 adds the map
  holder as well.
- The interpreter is an injected JDK-only class; it is not native code and is
  therefore still visible to a determined runtime dumper (as with all JVM-level
  protection). It raises static/decompiler cost, not absolute runtime security.
- `cantrip.enabled` without `vm2.enabled` is rejected with a warning.

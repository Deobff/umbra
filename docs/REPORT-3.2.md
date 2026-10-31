# Umbra 3.2.0 閳?security-hardening + GUI release report

Status: released. Artifacts: `dist/umbra.jar` (1,428,967 B, sha256
`0c070b3398f7fbbfa607213f994ea7d8a4076dbe971af251e486f0accd3bfccd`) and
`dist/umbra-3.2.0.zip` (1,542,800 B, sha256
`1c9a891083f311eee7e81b0bccc9d72a5cf768b3884e4b685a76071b7ec70549`). Every number
comes from a command run on this tree; evidence paths are listed. Items not
implemented are stated explicitly.

## 1. Scope

3.2 responds to an independent static/dynamic analysis of a 3.1 encrypted-archive
sample (`E:\teeess\report-umbra-demo-obf.md`) and its optimization list
(`E:\teeess\Umbra濞ｉ攱绌崳銊ょ喘閸栨牕缂撶拋?txt`). The compatibility model, CLI and Java 8 /
ASM-only build are unchanged. Encrypted archives use a new **index v3** format;
old v2 archives must be rebuilt. The desktop GUI gains per-mode detailed option
sheets.

## 2. Security fixes

### 2.1 Key lifecycle (P0-1)

* Per-build random 32-byte `siteSeed` (SecureRandom, not the obfuscator seed) is
  injected via `@@SEED@@`; the archive master key is
  `HMAC-SHA256(siteSeed, "umbra.master.v3" || zipComment || LE32(entryCount))`.
  The post-processor writes a random 16-byte base64 ZIP comment; the loader
  rebuilds the master from `JarFile.getComment()` + entry count.
* Per-entry key: `HMAC(master, "c:"+name || nonce)` (resources `"r:"`). The nonce
  is no longer keystream-only, so a class key is not stable across builds.
* The old four base64 key parts + salt are gone from the plaintext loader.
* `classEncryption.masterBinding`: `sample` default, `seed` diagnostic fallback.

### 2.2 Offline-verification defeat (P0-2)

Class, resource and loader digests are now HMAC-keyed:
`HMAC(master,"d:c:"+name||plaintext)`, `"d:r:"`, `"d:loader"`. A dumped payload
cannot be checked against the index without the master key. Expected digests and
the loader digest are wiped after constant-time comparison.

### 2.3 Integrity (P1-6)

* Encrypted archives clamp integrity level to >= 2 (per-class/resource keyed
  digest on every decrypt/define); `classEncryption.integrity=false` is the
  explicit opt-out.
* The payload watchdog starts at level >= 2, verifies a randomized ~1/20 of
  classes/resources per tick (`classEncryption.watchdogMs`, default 4000) and
  does a full pass every 20th tick at level 3.
* A heartbeat refreshed by the watchdog is checked on each decrypt/define; a
  suspended watchdog fails closed.

### 2.4 Information leakage (P1-4)

* Loader/guard failures are silent: `SecurityException` with empty stack and no
  message; no full stack trace, no fixed `[umbra-guard]` prefix. A random
  `@@LOGTOKEN@@` is used only for `action=log` and `-Dumbra.debug=true`.
* All injected runtime templates have `SourceFile`, SourceDebugExtension,
  LineNumberTable and LocalVariableTable stripped; `javap` on the plaintext
  loader/crypto/connection/handler shows no `Umbra*.java` names or line numbers.

### 2.5 Build/format correctness (P2)

* Build-time assertions: no `@@` in plaintext entries/names; index payload and
  plaintext-class names cross-checked against ZIP; exact plaintext-class set;
  module-info indexed only when present; entry-count matches the master binding;
  ZIP comment consistency.
* Bounded `readString`/counts/entry sizes (1 MiB / remaining bytes), 44-byte
  sealed minimum, payload algorithm whitelist {ChaCha20, AES-256-CTR}, dead
  ALG_XOR branch removed for archive payloads.

### 2.6 Additional guard signals (P2-6)

`-XX:+HeapDumpOnOutOfMemoryError`, `+HeapDumpBeforeFullGC` and
`jdk.attach.allowAttachSelf=true` are detected (each probe individually
try/caught; clean JDK matrix remains zero-false-positive). SIGQUIT handler
inspection and live HotSpotDiagnosticMXBean heap-dump invocation are documented
as not observable from pure Java (native/JVMTI gap).

### 2.7 String hardening (P2-5)

* Per-class deterministic random site ids (no sequential 176/177 pattern);
  same seed bytes identical, different seed differs.
* Payload v3 with a per-artifact/class salt (`string.siteSalt`); domains bumped
  to `io.umbra.string.v3.*`.
* Plaintext string cache **off by default** (`string.cache`), opt-in only;
  decryptor allocates no map unless the flag is set.
* Verified wipe/hide-trace flags; randomized per-site engine choice for
  `string.engine=auto`; unknown engines warn and fall back to the whitelist.

### 2.8 Native guard (P1-5)

* Extraction now uses a random 16-char directory + random 16-char file under
  `java.io.tmpdir` with a neutral marker file; no fixed `umbra-guard-*` name.
* Post-load wipe: POSIX unlink; on Windows the mapped image is locked, so the
  marked directory is removed by the next run (documented residual).
* JNI methods registered via `RegisterNatives`; only `JNI_OnLoad` and the tick
  export remain; COFF symbols stripped; guard 122,446 閳?**24,064 bytes**;
  plaintext `umbra` hits 27 閳?1 (the tick export required by the native-code
  pass).
* `native.timestamp=true` writes a normal PE timestamp (default reproducible 0);
  section names normal; strict PE hygiene assertions.

## 3. GUI

`Mode options閳ヮ泦 in the Preset group opens a 900鑴?00 sheet with 12 groups /
111 controls: Names, Strings, Integers & MBA, Flow, Exceptions, Virtualization,
Native, Archive & class encryption, Anti-debug, Type confusion & anti-analysis,
Compatibility, Output. Selecting Light/Balanced/Aggressive/Maximum/Nocturne
fills CLI-equivalent defaults; edits switch to Custom; Reset restores; the
left-column switches sync both ways; YAML save/load round-trips every key.

## 4. Verification

### 4.1 Full self-test gate

`build.cmd -Task test` on the release tree: **24 suites / 264,509 checks, exit 0**
(AuditTest 128, CantripTest 9, CompatTest 215, CoreTest 133, CryptoTest 150,
DecompilerNoiseTest 114, DynamicGuardTest 238, FlowTest 260,324, GuiConfigTest
80, GuiSelfTest 1,323, GuiLayoutTest 13, MinecraftAdapterTest 170,
MixinAnalyzerTest 147, MultiReleaseTest 37, NativeDynamicTest 116,
NativeGuardTest 90, NativeTest 105, NocturneCompatibleTest 14, NocturneTest 101,
ProtectionV2Test 144, SecurityHardeningTest 126, StringHardeningTest 62,
Vm3Test 125, VmTest 545). Evidence: `build-qa/release32b-test.log`.

### 4.2 Security checks (manual, release tree)

| Check | Result |
|---|---|
| v3 build (maximum): `--verify` + child run | exit 0, `OK`; node stats `level=2 v=3`, masterBinding=sample, 2543 entries |
| Two builds, same input/seed | different ZIP comments, different file hashes; both run `OK` |
| ZIP comment tamper | exit 1, **zero bytes** of output (silent refusal) |
| `-agentlib:jdwp` startup | exit 1, only the JVM transport line, no stack/prefix |
| `-XX:+HeapDumpOnOutOfMemoryError` | exit 1, zero bytes of output |
| Plaintext runtime classes | 4 classes; no `Compiled from`, `SourceFile`, LineNumberTable, `Umbra*.java`, old key constants |
| `@@` scan of classes/manifest | 0 hits |
| Class-encryption integrity | level 2, sampled watchdog started |
| Tampered class payload (SecurityHardeningTest) | rejected silently |
| Clean JDK 8/21/26 launches | exit 0, no guard output |
| GUI mode sheet | 900鑴?00 screenshots, 111 controls, mode defaults unit-checked |

### 4.3 Known residual limitations

* v3 archives only; rebuild v2-protected archives. ZIP comment/entry-count
  binding intentionally breaks repackaging that rewrites the comment or adds/
  removes entries (build assertions catch tool bugs).
* Windows mapped-DLL cleanup: current run leaves its random marked directory;
  next run removes it by marker+age. `MoveFileEx`/in-memory mapping not used.
* Native guard still exports `umbra_guard_tick` and sets `umbra.guard.path`
  because the unrelated native-code pass resolves them by name.
* Java-only heap-dump observation (SIGQUIT handler, live MXBean invocation) is
  not observable; native/JVMTI coverage is the remaining gap. P0-3
  (native fingerprint in the master/class KDF) is deferred and documented, not
  faked.
* Level-2 sampled watchdog detects tampering of unused payloads within 閳?0
  ticks (~80 s at 4 s); used payloads and level-3 full passes detect
  immediately.
* Plaintext interned `String`s can still be seen in a heap dump (JVM behavior);
  decryption temporaries are wiped and the plaintext cache is off by default.

## 5. Reproduction

```bat
build.cmd -Task test
java -jar dist\umbra.jar -i app.jar -o app-obf.jar --preset maximum --verify
java -jar app-obf.jar
java -jar dist\umbra.jar --gui --screenshot shot.png
java -jar dist\umbra.jar --gui --options-screenshot options.png
```

# Umbra 3.2.2 — release notes

K-OTP one-time program state, per-call string re-keying, a sealed second VM
dialect, method-level block scheduling, a hardened native guard, the `--set` fix
for the typed configuration sections, and a redesigned console UI.

* **Per-call string re-keying (`string.otpEngines`; on for `balanced`, `maximum`
  and `aggressive`)**: selected string sites store two ciphertexts under two
  different engines and the injected one-time state picks one per call
  (`carrier()`'s low bit strictly alternates), so consecutive calls at the same
  site take different decryption paths and one captured decryption does not
  describe the next. Indy sites, XOR sites, literals under 8 characters and sites
  above `string.otpMaxSites` stay single-engine. `demo` at `balanced`: 138 dual
  sites, +0.85 % artifact size.
* **Sealed second VM dialect (`cantrip.seal`, default on)**: the Cantrip program
  that reconstructs VM2 payload integers is now substituted through a per-build
  128-entry opcode table and ChaCha20-encrypted before being stored, so the
  artifact carries opaque base64 blobs instead of `~value;.` programs; the
  interpreter only exposes decode-and-run. Measured on `demo`: all 102 holders of
  a `light` build call `runSealed`, and the `balanced` build still runs (also with
  `-Xverify:all`).
* **Native shell (P1-5 subset)**: sensitive imports are resolved at runtime by
  FNV-hashed name lookup through `LoadLibraryA`/`GetProcAddress`, and every guard
  detection literal is sealed and decoded on first use. Measured: import table
  57 → 54 entries, export table still only `JNI_OnLoad` + `umbra_guard_tick`, and
  the plaintext markers (`frida`, `gum-`, `jdwp`, `NtQuery*`, …) are gone from
  `strings` and `.rdata`. Function-level virtualization is explicitly out of
  scope.
* **Native memory protection (P1-6)**: code-section CRC re-read plus page
  protection rotation on a guard-owned page, both reported through the existing
  `umbra_notify` mask. The rotation measures the steady-state protection at
  startup instead of assuming `PAGE_READWRITE` (the loader maps image data pages
  `PAGE_WRITECOPY`, which caused a false positive on every clean JVM) and repairs
  the page on a hit. `antiDebug.execWhitelist` keeps `execMemoryScan` from killing
  AWT/Swing apps at level 3.
* **One-time program state (`otp.enabled`; on for `balanced`, `maximum` and
  `aggressive`)**: `FlowObfuscationPass` injects a randomized `UmbraOtp` runtime
  class and takes the method-entry carrier from `carrier()` instead of a fresh
  `nanoTime` sample. The state advances on every protected call and bit 0
  strictly alternates, so the entry branch selects a different (semantically
  identical) instruction path on the next call: an execution recorded by a red
  team no longer describes the following one. The advance is a single
  synchronized block (concurrent calls never repeat a value) and the state can
  never fall into the xorshift zero fixed point.
* **Native one-time state (`otp.native`, default on)**: the generated guard also
  binds `nativeNext(J)J` to the injected OTP class from `JNI_OnLoad`, so the
  state transition runs in the guard library and folds in the per-build secret.
  The class name is encoded like the guard class name and the entry point stays
  out of the magic-located function table (that table drives the prologue
  hashes). Without a loadable guard the advance stays on the Java path.
* **Method-level block scheduling (`flow.reorder`; on for `balanced`, `maximum`
  and `aggressive`)**: independent basic blocks are lifted out of the method body
  and appended in shuffled order, every fall-through edge is repaired with an
  explicit `GOTO`, and the old position keeps a `GOTO` to the new location. Only
  blocks with an empty entry stack, outside every exception range/boundary and
  free of monitor instructions are moved, and every result goes through the
  method verification gate. Measured on `demo`: CFR fully structures 42 % of the
  guarded classes at `balanced` (58 % without the pass) and 8 % at `maximum`.
* **Console UI rewritten**: the JavaFX front end is no longer a single 31 KB
  `FxGui` with a stylesheet on top; it is six small units — `FxGui` (lifecycle +
  headless self-tests), `ConsoleModel` (state and the one command line that both
  the preview and the spawned process use), `ConsoleShell` (header pill, rail,
  segmented views, targets band, action bar), `OptionsView` (one card per
  configuration group), `Motion` and `Tokens`. The layout no longer uses a
  `TabPane`: a custom segmented control swaps three views inside one stack, the
  targets band sits above the action bar, and the header carries a status pill
  with a signal dot. Palette: graphite ramp adapted from the vfx dark theme
  (canvas `#171b1e`, panel `#1b2024`, raised `#24292e`, accent `#4d6ebe`).
  Motion keeps the strict frequency gate: press feedback 110/140 ms, view swap
  160 ms, option rows 180 ms with a 30 ms stagger, window entrance 220 ms, all on
  `SPLINE(0.23, 1, 0.32, 1)` and limited to opacity/transform;
  `-Dumbra.fx.reduceMotion=true` zeroes every duration while keeping the final
  state. `-Dumbra.fx.selfcheck=1` asserts the shell structure headlessly, and
  `-Dumbra.fx.shot` waits for a settled frame before capturing.
* **Closer to the vfx look**: the window is now self-drawn
  (`StageStyle.UNDECORATED`) with a 46 px title bar that carries the brand, the
  status pill and three window buttons whose hover colours follow vfx's semantic
  mapping (close red, maximize green, minimize amber); dragging moves the window,
  double-click maximizes, and thin strips on the right/bottom/corner resize it.
  Buttons use a `FusionButton` skin: the resting state is a flat raised rectangle
  with a hairline border, and on hover the **border** fades into the accent colour
  over 150 ms instead of the whole button changing colour.
* **The package now ships the new console.** The JavaFX front end lives in its own
  `umbra-gui-fx.jar` (it needs JavaFX, which the build JDK does not ship), and
  `build.ps1` copies it into `dist\` on both `dist` and `package` runs together
  with the launchers. `Umbra.cmd` now prefers the JavaFX console and only falls
  back to the console embedded in `umbra.jar` when no JavaFX-capable JDK 8 is
  installed; `umbra-fx.cmd` resolves the GUI jar from `dist\` or `gui-fx\`.
  `UMBRA_LAUNCH_DRYRUN=1` prints the resolved command instead of launching, which
  is how the packaged layout is verified.
* **Fixed: hidden and misleading option controls.** The engine publishes two
  control models (specs and switches, 12 groups each, only four titles shared), and
  the tree was built from one of them, so 19 switches in Data, Control flow,
  Archive, Anti-analysis and Verification were unreachable from the UI. The tree is
  now the union of both, groups whose switches are all owned by a spec are omitted
  instead of opening an empty card, UI-only specs (`verify`/`seed`/`mapping`) are
  no longer rendered as dead switches, enum values outside the declared list are
  appended instead of rendering a blank box, integer values are clamped with an
  audit note, and booleans accept `1/on/yes`. A new `-Dumbra.fx.audit-options`
  hook renders every group and reports such mismatches: `audit: CLEAN, 30 note(s)`.
* **Fixed: the slider track painted under the value readout.** JavaFX 8's slider
  skin sizes its track from the control width of the *first* layout pass, and the
  card is narrowed to the viewport afterwards, so the track kept a 2185 px width
  and ran beneath the readout (visible as text sitting "inside" the slider). The
  pair is now a two-column `GridPane` (track 200 / readout 46), the track is pinned
  with `setMaxWidth(200)`, and the slider is clipped to its own bounds so the skin
  cannot paint outside the control; the option rows are rebuilt once after the
  window is shown so controls start at their final width. Verified by pixel scan:
  track bands 2185 px → 183–206 px, zero readout-coloured pixels inside a track.
* **CFR metric fix in the red/blue harness**: the decompile row counted
  `public class` in CFR's output, which measures class modifiers (inner/abstract
  classes are emitted without `public`) instead of the obfuscation. A class now
  counts as recovered only when CFR structured it without the
  `Unable to fully structure code` fallback, with the roadmap's `<50 %` verdict;
  both numbers are printed.
* **`--set <typed section>.*` now works**: `--set renamer.enabled=false`,
  `--set flowObfuscation.level=aggressive`, `--set stringEncryption.minLength=3`
  and the other typed keys used to land in the advanced-option map while the
  engine read the typed section. The mapping happens in the CLI assembly stage,
  so the precedence is preset < `--set` < explicit switches (`--no-flow`, …), and
  a configuration without typed keys keeps the exact same objects.
* **Fixed: intermittent `IllegalAccessError` in `maximum` builds**:
  `AntiLlmPass` inserted a cross-class decoy call to a `private static` method;
  the call site is guarded by a `nanoTime`-seeded predicate, so the illegal
  instruction only linked when that guard happened to fire (≈0.3 % of runs).
  Cross-class decoys are now promoted to package access and only target classes
  in the same package. Static audit: 11 illegal cross-class references → 0;
  stress: 800 runs of a `maximum` artifact → 0 failures.
* **QA**: two stale `NativeDynamicTest` expectations were aligned with the
  opt-in executable-memory scan (`0x40000` is level 3 only since 3.2.1). New
  suites `OtpTest` (17 checks) and `TypedSetTest` (38 checks); the red/blue
  harness gains a seventh attack row (one-shot OTP state reuse), which reports
  `N/A` and leaves the denominator when a sealed archive hides the state class.
* Verification: 26 suites green, `demo` runs at `light`/`balanced`/`maximum`
  (`-Xverify:all` on `maximum`), SnakeGame `maximum` opens its window.

## 3.2.1 history

GUI animation/UX update on top of 3.2.0.

* **Mode options sliders**: all 25 integer options now use custom animated
  sliders (click, drag, wheel, arrow/PgUp/PgDn/Home/End, focus ring, tooltip).
  Thumb/fill ease over 160 ms; mode switch, Reset and YAML refresh animate to
  the new target without firing callbacks during refresh.
* **Smoother GUI**: one shared 60 fps animation helper with frame-time delta,
  coalesced bounded repaints, auto-stop and a 200 ms cap. Applied to pill
  switches, group expand/collapse and hover, preset/mode chips, buttons,
  status-bar and console fades; the whole-window entrance timer was removed.
  `-Dumbra.gui.animations=false` disables motion; screenshot rendering forces
  deterministic still frames.
* **Verification**: GuiSelfTest 1,458 checks / 0 failures, GuiConfigTest 311,
  GuiLayoutTest 16; real slider-driven protect (`flowObfuscation.maxInstructions=12000`,
  `string.strength=3`) -> Verification OK and protected demo prints OK.
* No engine/security changes in 3.2.1; 3.2.0 security fixes and the index-v3
  compatibility note still apply.

## 3.2.0 history

Umbra 3.2 hardens the encrypted-archive layer against the exact attacks shown by
an independent analysis of a 3.1 demo sample, without changing the Java 8 /
ASM-only build. Encrypted archives use a new **index v3** format (old v2
archives are not loadable, rebuild them). The desktop GUI gains per-mode
detailed option sheets.

## Security hardening

* **Sample-bound master key** (`classEncryption.masterBinding=sample` default):
  a fresh 32-byte site seed plus the ZIP comment and entry count derive the
  archive master key; two builds of the same input differ, and editing the
  comment or adding/removing entries makes every payload unreadable.
* **Per-entry nonce in the KDF**: class/resource keys are
  `HMAC(master, "c:"+name || nonce)` so repeated builds no longer produce
  stable per-class keys.
* **Keyed digests**: class/resource/loader integrity is HMAC-keyed; a decrypted
  payload can no longer be verified offline without the master key.
* **Integrity defaults**: encrypted archives use level ≥2 (per-class keyed
  digest on every decrypt/define); a sampled, randomly ordered watchdog
  re-verifies ~1/20 of the payloads per tick with a fail-closed heartbeat.
* **No self-identifying failures**: refusals are silent (empty stack, no fixed
  `[umbra-guard]` prefix, no `Umbra*.java`/line numbers in plaintext runtime
  templates); diagnostics only with `-Dumbra.debug=true` or `action=log`.
* **Build-time assertions**: no `@@` placeholders, index/ZIP cross-check,
  exact plaintext-class set, module-info only when present, bounded index
  reads, payload algorithm whitelist, ZIP-comment consistency.
* **New guard signals**: `-XX:+HeapDumpOnOutOfMemoryError` /
  `+HeapDumpBeforeFullGC`, `jdk.attach.allowAttachSelf`.
* **String hardening**: randomized per-class site indices, per-artifact domain
  salt (payload v3), plaintext cache **off by default**, verified
  wipe/hide-trace flags, randomized multi-engine selection.
* **Native guard**: random extraction directory/filename (no
  `umbra-guard-*`), mark-and-overwrite cleanup, RegisterNatives with only
  `JNI_OnLoad`/tick exported, PE timestamp option, stripped COFF symbols,
  strict PE hygiene assertions (122 KB → ~24 KB cold guard).
* **Config**: `classEncryption.masterBinding`, `classEncryption.watchdogMs`,
  `string.siteSalt`, `string.cache`, `native.timestamp`.

## GUI

* **Mode options…** button in the Preset group opens a 900×700 sheet with
  **12 groups / 111 controls** covering names, strings, integers/MBA, flow,
  exceptions, virtualization, native, archive/class encryption, anti-debug,
  type confusion/anti-analysis, compatibility and output.
* Selecting Light/Balanced/Aggressive/Maximum/Nocturne fills every control with
  the CLI-equivalent defaults; any edit switches to Custom; Reset restores the
  mode defaults; the left-column switches stay in sync both ways; YAML
  load/save round-trips every detailed value.

## Verification

See `docs/REPORT-3.2.md`: full `build.cmd -Task test` gate, `SecurityHardeningTest`
(126 checks), `StringHardeningTest` (61), `NativeGuardTest` (90),
`NativeDynamicTest` (116), GUI tests and clean/JDWP/javaagent/tamper runs.
Residual limitations are listed there (Windows mapped-DLL cleanup, P0-3
fingerprint-in-KDF deferred, sampled watchdog detection window).

## 3.1 history

Umbra 3.1 is a hardening release on top of 3.0: a systematic bug hunt with
fixes, and a substantially strengthened dynamic-protection layer (runtime
guard, real attach detection, anti-dump, native dynamic checks). The
compatibility model, CLI, GUI, plugins and Java 8/ASM-only build are unchanged.
Full evidence: `docs/REPORT-3.1.md` and `docs/AUDIT-3.1.md`.

## Dynamic protection

* **Unified Java runtime guard** (one injected class shared by entry points,
  integrity and the class-encryption loader):
  * JVM/agent arguments (`jdwp`, `-Xdebug`, `-Xrunjdwp`, `-agentlib`,
    `-agentpath`, `-javaagent`, `-XX:+StartAttachListener`,
    `-XX:+EnableDynamicAgentLoading`, `sun.java.command`);
  * environment markers (`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`,
    `JDK_JAVA_OPTIONS`, `FRIDA_*`, `GUM_*`, Frida/Gum `LD_PRELOAD` /
    `DYLD_INSERT_LIBRARIES`);
  * debugger/attach detection (`sun.jdwp.listenerAddress`, `JDWP*` threads,
    `.attach_pid<pid>`/`.java_pid<pid>`, real JDWP handshake on the advertised
    port, JMX remote properties);
  * **dynamic-attach watcher**: `WatchService` on the temp directory for the
    transient attach-pid files, agent-load frame sampling on the Attach
    Listener thread, and thread-snapshot diffing (a `JDWP*`/`Attach Listener`
    thread that appears after install is a signal);
  * randomized timing/anti-suspend drift and a randomized daemon watchdog;
  * sticky fail-closed state: on a signal the class-encryption loader refuses
    to decrypt/define classes; actions `throw|exit|corrupt|log`.
* **Native guard hardening**: anti-remote-thread (thread start addresses outside
  all modules), executable private-memory scan (manual mapping/injected code),
  guard-page/memory-breakpoint scan, randomized code-section sampling, timing
  drift, unbacked-module detection, opt-in level-3 external-handle anti-dump,
  Linux `/proc` tracer/maps checks; one gcc compile per run with a post-link
  sampled-hash table.
* **Anti-dump**: per-class digests re-checked at define time, plaintext/key
  buffers wiped after use, loader integrity and guard inheritance, rebuilt
  native DLL refused via fingerprint + backfill challenge.
* **New options**: `antiDebug.attachWatch` (true), `antiDebug.portProbe`
  (false), `antiDebug.env` (true), `antiDebug.timing` (true), plus the native
  level-2/3 knobs; all documented in `docs/OPTIONS.md`.

## Bugs fixed (summary; full table in `docs/AUDIT-3.1.md`)

* **Config/YAML**: config writer quoted paths/keys (save→load truncation at
  `#`/`:”); tab-indentation parsing no longer chops keys; BOM stripped in the
  parser; single-quoted scalars are literal; empty `input:`/`output:` treated
  as unset.
* **CLI/security**: license gate holes (config-supplied license ignored with
  `--require-license -c`; unreadable license now exits 3; `--license` keeps the
  config public key/require; `--require-feature` without a license exits 3);
  clean errors for malformed JARs/missing config/invalid numbers; out-of-range
  limits rejected; `--allow-in-place` required to overwrite the input;
  `--dry-run` works without `-o`; unwritable `--compat-report` is a warning,
  not a failed run.
* **GUI**: headless launch exits 1; missing/unknown arguments exit 2.
* **Archive/layout**: invalid manifests sanitized (output always
  `JarFile`-readable); BOM in manifests; invalid `module-info` dropped in AUTO
  mode; versioned-only `Main-Class` verified correctly; corrupt nested
  `BOOT-INF/lib` jars are a hard verify error; output written via temp file +
  atomic move.
* **Passes**: string encryption can no longer overflow the 64 KB method limit
  (`strings.skipped.methodSize/classLimit`); flow junk insertion is frame-aware
  with a conservative retry.
* **Dynamic**: `action=log` now works; encrypted-archive level-3 watchdog
  actually starts; the duplicate agent-arg check no longer overrides the guard;
  guard lazy-init concurrency window closed; 3.0 guard level-2 cost reduced
  from ~1.05 s to ~32–42 ms; native guard single-compile/temp-dir/JNI-symbol
  fixes.

## Verification

* `build.cmd -Task test`: all self-test suites green (counts in
  `docs/REPORT-3.1.md`); new `AuditTest` (126 checks), `DynamicGuardTest`
  (239 checks incl. real dynamic attach and no-port-scan false-positive
  regression), `NativeDynamicTest` (89 checks).
* Clean-JVM false-positive matrix: anti-debug levels 1–3 on JDK 8/21/26 run
  normally (no guard output, watchdog never keeps the JVM alive).
* Detection: startup `-javaagent`/`-agentlib:jdwp`/`-Xrunjdwp`, dynamic attach
  (native guard deterministic; Java-only best-effort on Windows — measured
  single-attempt 50–75 %, retried in tests, Linux deterministic via attach-pid
  WatchService), FRIDA/env markers, fake JDWP listener with port probing off by
  default, `.attach_pid` artifacts, encrypted payload tamper refusal.
* External-artifact acceptance and feature matrix: see
  `qa/results-3.1/` and `docs/REPORT-3.1.md`.

## Known limitations (new in 3.1)

* Java-only dynamic-attach detection on Windows is best-effort (pipe-based
  attach exposes only a few-ms agent-load frame); the native guard
  (`antiDebug.nativeGuard=true`) is recommended when dynamic attach must be
  detected reliably.
* Linux native guard checks are compiled but not executed on this Windows
  host; `/proc` parsers are unit-tested.
* Real debugger/Frida/manual-map scenarios are not simulatable here; native
  checks are covered by synthetic hooks and compiled paths. The executable
  memory scan ignores RWX regions to avoid JIT false positives.
* `antiDebug.portProbe` is diagnostic and off by default (a foreign local JDWP
  server could otherwise cause a false positive).
* Lazy class encryption tolerates tampered payloads for resources the program
  never reads; used class payloads are refused.
* Flow on one exotic StackMapTable shape is still rolled back (ASM frame-merge
  limitation) — output remains valid, that class keeps less protection.
* Existing 3.0 limitations (nested-layout root-protection skips, non-executable
  WAR, Windows-focused native codegen, heavy presets, opt-in semantic
  transforms) still apply.

## Compatibility

JDK 8+ to run the tool; protected outputs keep the input class-file version and
run on JDK 8 through current JDKs. Windows is the primary native-code target;
the rest of the pipeline is platform neutral.

## 3.0 history

Umbra 3.0 rebuilt the suite around a layout-aware archive engine (Spring Boot
fat/WAR, multi-release, JPMS, signed, agents), added type confusion, multi-engine
string encryption, flow v2, VM2 v3, native anti-dump, a fully rewritten Swing
GUI and Gradle/Maven plugins, with `--inspect`/`--compat-report` diagnostics.
3.1 keeps all of that and focuses on correctness and runtime protection.

* **The old Swing console is gone.** `io.umbra.gui` now holds only the control
  model (`GuiConfig`, `GuiModeOptions`, `GuiPresets`, `GuiSwitches`); the Swing
  window, its component library and its self-test were deleted, which takes the
  engine jar from 481 to 314 classes (1.51 MB → 1.22 MB). `java -jar umbra.jar`
  with no arguments (or `--gui`) looks for `umbra-gui-fx.jar` next to itself and
  starts the JavaFX console as a child process, printing the command line help
  with the missing pieces when either the console jar or a JavaFX-capable JVM is
  absent. `build.ps1 -Task gui` starts the JavaFX console too.
* **Title bar and About.** The title bar no longer carries the "protection
  console" subtitle (just the mark, the name and the version), and it gained an
  About button that opens a modal window introducing the product: one paragraph on
  what Umbra is, the seven protection layers it implements, and a single muted
  line with the version and the JVM. The status
  pill is pinned to its preferred width, which fixes the truncated "rd" that
  appeared when the bar was squeezed. `-Dumbra.fx.about-shot=<png>` renders the
  About window headlessly.
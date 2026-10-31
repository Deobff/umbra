# Minecraft mod auto-adaptation — verification report

Umbra detects Minecraft mod containers and adapts its protection so the loader
and Mixin runtime can still apply the mod after obfuscation. This document is the
QA contract for that feature: what is detected, what is kept, which protections
are downgraded, and the measured evidence.

Owner: qa (`demo/minecraft/`, `qa/minecraft/`, this document).
Engine code: `src/main/java/io/umbra/core/minecraft/` (mc-adapter / mc-mixin
owners). QA never edits engine code; failures are reported to the Lead instead.

## 1. Options

| option | default | effect |
|---|---|---|
| `minecraft.enabled` | `true` | run mod-container detection; `false` disables adaptation completely |
| `minecraft.forceVmp` | `false` | keep method virtualization enabled for a detected mod (virtualization is otherwise disabled) |
| `minecraft.allowConflicts` | `false` | keep the user's protection settings instead of applying the loader compatibility downgrade |

Detection stats/log: `minecraft.detected`, `minecraft.loader`, `minecraft.modIds`,
`minecraft.keepRules`, `minecraft.frozenClasses`, `minecraft.bodySkipClasses`,
`minecraft.targets` (the loader/mod-id values are logged and exported as report
text stats; keep/body-skip/target counts are numeric report counters).

## 2. What is detected

Detection is resource/annotation driven (read-only, never fails on malformed
metadata) and works on a plain obfuscation input jar, with no Minecraft on the
classpath:

| container | evidence accepted |
|---|---|
| Fabric | `fabric.mod.json` (id, entrypoints, mixins, accessWidener) |
| Quilt | `quilt.mod.json` (`quilt_loader` id/entrypoints/mixin/access_widener) |
| Forge legacy (1.8.9/1.12.2) | `mcmod.info`, `@net.minecraftforge.fml.common.Mod`, `FMLCorePlugin`/`TweakClass`/`FMLAT` manifest attributes, coremod interfaces |
| Forge modern (1.20+) | `META-INF/mods.toml` (`[[mods]]`, `[[mixins]]`), `@Mod` |
| NeoForge | `META-INF/neoforge.mods.toml`, `@net.neoforged.fml.common.Mod` |
| Mixin | `*.mixins.json` configs (including configs referenced from loader metadata), `@Mixin` value/targets, `@Shadow`/`@Overwrite`/`@Inject`/`@At` annotation analysis |
| Access data | `*.accesswidener` files, `META-INF/accesstransformer.cfg` |

The loader string is comma separated (for example `fabric,mixin` or
`forge,mixin`). With the isolated fixtures used here the detected values are
`fabric,mixin`, `quilt,mixin`, `forge,mixin`, `forge,mixin`, `neoforge,mixin`.

## 3. What is kept / exempted

* entry classes and entrypoint methods referenced from loader metadata
  (`fabric.mod.json` entrypoints, Quilt `quilt_loader.entrypoints`, `@Mod`
  classes) keep their names so the loader can find them by string;
* `@Mixin` classes and their targets keep class names, referenced members
  (`@Shadow` fields/methods, `@Overwrite`/`@Inject` targets) and their method
  bodies (body-skip: renaming/debug cleanup may still run, but control-flow,
  virtualization, native conversion, reference hiding and constant rewriting are
  skipped for those classes);
* mixin configs, refmaps, access wideners, access transformers and loader
  metadata resources are preserved verbatim (byte-identical);
* loader plugin/coremod classes are hard-kept and frozen.

Measured on the fixtures (adaptive case):

| fixture | detected loader | keep rules | body-skip classes | mixin targets |
|---|---|---|---|---|
| fabric | fabric,mixin | 9 | 3 | 1 |
| quilt | quilt,mixin | 9 | 3 | 1 |
| forge-legacy | forge,mixin | 10 | 5 | 1 |
| forge-modern | forge,mixin | 8 | 3 | 1 |
| neoforge | neoforge,mixin | 7 | 3 | 1 |

## 4. Auto-downgrade matrix

When a mod container is detected (and `minecraft.allowConflicts=false`), the
following protections are disabled automatically because they conflict with
loader extraction/remapping:

| protection | adaptive run (detected) | `minecraft.enabled=false` control | why it is downgraded |
|---|---|---|---|
| class encryption (`classEncryption.*`) | off (0 classes) | on (25 classes encrypted) | loader reads classes/resources directly; archive encryption needs an executable entry point, which mods don't have |
| standalone integrity (`integrity.*`) | off | delegated/unsupported | same archive-level conflict |
| native code (`native.*`) | off (0 methods) | would convert bodies | loader/Mixin patches bytecode from outside |
| method virtualization (`methodVirtualization.*`, `vm2.*`) | off (0 methods) unless `minecraft.forceVmp=true` | on (9 methods) | Mixin injection points and remapping match bytecode shape |
| reference obfuscation (`referenceObfuscation.*`) | off (0 indy sites) | on (2 sites) | reflected/remapped call sites and bootstrap expectations |
| resource rewriting (`resources.*`) | off (0 resources rewritten) | on | mixin configs/refmaps/AW/AT must stay byte-identical |
| member trimming (`trim.*`) | off (0 members) | on | loader/mixin access members are looked up by name |
| renaming / string / int encryption / flow | **kept on** for ordinary classes | kept on | still valid for non-adapted classes |

`minecraft.forceVmp=true` re-enables virtualization (measured 2 virtualized
methods in the fabric control) while mixin/target bodies remain untouched.
`minecraft.allowConflicts=true` keeps the user's aggressive settings: class
encryption (18 classes) and virtualization (2 methods) stayed on and the archive
was no longer loadable as plain classes.

## 5. Synthetic verification matrix

Harness: `qa/minecraft/verify-mc.cmd` → obfuscates each fixture with aggressive
settings, checks the audit report/log and runs the simulated-loader harness
(`demo/minecraft/harness/src/qa/mc/McHarness.java`) over the protected jar. The
harness derives the entry class/method from the protected jar's **own metadata**
(never from a mapping), loads it through a `URLClassLoader`, invokes it, captures
the marker and asserts: every `.class` entry readable (no class encryption), no
native library, entry/mixin/target class names unchanged, metadata + mixin
config + refmap + AW/AT byte-identical, target/mixin method bodies
instruction-for-instruction identical (no VM/switch), and ordinary classes still
protected (helper token not plaintext).

Result (semantics, 2026-10-23, seed 23303, isolated build
`build-qa\umbra.jar` sha256 `bb4803c8d8e7b0427370ca9261053c23ff2cb7cc08bdb6c4f2e3de0ea3d27e84`):
`qa/minecraft/results/20261023-195859/summary.md` — **PASS**, all cases:

| fixture | case | status | detected | keep | body-skip | targets | classEnc | native | vm | indy | out bytes | ratio | harness |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fabric | adaptive | PASS | 1 | 9 | 3 | 1 | 0 | 0 | 0 | 0 | 20,622 | 2.16× | RESULT PASS + marker |
| fabric | enabled-false | PASS | 0 | 0 | 0 | 0 | 25 | 0 | 9 | 2 | 74,609 | 7.81× | NO_ADAPT_CONFIRMED |
| fabric | vm-forced | PASS | 1 | 9 | 3 | 1 | 0 | 0 | 2 | 0 | 29,790 | 3.12× | RESULT PASS + marker |
| fabric | conflicts | PASS | 1 | 9 | 3 | 1 | 18 | 0 | 2 | 1 | 65,696 | 6.88× | CONFLICT_CONFIRMED |
| quilt | adaptive | PASS | 1 | 9 | 3 | 1 | 0 | 0 | 0 | 0 | 19,810 | 2.25× | RESULT PASS + marker |
| forge-legacy | adaptive | PASS | 1 | 10 | 5 | 1 | 0 | 0 | 0 | 0 | 21,277 | 2.08× | RESULT PASS + marker |
| forge-modern | adaptive | PASS | 1 | 8 | 3 | 1 | 0 | 0 | 0 | 0 | 21,363 | 2.08× | RESULT PASS + marker |
| neoforge | adaptive | PASS | 1 | 7 | 3 | 1 | 0 | 0 | 0 | 0 | 20,640 | 2.15× | RESULT PASS + marker |

All runs also passed `--verify` on JDK 8; the harness runs on JDK 8 as well.
Every adaptive case asserted: `minecraft.detected=1`, expected loader in the
detection log, keep-rules/body-skip/targets > 0, class-encryption/native/VM/
reference-hiding/trimming/resource-rewriting/integrity counters at zero,
ordinary classes still renamed and strings still encrypted, helper token not
present in plaintext, and mixin/target bodies unchanged.

Fixture isolation (per Lead review): each fixture jar contains only its own
loader's canonical metadata and classes, e.g. `fabric.jar` has
`fabric.mod.json` + `demo.accesswidener` + `demo.mc.mixins.json`/refmap and only
Fabric entry/stub classes; Forge jars have `mcmod.info`/`META-INF/mods.toml` +
AT, NeoForge has `META-INF/neoforge.mods.toml` + AT, and no fixture contains
another loader's metadata.

## 6. Real-loader verification (Fabric 1.21.4)

`qa/minecraft/real-loader.cmd` installs a real Fabric 1.21.4 server (Fabric meta
+ Mojang piston-meta downloads), builds a tiny real Fabric mod
(`qa.realtest.RealMod implements ModInitializer`, prints
`UMBRA_MC_REAL_MARKER realtest`), and runs the server twice with `eula=true`:
once with the untouched control mod, once with the Umbra-protected mod (aggressive
settings that the adapter must downgrade). A PASS requires both runs to print the
mod marker and reach `Done (…)`.

Verdict: **PASS** (2026-10-23, run
`qa/minecraft/results/real-loader/20261023-195844/summary.md`).

| item | value |
|---|---|
| Minecraft server | Fabric 1.21.4 (Mojang piston-meta), loader `0.16.9`, installer `1.0.1` |
| Java (server + Umbra for this mode) | Zulu `openjdk 21.0.9` LTS (`C:\Program Files\Zulu\zulu-21`) |
| Umbra jar | `build-qa\umbra.jar`, sha256 `bb4803c8d8e7b0427370ca9261053c23ff2cb7cc08bdb6c4f2e3de0ea3d27e84` |
| real mod | `qa.realtest.RealMod implements net.fabricmc.api.ModInitializer`, prints `UMBRA_MC_REAL_MARKER realtest`, `fabric.mod.json` id `umbra-qa-realtest` |
| control run | marker printed, `Done (0.923s)`, 23 s wall time, `logs/server-control.log` |
| protected run | Umbra-protected jar 11,465 bytes sha256 `bb4803c8d8e7b0427370ca9261053c23ff2cb7cc08bdb6c4f2e3de0ea3d27e84`; marker printed, `Done (1.265s)`, 17 s wall time, `logs/server-protected.log` |
| adaptation on the real mod | `minecraft: detected fabric` (1 keep rule; 0 mixin body-skip because this tiny mod has no mixins); aggressive flags were requested (`classEncryption`, `integrity`, `--virtualize`, `--reference-obfuscation`, `--rewrite-resources`, `--trim`, `mba`, `--anti-debug`) and downgraded automatically |
| evidence | `summary.md`/`summary.json`, `protect-report.json`, `logs/server-*.log`, `mod/realtest-{control,protected}.jar`, `mod/umbra-mapping.txt` |

Both servers were launched headless with `eula=true` and a bounded wait for
`Done (` plus the mod marker; the process is stopped after the assertions. The
run reused a cached server installation (`server/` directory) for the second
build, which is why the protected run took 17 s; the first run downloaded the
Minecraft server and libraries and took 69 s. A missing network/toolchain is
reported as SKIP with the concrete reason, never as PASS.

The bulky cached server installation (Minecraft server jar, libraries, world)
is pruned from the repository after the run — only the summary, server logs, the
two real mod jars (control 1,318 B / protected 11,465 B) and the protect report
are kept (~830 KB for the whole real-loader evidence). Re-running
`qa\minecraft\real-loader.cmd` re-downloads the server automatically.

## 7. Reproduction

```bat
rem fixtures + simulated loader matrix
cmd /c qa\minecraft\build-fixtures.cmd -Clean
cmd /c qa\minecraft\verify-mc.cmd -UmbraJar build-qa\umbra.jar

rem real Fabric server (best effort; needs network + Java 21)
cmd /c qa\minecraft\real-loader.cmd -UmbraJar build-qa\umbra.jar
```

Fixtures: `qa/minecraft/fixtures/*.jar` + `FIXTURES.json`; sources under
`demo/minecraft/src` (stub annotations only, no external dependencies) and
metadata under `demo/minecraft/resources`; build script compiles with plain
`javac` (Java 8 target).

## 8. Known limitations

1. **External mixin targets.** Real mods usually target game classes that live in
   the Minecraft jar, not in the mod jar. Umbra keeps the target class name and
   injection members, but QA cannot compare the body of a class that is not part
   of the input archive; the fixture includes a synthetic target inside the mod
   jar to make the body-immutability assertion measurable.
2. **Nested jars.** Fabric/Forge jars may bundle `META-INF/jars/*.jar` (JiJ) and
   additional nested mixin configs. The detector scans archive resources and
   classes of the outer jar; nested container metadata is not recursively
   adapted (out of scope for this feature pass).
3. **Coremods / 1.8.9 differences.** Forge 1.8.9 coremods (`IFMLLoadingPlugin`,
   access transformers in manifests) are recognised conservatively (name plus
   manifest attributes); exotic coremod bytecode patching is not modelled.
4. **Refmaps / Mixin AP remapping.** Refmaps and mixin configs are preserved
   byte-identically and never rewritten. This is correct only while the target
   names referenced by the refmap are kept, which the adapter does for mixin
   targets; a mod that depends on Mixin AP re-obfuscation of an external game jar
   is not supported.
5. **Class encryption cannot be used on mods** (no archive entry point; loader
   reads classes directly) and is downgraded. If a user forces it via
   `minecraft.allowConflicts=true`, the output is not loadable by the loader —
   the conflicts control asserts exactly that.
6. **Anti-debug without an entry point.** Real mod jars have no `main`; the
   anti-debug guard is injected but reported as unreferenced
   (`anti-debug: no program entry point found ... unreferenced`) — harmless, but
   it means anti-debug protection is effectively useless for pure mod jars.
7. **Real loader is single-version.** The real-loader check uses Fabric 1.21.4
   only (Forge 1.12.2/NeoForge server installers are much heavier and were not
   attempted in the time box); loader-specific quirks of other versions are
   covered only by the synthetic metadata matrix. The real test mod has no
   mixins, so the real server proves metadata detection, entrypoint keep and
   downgrade behaviour; mixin keep/body-skip behaviour is proven synthetically
   (Fabric/Quilt/Forge/NeoForge fixtures).
8. **Detection is metadata-driven.** A heavily customised mod with non-standard
   metadata file names (or metadata generated at build time into unknown paths)
   will not be adapted; the fallback is a normal obfuscation run without keeps.

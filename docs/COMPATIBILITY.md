# Umbra 3.0 — compatibility model and tested inputs

This document defines what "any build program" means for Umbra 3.0: which
archive layouts, class-file generations and build toolchains are supported,
what Umbra guarantees for each, and where the remaining limits are. The
evidence tables in section 5 are filled from `qa/results-3.0/` runs (commands,
logs and hashes are kept there); anything not tested is explicitly listed as
untested instead of being claimed.

## 1. Supported archive layouts

Umbra detects the layout before any pass runs (`io.umbra.core.compat`) and
writes the transformed program back into the same container.

| Layout | Detection | Transform behaviour | Container preservation |
|---|---|---|---|
| Flat JAR | default | all classes transformed, entry points rewritten | original resource entries kept, `META-INF/INDEX.LIST` dropped |
| Spring Boot fat JAR (2.x/3.x) | `BOOT-INF/classes/`, `BOOT-INF/lib/`, `Main-Class=…JarLauncher/WarLauncher`, `Start-Class` | classes under `BOOT-INF/classes/` transformed in place; root loader classes (`org.springframework.boot.loader.**`) frozen, not renamed and not body-transformed; `Start-Class`/`Main-Class`/agent attributes remapped | nested `BOOT-INF/lib/*.jar` preserved byte-identically **including their STORED compression method** (Spring Boot refuses compressed nested jars) |
| Spring Boot WAR / plain WAR | `WEB-INF/classes/`, `WEB-INF/web.xml`, war launcher | classes under `WEB-INF/classes/` transformed in place | `WEB-INF/lib/`, static resources and JSPs kept; manifest remapped |
| Multi-release JAR | `META-INF/versions/N/` + `Multi-Release: true` | `layout.multiRelease=preserve` (default): every version is transformed with one consistent class/member mapping and written back under `META-INF/versions/N/`; `flatten` produces the 2.0-style plain JAR | `Multi-Release` manifest attribute and versioned directory tree preserved in `preserve` mode |
| Modular JAR | `module-info.class` (root or versioned) | skipped as a normal class; descriptor `exports`/`opens`/`uses`/`provides` remapped through the mapping, or kept/dropped per `layout.moduleInfo` | never emits a descriptor that references renamed packages without updating it |
| Signed JAR | `META-INF/*.SF/.RSA/.DSA/.EC`, digest attributes | signature entries and digest attributes stripped before transformation | output is a valid unsigned JAR; re-sign after protection |
| Java agent JAR | `Premain-Class`, `Agent-Class`, `Launcher-Agent-Class` | those manifest attributes remapped | attach keeps working with the renamed agent class |
| OSGi bundle | `Bundle-SymbolicName`, `Export-Package`, … | class names and package references remapped in manifest headers | valid OSGi metadata for renamed packages |
| JAR index | `META-INF/INDEX.LIST` | dropped | tooling regenerates nothing; safe |

Class-name references inside `META-INF/services/*`, `spring.factories`,
`META-INF/spring/*.imports`, `plugin.yml`/`bungee.yml` and (when enabled)
textual resources are rewritten through the same mapping. Duplicate archive
entries no longer abort the run: the first occurrence wins, the rest are
dropped and a `layout.duplicates` statistic plus a warning is emitted.

## 2. Entry-point protection on nested layouts

Class encryption (whole-archive payload + bootstrap loader) and similar
root-level launchers cannot protect a nested loader container; they would
produce an archive that no longer boots. Umbra 3.0 therefore detects the layout
and disables class encryption on non-flat layouts (and on preserved
multi-release archives) with an explicit warning and
`classEncryption.skipped.layout` statistic instead of silently emitting a
broken artifact. Set `layout.forceEntryProtection=true` only if you know the
target loader tolerates it. Entry-point checks that live inside application
methods (anti-debug, integrity, auth gate) remain available.

## 3. Class-file generations and runtimes

* Input classes: ASM 9.11 readers accept class files through the current Java
  release line (Java 8 through Java 26 as of this release). Umbra itself runs
  on JDK 8.
* Output classes keep the input class-file version unless a constant requires
  a newer version (there is an explicit version-safety upgrade step).
* Protected output is tested on Zulu 8, Zulu 21 and Java 26.

## 4. Build-tool integration

| Build tool | Integration | Verification |
|---|---|---|
| CLI / CI scripts | `java -jar umbra.jar` full option surface, `--inspect`, `--compat-report`, `--dry-run` | `qa/verify.ps1` matrix |
| Gradle | `io.umbra` plugin, `umbra{}` extension, `umbraProtect` task (depends on `jar`), configuration-cache compatible | `plugins/qa/run-qa.ps1`, Gradle 8.14 sample build → protect → run |
| Maven | `io.umbra:umbra-maven-plugin`, `umbra:protect` bound to `package` | `plugins/qa/run-qa.ps1`, Maven 3.9.9 sample build → protect → run |
| Spring Boot Maven/Gradle | fat JAR/WAR outputs are protected in place (section 1) | real Spring Boot 2.7.18 / 3.x artifacts in `qa/results-3.0/` |

## 5. Tested input matrix

Final acceptance run (QA final gate, release jar sha256
`13661e1a92d163cbda7c1052e629f6c17bb9e3f4f237623a1544e8876c09cbb5`):
corpus matrix 44/45 PASS, feature matrix PASS, Minecraft PASS; the single
residual is the documented `kotlin-app`/`maximum` oversized-class limitation
(>`ClassTooLargeException` for a generated >64 KB class; `light`/`balanced`
pass). Evidence:
`qa/results-3.0/final/` (summary + logs + reports).

| artifact | toolchain / version | layout | preset(s) / mode | runtime | result |
|---|---|---|---|---|---|
| demo application | `demo/demo.jar` (Javac 8) | flat | baseline, light, balanced, maximum, native, v3 | JDK 8/21/26 | PASS — `Verification: OK`, prints `OK` |
| Spring Boot fat JAR | Spring Boot 2.7.18, Maven 3.9.9, JDK 8 | spring-boot | balanced/maximum in corpus; layout probes light/balanced/maximum | JDK 8/21 | PASS — boots, HTTP marker; 28/28 nested jars STORED |
| Spring Boot 3 fat JAR | Spring Boot 3.2, JDK 21 | spring-boot | balanced | JDK 21 | PASS — HTTP marker `UMBRA-SB3-OK` |
| executable WAR | Spring Boot 2.7.18 | war | light/balanced/maximum | JDK 8/21 | PASS — boots, HTTP `UMBRA-WAR-OK` |
| multi-release JAR | javac (base + versions/17) | multi-release, `preserve` | balanced, light, maximum | JDK 8 / 21 | PASS — `MULTI-BASE` / `MULTI-V17`; versioned path preserved |
| modular JAR | javac 21, `module qa.mod` | module-info | light/balanced/maximum | JDK 21 (`--module-path -m`) | PASS — `JPMS-OK` |
| Java agent | Javac 8, `Premain-Class` | flat | light | JDK 8 attach | PASS — cross-jar attach prints `AGENT-OK` + `TARGET-OK` |
| Java 17 records/sealed | javac 21 `--release 17` | flat | light/balanced/maximum | JDK 21 | PASS |
| Java 21 pattern switch | javac 21 | flat | light/balanced/maximum | JDK 21 | PASS |
| Java 26 class files | javac 26 | flat | light/balanced/maximum | JDK 26 | PASS |
| Kotlin application | Kotlin/Gradle | flat | light/balanced (maximum hits the documented oversized-class limit) | JDK 8 | PASS light/balanced |
| Maven Shade JAR | Maven Shade | flat | balanced/maximum | JDK 8 | PASS |
| Gradle Shadow JAR (Gson `TypeToken`) | Gradle Shadow | flat | light/balanced/maximum | JDK 8 | PASS — generic signatures kept |
| signed JAR | jarsigner (JDK 8) | flat | light/balanced/maximum | JDK 8 | PASS — signature stripped cleanly, runs |
| ServiceLoader app | javac 8 | flat | light/balanced/maximum | JDK 8 | PASS — framework metadata rewritten |
| large real JAR (4k+ classes) | real-world shaded app | flat | light/balanced | JDK 8 | PASS light/balanced; excluded from the official gate for time (optional-dependency verifier note) |

Determinism: two runs with the same seed produce byte-identical output
(`2562676b451dd6e3822ebfe626e0b81ed4af37688b50f234385a09602b7e0665`).
Tamper test: a modified encrypted archive is rejected at startup (exit 1).
Build-tool plugins: Gradle and Maven sample builds → protect → run, 22/22
checks PASS (`plugins/qa/SUMMARY.md`).

## 6. Known limitations (honest list)

* Kernel-level or VM-level attackers are out of scope for every Java
  obfuscator; class-encryption key material necessarily exists in the
  plaintext loader and native libraries are decrypted in memory before
  `System.load`. Umbra raises reverse-engineering cost; it does not make a
  determined native-level reverse engineer impossible.
* On nested layouts (Spring Boot/WAR) whole-archive class encryption is
  disabled as described in section 2.
* Multi-release output in `preserve` mode requires a JDK 9+ runtime to use the
  versioned entries; `flatten` mode intentionally drops them (2.0 behaviour).
* Native code generation is Windows-focused (MinGW/Clang) and requires a local
  C toolchain; every failure falls back to Java methods.
* Full virtual-machine protection of arbitrary methods is intentionally
  conservative: unsupported bytecode shapes are left untouched and counted in
  `virtualization.skipped` rather than producing unverifiable code.
* Frameworks that load classes through custom binary-name conventions not
  covered by the keep analysis (exotic DI containers, custom serializers) may
  still require explicit `--keep` rules; `--inspect` and the audit report list
  the detected frameworks and reflection sites to make this visible.

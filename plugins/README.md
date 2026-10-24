# Umbra build-tool plugins

Protect your project's JAR with **Umbra** from the normal build: a **Gradle**
plugin (`id 'io.umbra'`, task `umbraProtect`) and a **Maven** plugin
(`io.umbra:umbra-maven-plugin`, goal `umbra:protect`, default phase `package`).

Both plugins are thin, dependency-free wrappers around the Umbra CLI. They:

* consume the project JAR, run the real `umbra.jar` as a child process and
  write a protected artifact plus mapping and log;
* stream the CLI output into the build log and **fail the build on a non-zero
  exit** using the documented Umbra exit-code meanings;
* build the command as an **argument vector** (no shell), so paths and values
  with spaces or shell metacharacters are passed verbatim;
* add **no new runtime dependency** to the project — `umbra.jar` itself is the
  only tool involved;
* are compiled to **Java 8 bytecode** (class-file major version 52).

| Module | Artifact | Coordinates |
|---|---|---|
| `umbra-gradle-plugin/` | `plugins/dist/umbra-gradle-plugin-3.0.0.jar` | Gradle plugin id `io.umbra` |
| `umbra-maven-plugin/` | `plugins/dist/umbra-maven-plugin-3.0.0.jar` | `io.umbra:umbra-maven-plugin:3.0.0` |

---

## 1. Requirements and compatibility

Tested combinations are listed in §10 (QA evidence). The honest matrix:

| Component | Validated here | Supported / notes |
|---|---|---|
| Umbra CLI | `dist/umbra.jar` **2.0.0** (current distribution) | Any Umbra with the stable CLI contract `-i -o -c --preset --seed --keep --set --verify`. 3.0 is a drop-in target; QA re-runs against whatever `dist/umbra.jar` is present. |
| Plugin version | 3.0.0 | Plugin releases track the product major version. |
| JDK for the build | Zulu **8.0.502** | JDK 8+ can run Maven/Gradle and Umbra. The plugin classes themselves are Java 8 bytecode. Use `javaHome` to launch Umbra with a different JDK than the build. |
| Gradle | **8.14** (local distribution) | Tested only with 8.14. The plugin uses lazy `Property`/`RegularFileProperty` (Gradle 5.1+) and configuration-cache APIs (Gradle 6.6+), so Gradle 7–8 is expected to work but was not executed; Gradle 9+ is **not** validated. |
| Maven | **3.9.9** | Plugin descriptor declares `requiredMavenVersion 3.6.0`; only 3.9.9 was executed here. |
| OS | Windows 10 | Plugin code is OS-portable (picks `bin/java.exe` vs `bin/java` from `os.name`). The *build/QA helper scripts* in this repository are Windows PowerShell only; the plugins themselves are not. |
| Network | not needed at build time | The plugins never download anything. Building the plugins themselves needs Maven Central once (Maven plugin API/annotations/plugins). |

Umbra CLI contract used (unchanged since 2.0, still printed by `--help`):

```
java -jar umbra.jar -i <input.jar> -o <output.jar> [-c <config.yml>]
     [--preset <name>] [--seed <n>] [--keep <rule>]...
     [--set k=v]... [--verify]
```

Exit codes preserved by both plugins:

| Code | Meaning |
|---:|---|
| 0 | success |
| 1 | configuration / transform failure |
| 2 | `--verify` found a class that does not link |
| 3 | license missing/invalid/revoked (only with `--require-license`) |

---

## 2. Build and install the plugins

### 2.1 One command (recommended)

From the Umbra root:

```bat
plugins\build-plugins.ps1
:: or: plugins\build-plugins.cmd
```

The script (`plugins/build-plugins.ps1`):

1. finds a JDK (`JAVA_HOME`, `-JavaHome`, or `C:\Program Files\Zulu\zulu-8`),
   Gradle 8.14 (`GRADLE_HOME`, `gradle.bat` on `PATH`, or the local Gradle
   wrapper cache) and Apache Maven 3.9.9 (`MAVEN_HOME`, `mvn.cmd` on `PATH`,
   or auto-downloads the pinned zip);
2. builds the Gradle plugin **offline** (`java-gradle-plugin`, no external
   dependencies), copies the jar to `plugins/dist/` and publishes it to
   `~/.m2` with `publishToMavenLocal` (plus the plugin marker), so
   `plugins { id 'io.umbra' version '3.0.0' }` resolves via `mavenLocal()`;
3. builds and installs the Maven plugin with `mvn clean install` and copies
   its jar to `plugins/dist/`;
4. prints the two jar paths, sizes and SHA-256 hashes.

Maven is **not installed system-wide** here. The script uses a pinned,
checksum-verified download:

```
version: 3.9.9
url:     https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.zip
sha-256: 4EC3F26FB1A692473AEA0235C300BD20F0F9FE741947C82C1234CEFD76AC3A3C
```

cached in `plugins/.cache/maven/apache-maven-3.9.9/` (`plugins/.cache/` is
git-ignored). Gradle 8.14, if missing:

```
https://services.gradle.org/distributions/gradle-8.14-bin.zip
```

### 2.2 Manual commands

```bat
:: Gradle plugin (Java 8 bytecode, offline build)
cd plugins\umbra-gradle-plugin
gradle --no-daemon --offline clean jar distJar publishToMavenLocal
:: -> build\libs\umbra-gradle-plugin-3.0.0.jar, copied to plugins\dist\

:: Maven plugin
cd plugins\umbra-maven-plugin
mvn -B -ntp clean install
:: -> target\umbra-maven-plugin-3.0.0.jar, installed in ~/.m2
```

### 2.3 Install into a project without mavenLocal

The Gradle plugin jar is self-contained (only the Gradle API is needed):

```groovy
// settings.gradle of the consuming project (optional, when using a Maven repo)
pluginManagement {
    repositories {
        mavenLocal()            // io.umbra was installed by publishToMavenLocal
        mavenCentral()
        gradlePluginPortal()
    }
}
```

```groovy
// build.gradle — local jar instead of a repository
buildscript {
    dependencies {
        classpath files("path/to/umbra-gradle-plugin-3.0.0.jar")
    }
}
apply plugin: 'io.umbra'
```

For Maven the plugin is a normal artifact in the local repository after
`mvn install`; with an internal repository, `mvn deploy` it there.

---

## 3. Gradle plugin

### 3.1 Minimal build.gradle

```groovy
plugins {
    id 'java'
    id 'io.umbra' version '3.0.0'
}

umbra {
    toolJar = file("${rootDir}/dist/umbra.jar")   // required unless UMBRA_JAR is set
    preset  = 'balanced'
    verify  = true
}
```

```bat
gradlew build           :: normal compile + jar
gradlew umbraProtect    :: protected jar in build\umbra\
```

`umbraProtect` depends on `jar`; when the `java` plugin is present the input
defaults to the `jar` task's archive file.

### 3.2 Full extension reference

```groovy
umbra {
    // Required: Umbra CLI jar (default: UMBRA_JAR environment variable).
    toolJar = file("${rootDir}/dist/umbra.jar")

    // Optional JDK/JRE home used to launch Umbra (default: build JVM).
    javaHome = 'C:/Program Files/Zulu/zulu-8'

    // Optional YAML config passed as -c; explicit DSL values override it.
    config = file('umbra.yml')

    // Input jar (default: the jar task archive file).
    input = file("${layout.buildDirectory.get().asFile}/libs/app.jar")

    // Protected output jar (default: build/umbra/<project-name>-obf.jar).
    output = file("${layout.buildDirectory.get().asFile}/umbra/app-obf.jar")

    // Optional preset: light|balanced|aggressive|maximum|library|spring-boot|
    // jackson|service-loader|micronaut|nocturne (validated by the CLI).
    preset = 'balanced'

    seed   = 23303L
    verify = true

    // Keep rules, passed as repeated --keep.
    keep = ['com.example.Main', '@io.umbra.annotations.Keep']

    // Advanced options: 'key=value' becomes --set key=value; entries starting
    // with '-' are passed to the CLI verbatim (new CLI flags work without a
    // plugin release).
    options = [
        'mba.enabled=true',
        'vm2.enabled=true',
        '--fixed-time'
    ]

    // Retain the mapping (and optionally the full CLI log) for stack-trace
    // de-obfuscation and release evidence.
    mapping = file("${layout.buildDirectory.get().asFile}/umbra/mapping.txt")
    logFile = file("${layout.buildDirectory.get().asFile}/umbra/umbra.log")
}

// Optional: protect as part of the standard build.
tasks.named('build') { dependsOn 'umbraProtect' }
```

### 3.3 Kotlin DSL (build.gradle.kts)

```kotlin
plugins {
    java
    id("io.umbra") version "3.0.0"
}

umbra {
    toolJar.set(file("${rootDir}/dist/umbra.jar"))
    preset.set("balanced")
    seed.set(23303L)
    verify.set(true)
    keep.set(listOf("com.example.Main"))
    options.set(listOf("mba.enabled=true"))
    mapping.set(file("build/umbra/mapping.txt"))
    logFile.set(file("build/umbra/umbra.log"))
}

tasks.named("build") { dependsOn("umbraProtect") }
```

### 3.4 Task details

| Property | Default | CLI argument |
|---|---|---|
| `toolJar` | `UMBRA_JAR` env, else required | `-jar <toolJar>` |
| `javaHome` | build JVM (`java.home`) | executable selection |
| `config` | none | `-c <config>` |
| `input` | `jar` task archive file | `-i <input>` |
| `output` | `build/umbra/<project>-obf.jar` | `-o <output>` |
| `preset` | none (CLI default) | `--preset` |
| `seed` | none | `--seed` |
| `verify` | `false` | `--verify` |
| `keep` | empty | repeated `--keep` |
| `options` | empty | `--set k=v` / free-form flags |
| `mapping` | none | post-run relocation of the CLI mapping |
| `logFile` | none | plugin-side tee of CLI output |

The task is configuration-cache friendly (only lazy properties, no `Project`
access at execution time) and declares `@Input`/`@OutputFile` properties, so a
second run is `UP-TO-DATE`. It is intentionally **not** `@CacheableTask`
(protecting is not a deterministic pure function across machines; use a fixed
`seed` for reproducible output).

---

## 4. Maven plugin

### 4.1 Minimal pom.xml

```xml
<build>
  <plugins>
    <plugin>
      <groupId>io.umbra</groupId>
      <artifactId>umbra-maven-plugin</artifactId>
      <version>3.0.0</version>
      <executions>
        <execution>
          <id>umbra-protect</id>
          <phase>package</phase>
          <goals><goal>protect</goal></goals>
          <configuration>
            <toolJar>${project.basedir}/dist/umbra.jar</toolJar>
            <preset>balanced</preset>
            <verify>true</verify>
          </configuration>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

```bat
mvn package                       :: protect runs in the package phase
mvn io.umbra:umbra-maven-plugin:3.0.0:protect   :: or invoke directly
```

### 4.2 Full configuration reference

```xml
<plugin>
  <groupId>io.umbra</groupId>
  <artifactId>umbra-maven-plugin</artifactId>
  <version>3.0.0</version>
  <executions>
    <execution>
      <id>umbra-protect</id>
      <phase>package</phase>
      <goals><goal>protect</goal></goals>
      <configuration>
        <!-- required unless UMBRA_JAR is set -->
        <toolJar>${project.basedir}/dist/umbra.jar</toolJar>
        <javaHome>C:/Program Files/Zulu/zulu-8</javaHome>
        <configFile>${project.basedir}/umbra.yml</configFile>
        <input>${project.build.directory}/${project.build.finalName}.jar</input>
        <output>${project.build.directory}/${project.build.finalName}-obf.jar</output>
        <preset>balanced</preset>
        <seed>23303</seed>
        <verify>true</verify>
        <keep>
          <keep>com.example.Main</keep>
          <keep>@io.umbra.annotations.Keep</keep>
        </keep>
        <options>
          <option>mba.enabled=true</option>
          <option>--fixed-time</option>
        </options>
        <mapping>${project.build.directory}/umbra/mapping.txt</mapping>
        <logFile>${project.build.directory}/umbra/protect.log</logFile>
      </configuration>
    </execution>
  </executions>
</plugin>
```

| Parameter | Maven property | Default |
|---|---|---|
| `toolJar` | `-Dumbra.toolJar=` | `UMBRA_JAR` env, else required |
| `javaHome` | `-Dumbra.javaHome=` | build JVM |
| `configFile` | `-Dumbra.config=` | none (`-c`) |
| `input` | `-Dumbra.input=` | `target/<finalName>.jar` |
| `output` | `-Dumbra.output=` | `target/<finalName>-obf.jar` |
| `preset` | `-Dumbra.preset=` | none |
| `seed` | `-Dumbra.seed=` | none |
| `verify` | `-Dumbra.verify=` | `false` |
| `keep` | – | empty |
| `options` | – | empty |
| `mapping` | `-Dumbra.mapping=` | none |
| `logFile` | `-Dumbra.logFile=` | none |

The Mojo is `threadSafe`, bound to `package`, and declares
`requiresDependencyResolution=runtime` (like an obfuscation/proguard step).
The protected jar is an **additional** artifact; the original
`target/<finalName>.jar` remains untouched for mapping/debugging. Do not point
`output` at the original artifact unless you deliberately want it replaced.

---

## 5. `options`: advanced flags and the full CLI surface

Named parameters cover the stable option set. Everything else goes through
`options` (Gradle) / `<options>` (Maven):

| Entry form | Result |
|---|---|
| `key=value` | two argv tokens: `--set` and `key=value` |
| starts with `-` | split on whitespace and appended verbatim (no shell, no expansion) |

Examples:

```groovy
options = [
    'string.strength=3',                       // --set string.strength=3
    '--reference-obfuscation',                 // plain CLI flag
    '--input-mapping build/umbra/mapping.txt', // flag with a value
    '--lib libs/runtime.jar',                  // repeatable flag with a value
    '--incremental build/prev-obf.jar'
]
```

Because free-form entries are split on whitespace only, a value containing a
space must be provided through the `options` string as-is
(`'--auth-title My App'` becomes three tokens and is not a valid Umbra
argument); use a config YAML or a value without spaces instead.
`--dry-run` is honoured: the plugin skips output-jar checks and mapping
relocation.

3.0-only flags can be passed the same way without waiting for a plugin
release, e.g. `options = ['--inspect']` (the plugin does not validate flags; the
CLI does).

---

## 6. Mapping, logs, and reproducible builds

* The **mapping** file (ProGuard-style, `MappingWriter` output) is what you
  need to de-obfuscate stack traces and to keep names stable across releases.
* Umbra 2.x writes its mapping next to the output jar as
  `umbra-mapping.txt`; the CLI has **no flag for the mapping path**. The
  plugin's `mapping` parameter therefore moves that file to the requested
  location after a successful run (printed in the build log). If the YAML
  config sets a custom `renamer.mappingFile`, the CLI writes there and the
  plugin prints a warning instead of pretending success.
* Reuse a previous mapping for stable names with
  `options = ['--input-mapping build/umbra/mapping.txt']` (CLI
  `--input-mapping`).
* `logFile` tees the complete CLI stdout/stderr (UTF-8) including the exact
  command line. Keep it as release evidence.
* Reproducibility: pass a fixed `seed` and add `--fixed-time` through
  `options`. Same input + config + seed then produces byte-identical output.

---

## 7. CI examples

### 7.1 GitHub Actions — Gradle

```yaml
name: build-and-protect
on: [push]
jobs:
  protect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '8'
      - uses: gradle/actions/setup-gradle@v4
        with:
          gradle-version: 8.14
      - name: Install Umbra plugins
        run: |
          gradle -p plugins/umbra-gradle-plugin publishToMavenLocal
      - name: Build and protect
        env:
          UMBRA_JAR: ${{ github.workspace }}/dist/umbra.jar
        run: gradle build umbraProtect
      - uses: actions/upload-artifact@v4
        with:
          name: protected
          path: |
            build/umbra/*-obf.jar
            build/umbra/mapping.txt
            build/umbra/umbra.log
```

The plugin falls back to the `UMBRA_JAR` environment variable when `toolJar`
is not configured, so a CI can inject the tool path without editing the build
file. Windows runners can use the same commands with `gradlew.bat` /
`gradle.bat`. The examples assume `dist/umbra.jar` is present in the checkout
(checked in, or restored from a release artifact in an earlier step).

### 7.2 GitHub Actions — Maven

```yaml
name: build-and-protect
on: [push]
jobs:
  protect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '8'
      - name: Install Umbra plugins
        run: mvn -B -ntp -f plugins/umbra-maven-plugin/pom.xml install
      - name: Build and protect
        env:
          UMBRA_JAR: ${{ github.workspace }}/dist/umbra.jar
        run: mvn -B -ntp package
      - uses: actions/upload-artifact@v4
        with:
          name: protected
          path: |
            target/*-obf.jar
            target/umbra/mapping.txt
            target/umbra/protect.log
```

### 7.3 Jenkins (declarative pipeline)

```groovy
pipeline {
    agent any
    tools { jdk 'zulu-8' }
    environment {
        UMBRA_JAR = "${env.WORKSPACE}/dist/umbra.jar"
    }
    stages {
        stage('Install Umbra plugins') {
            steps {
                sh 'mvn -B -ntp -f plugins/umbra-maven-plugin/pom.xml install'
                // Gradle plugin instead: sh 'gradle -p plugins/umbra-gradle-plugin publishToMavenLocal'
            }
        }
        stage('Build + protect') {
            steps {
                sh 'mvn -B -ntp clean package'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'target/*-obf.jar, target/umbra/mapping.txt, target/umbra/protect.log',
                             allowEmptyArchive: true
            junit 'target/surefire-reports/*.xml'
        }
    }
}
```

Windows agents: use `bat 'mvn -B -ntp package'` and
`bat 'gradle.bat -p plugins\\umbra-gradle-plugin publishToMavenLocal'`.

Artifacts to retain from any CI run: **protected jar**, **mapping**,
**log**, and (when used) the license file.

---

## 8. Repository layout

```
plugins/
  README.md                  this document
  toolchain.ps1              JDK/Gradle/Maven/Umbra-jar discovery + pinned Maven download
  build-plugins.ps1/.cmd     builds both plugins, publishes/installs, copies to dist/
  dist/                      umbra-gradle-plugin-3.0.0.jar, umbra-maven-plugin-3.0.0.jar
  .cache/                    pinned Maven 3.9.9 (git-ignored)
  umbra-gradle-plugin/
    build.gradle, settings.gradle
    src/main/java/io/umbra/gradle/UmbraPlugin.java        plugin id + extension wiring
    src/main/java/io/umbra/gradle/UmbraExtension.java     DSL
    src/main/java/io/umbra/gradle/UmbraProtectTask.java   task action
    src/main/java/io/umbra/tool/CliRunner.java             JDK-only CLI runner
  umbra-maven-plugin/
    pom.xml
    src/main/java/io/umbra/maven/UmbraProtectMojo.java    umbrella Mojo
    src/main/java/io/umbra/tool/CliRunner.java            identical copy
  qa/
    run-qa.ps1/.cmd          end-to-end QA (build -> protect -> run -> failure path)
    gradle-sample/           plain Java "OK" app with the Gradle plugin wired
    maven-sample/            plain Java "OK" app with the Maven plugin wired
    logs/                    captured commands/output of the last QA run
    SUMMARY.md               PASS/FAIL table of the last QA run
```

`CliRunner` is intentionally duplicated in both modules (identical source) so
each plugin jar is self-contained and neither build classpath gains a library.

---

## 9. QA / evidence

```bat
plugins\qa\run-qa.ps1
:: or: plugins\qa\run-qa.cmd
:: reuse the installed plugins without rebuilding them:
plugins\qa\run-qa.ps1 -SkipBuild
```

The script rebuilds and installs the plugins, then executes, with real
commands and captured logs under `plugins/qa/logs/`:

1. Gradle sample: `clean build` → `umbraProtect` → `java -jar` the protected
   jar (expects `OK`), mapping/log presence, `--verify` OK, configuration-cache
   run, and a bad-option run that must fail the build.
2. Maven sample: `mvn -o clean package` (protect bound to `package`) →
   `java -jar` the protected jar (expects `OK`), mapping/log presence,
   `--verify` OK, and a bad-option run that must fail the build.

Results are written to `plugins/qa/SUMMARY.md`; the script exits non-zero if
any check fails. QA runs against whichever `dist/umbra.jar` currently exists
and prints its version, so it can be re-run after every Umbra rebuild.

**Last verified run in this environment** (see `plugins/qa/SUMMARY.md` and
`plugins/qa/logs/` for the exact output):

* JDK `openjdk 1.8.0_502` (Zulu 8), Gradle `8.14`, Maven `3.9.9`,
  Umbra CLI `2.0.0`, plugin version `3.0.0`;
* `22 passed, 0 failed`;
* Gradle protected jar `build/umbra/umbra-gradle-sample-obf.jar` (76,233
  bytes) prints `OK`, Maven protected jar
  `target/umbra-maven-sample-1.0.0-obf.jar` (79,646 bytes) prints `OK`;
* `Verification: OK` from both CLI runs;
* bad preset (`-PumbraPreset=does-not-exist`,
  `-Dumbra.preset=does-not-exist`) → build exit code `1` with
  `Umbra failed with exit code 1 (configuration or transform failure)`;
* Gradle `--configuration-cache` run stored an entry and succeeded.

Exemplary commands from the QA logs:

```bat
:: Gradle sample (plugins/qa/gradle-sample)
gradle --no-daemon --offline clean build
gradle --no-daemon --offline umbraProtect
java -jar build\umbra\umbra-gradle-sample-obf.jar
:: -> OK

:: Maven sample (plugins/qa/maven-sample)
mvn -B -ntp -o clean package
java -jar target\umbra-maven-sample-1.0.0-obf.jar
:: -> OK
```

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `umbra.toolJar is not configured` (Gradle) / `umbra.toolJar is not configured` (Maven) | Set `toolJar`/`<toolJar>` to `dist/umbra.jar` or export `UMBRA_JAR`. The plugins never download Umbra. |
| `Unknown preset: <x>` and exit code 1 | The CLI validates presets. Use `light`, `balanced`, `aggressive`, `maximum`, `library`, `spring-boot`, `jackson`, `service-loader`, `micronaut` or `nocturne`. |
| Exit code 2 with `--verify` | The protected class failed JVM linking (stack maps/descriptors/access). This is an Umbra bug: keep the failing jar + log and report it. |
| Exit code 3 | `--require-license` is active and the license is missing/expired/invalid. |
| Exit code 1 in a Java project that ran fine before | Read the CLI error line in the build log; often a bad `options` entry (`key=value` or `-flag` only) or a config/YAML problem. |
| `UnsupportedClassVersionError` when running the protected jar | Run it with the JDK that matches its bytecode; set `javaHome` to the desired JDK for the CLI when the build JVM differs. |
| Protected jar runs but application fails | Not every framework works with every protection level. Start from `--preset light`, keep reflective entry points (`keep`), then increase. Use `--verify` and application-level smoke tests. |
| `warning: mapping file requested ... was not written` | Renaming is disabled, or the YAML config sets a custom `renamer.mappingFile` (the CLI then writes there). Read the CLI log line `mapping written to ...`. |
| Gradle: `Plugin [id: 'io.umbra'] was not found` | Install it first (`plugins\build-plugins.ps1`, or `gradle -p plugins/umbra-gradle-plugin publishToMavenLocal`) and keep `mavenLocal()` in `pluginManagement.repositories`. |
| Maven: plugin not found | Run `mvn -f plugins/umbra-maven-plugin/pom.xml install` once, or deploy the plugin jar to your internal Maven repository. |
| Maven first build hangs / re-verifies cached artifacts | Maven 3.9 re-checks stale `_remote.repositories` provenance files; removing them (safe) makes offline/local builds fast. The QA script uses `-o` after the plugin build populated the cache. |
| Gradle configuration cache invalidation message | Expected when the plugin jar or tool jar changes. The task itself is configuration-cache compatible (`Configuration cache entry stored`); entries are invalidated by input changes as with any task. |
| Very large `--keep` lists / Windows command line limits | Use a YAML `config` file inside the project instead of hundreds of `keep` entries; the child process still uses an argument vector, but Windows caps the total command line length. |
| Quoting/spaces in paths | No shell is involved: `ProcessBuilder` passes each argument verbatim, so spaces are safe. Only the free-form `-flag value` entries are whitespace-split. |
| PowerShell blocks the scripts | Use the `.cmd` wrappers (`build-plugins.cmd`, `qa\run-qa.cmd`) or run with `-ExecutionPolicy Bypass`. |

---

## 11. Limitations (honest list)

* **Mapping path**: the 2.x CLI has no flag for the mapping output path; the
  plugins relocate `umbra-mapping.txt` from next to the output jar. A future
  CLI `--mapping <file>` flag would remove the relocation step — the plugins
  will keep working either way (relocation is a no-op if paths match).
* **Build scripts are Windows/PowerShell only** (`build-plugins.ps1`,
  `qa/run-qa.ps1`). The plugin code and the manifest/descriptor themselves are
  OS-independent and were only exercised on Windows here.
* **Gradle Plugin Portal publishing** is not configured; distribution is
  `plugins/dist/` + `publishToMavenLocal`/internal repository. Adding the
  `com.gradle.plugin-publish` plugin would be the next step for public
  releases.
* **Gradle 9** is not validated (Gradle 9 requires a Java 17 build JVM and
  drops some old APIs; the plugin avoids deprecated Gradle APIs but was not
  run there).
* The protected artifact is **additional**; projects that want `jar` replaced
  must set `output`/`<output>` to the original artifact path deliberately.
* The task is not `@CacheableTask`, so it re-runs when its inputs change; there
  is no cross-machine build-cache entry.
* `javaHome` only chooses the Java launcher; the plugin does not verify that
  the JDK version matches the bytecode of the project.
* No Maven site/plugin-help generation beyond the generated descriptor.

---

## 12. Root documentation handoff (for the Umbra README / docs)

Text the Umbra maintainer can paste into the root documentation:

> **Build-tool plugins.** `plugins/` contains a Gradle plugin (`id 'io.umbra'`,
> task `umbraProtect`) and a Maven plugin (`io.umbra:umbra-maven-plugin`,
> goal `umbra:protect`, bound to `package`) that run `umbra.jar` on the project
> artifact from the normal build. Both stream the CLI output, fail the build on
> a non-zero exit and retain mapping/log files; they add no dependency to the
> protected project and are Java 8 bytecode. Build them with
> `plugins\build-plugins.ps1` (artifacts in `plugins/dist/`), verify with
> `plugins\qa\run-qa.ps1` (logs + `plugins/qa/SUMMARY.md`). Requirements:
> JDK 8+, Gradle 8.x (tested 8.14), Maven 3.9.x (tested 3.9.9). See
> `plugins/README.md` for usage, CI snippets and troubleshooting.

Suggested root `.gitignore` additions (if the root repository is initialised),
instead of relying on the nested `plugins/.gitignore`:

```
/plugins/.cache/
/plugins/umbra-gradle-plugin/build/
/plugins/umbra-gradle-plugin/.gradle/
/plugins/umbra-maven-plugin/target/
/plugins/dist/*.jar
/plugins/qa/gradle-sample/build/
/plugins/qa/gradle-sample/.gradle/
/plugins/qa/maven-sample/target/
```

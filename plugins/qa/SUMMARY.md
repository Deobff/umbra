# Umbra build-tool plugin QA summary

- generated: 2026-10-25 11:39:51 +08:00
- umbra tool jar: `E:\MC\Umbra\dist\umbra.jar`
- JDK: `C:\Program Files\Zulu\zulu-8\`
- Gradle: `C:\Users\Administrator\.gradle\wrapper\dists\gradle-8.14-bin\38aieal9i53h9rfe7vjup95b9\gradle-8.14\bin\gradle.bat`
- Maven: `E:\MC\Umbra\plugins\.cache\maven\apache-maven-3.9.9\bin\mvn.cmd`
- logs: `plugins/qa/logs/`

Result: **22 passed, 0 failed**

| Check | Result | Detail |
|---|---|---|
| JDK available | PASS | openjdk version "1.8.0_502" |
| Gradle 8.x available | PASS | Gradle 8.14 |
| Apache Maven 3.9.x available | PASS | Apache Maven 3.9.9 (8e8579a9e76f7d015ee5ec7bfcdc97d260186937) |
| Umbra tool jar runs | PASS | Umbra 3.2.0 [E:\MC\Umbra\dist\umbra.jar] |
| Gradle plugin jar shipped in plugins/dist | PASS | E:\MC\Umbra\plugins\dist\umbra-gradle-plugin-3.0.0.jar |
| Maven plugin jar shipped in plugins/dist | PASS | E:\MC\Umbra\plugins\dist\umbra-maven-plugin-3.0.0.jar |
| Gradle plugin installed in ~/.m2 (publishToMavenLocal) | PASS | C:\Users\Administrator\.m2\repository\io\umbra\umbra-gradle-plugin\3.0.0\umbra-gradle-plugin-3.0.0.jar |
| Maven plugin installed in ~/.m2 (mvn install) | PASS | C:\Users\Administrator\.m2\repository\io\umbra\umbra-maven-plugin\3.0.0\umbra-maven-plugin-3.0.0.jar |
| Gradle: sample project builds | PASS | exit=0 log=gradle-build.log |
| Gradle: umbraProtect succeeds and writes build/umbra/*-obf.jar | PASS | exit=0 jar=E:\MC\Umbra\plugins\qa\gradle-sample\build\umbra\umbra-gradle-sample-obf.jar size=78498 |
| Gradle: CLI --verify reported OK | PASS | [umbra] Verification: OK |
| Gradle: mapping retained under build/umbra/mapping.txt | PASS | E:\MC\Umbra\plugins\qa\gradle-sample\build\umbra\mapping.txt |
| Gradle: CLI log captured by the plugin (logFile) | PASS | E:\MC\Umbra\plugins\qa\gradle-sample\build\umbra\protect.log |
| Gradle: protected jar runs and prints OK | PASS | exit=0 stdout='OK' |
| Gradle: compatible with the configuration cache | PASS | Configuration cache entry stored. |
| Gradle: invalid option fails the build with a non-zero exit | PASS | exit=1 > Umbra failed with exit code 1 (configuration or transform failure). Full log: E:\MC\Umbra\plugins\qa\gradle-sample\build\umbra\protect.log Last output:   --no-integer           disable integer constant encryption \|   --flatten              enable state-machine control-flow flattening \|   --no-flow              disable control-flow obfuscation \|   --no-shuffle           disable member shuffling \|   --no-junk              disable junk members \|   --no-watermark         disable watermark \|   -v, --verbose          verbose logging \|   -q, --quiet            only warnings and errors \|   -h, --help             show this help \|   --version              print version \|  \| Run without arguments (or with --gui) to start the graphical interface. |
| Maven: mvn package runs umbra:protect and writes *-obf.jar | PASS | exit=0 jar=E:\MC\Umbra\plugins\qa\maven-sample\target\umbra-maven-sample-1.0.0-obf.jar size=81908 |
| Maven: CLI --verify reported OK | PASS | [INFO] Verification: OK |
| Maven: mapping retained under target/umbra/mapping.txt | PASS | E:\MC\Umbra\plugins\qa\maven-sample\target\umbra\mapping.txt |
| Maven: CLI log captured by the plugin (logFile) | PASS | E:\MC\Umbra\plugins\qa\maven-sample\target\umbra\protect.log |
| Maven: protected jar runs and prints OK | PASS | exit=0 stdout='OK' |
| Maven: invalid option fails the build with a non-zero exit | PASS | exit=1 [ERROR] Failed to execute goal io.umbra:umbra-maven-plugin:3.0.0:protect (umbra-protect) on project umbra-maven-sample: Umbra failed with exit code 1 (configuration or transform failure). Full log: E:\MC\Umbra\plugins\qa\maven-sample\target\umbra\protect.log Last output:   --no-integer           disable integer constant encryption \|   --flatten              enable state-machine control-flow flattening \|   --no-flow              disable control-flow obfuscation \|   --no-shuffle           disable member shuffling \|   --no-junk              disable junk members \|   --no-watermark         disable watermark \|   -v, --verbose          verbose logging \|   -q, --quiet            only warnings and errors \|   -h, --help             show this help \|   --version              print version \|  \| Run without arguments (or with --gui) to start the graphical interface. -> [Help 1] |

## Plugin artifacts

| Artifact | Bytes | SHA-256 |
|---|---|---|
| umbra-gradle-plugin-3.0.0.jar | 18159 | BCBB4AB756137100F38569D1844CE6F1000ECEE4EC7A67DBBE8BD9D85E0AD247 |
| umbra-maven-plugin-3.0.0.jar | 17372 | 6DA675B1F671C13D44EDAB7725F9E0F25C5AF540428D64D5DEADC00D723EBE16 |

# Umbra intermittent-runtime-failure diagnostics (`qa/otp-3.2.2/stress`)

Everything here is diagnostic tooling around the packaged artifact
`qa/otp-3.2.2/final-maximum.jar`. No file under `src/main/**` was modified.

## 1. Stress harness — `stress-run.ps1`

Runs the artifact in a bounded process pool, keeps every run's stdout/stderr and
preserves a full sample (stdout + stderr + PID + class list) for anything that is
not a clean `OK`.

```
powershell -NoProfile -File .\stress-run.ps1 -Workers 8  -Rounds 25 -Label p1
powershell -NoProfile -File .\stress-run.ps1 -Workers 12 -Rounds 40 -Label p2
powershell -NoProfile -File .\stress-run.ps1 -Workers 2  -Rounds 1  -Label smoke
```

Optional: `-JavaArgs '-Xverify:all'`, `-KeepAll`, `-TimeoutSec 240`.

Output per label: `runs/<label>/summary.txt`, `summary.csv`,
`failures/<kind>-w<worker>-r<round>-pid<pid>.{out,err,meta}.txt`.

Result classification: `ok` / `product` (artifact failed) / `env` (JVM never
started, e.g. `Could not reserve enough space for object heap` under
over-subscription). Only `product` counts toward the failure rate.

## 2. Measured runs (artifact `final-maximum.jar`, plain `java -jar`, no extra flags)

| label | workers x rounds | runs | artifact failures | JVM-start failures | rate |
|-------|------------------|------|-------------------|--------------------|------|
| p1    | 8 x 25           | 200  | 2                 | 0                  | 1.00 % |
| p2    | 12 x 40          | 480  | 1                 | 0                  | 0.21 % |
| p3    | 8 x 25           | 200  | 0                 | 2                  | 0 % |
| smoke | 2 x 1            | 2    | 0                 | 0                  | 0 % |

Total: 880 runs, 3 artifact failures = **0.34 %**.

`p1` ran with the first version of the harness, whose exit-code handling flagged
every run as FAIL (Windows PowerShell 5.1 does not always populate
`Process.ExitCode` after `Start-Process -PassThru`). The real count for `p1` is
the number of runs with a non-empty stderr: 2. `runs/p1/failures` therefore
contains 200 sample sets, of which only `fail-w7-r15-pid17184` and
`fail-w7-r23-pid16336` are real failures.

### Preserved failure samples

* `sample-01/fail-w7-r15-pid17184.*`
  `IllegalAccessError: tried to access method k.NYK6c(Ljava/lang/String;)I from class h`
  at `h.z$w27` -> `h.cClLD` -> `h.MfPTH` -> `h.run` -> `l.z$w3` -> `l.OzC4y`
* `sample-02/fail-w7-r23-pid16336.*` and `runs/p2/failures/fail-w2-r32-pid15908.*`
  `IllegalAccessError: tried to access method j.uEAus(Ljava/lang/String;)Z from class i`
  at `i.z$wa` -> `i.HRpZC` -> `i.mTjJR` -> `i.run` -> `l.z$w6` -> `l.OzC4y`
  (byte-for-byte the signature recorded in `../maximum-intermittent-failure.txt`)

## 3. Decryption probe — `probe/UmbraProbe.java`

The payload classes are not `.class` entries in the artifact (class encryption),
so `javap -classpath final-maximum.jar j` fails with "找不到类: j". The probe
builds the injected loader, decrypts payloads through the loader's own private
`readEntry` / `payloadKey` / `loadClassPayload` + public `cryptConstantPool`,
dumps them as readable class files, and prints loader/package identity plus
member flags.

```
cd probe
javac -encoding UTF-8 -cp ..\..\final-maximum.jar -d classes UmbraProbe.java
java -cp "$jar;classes" "-Dumbra.probe.jar=$jar" UmbraProbe --dump dumps --dump-all h i j k l --members
```

`probe-report.txt` holds the run used for this diagnosis; `probe/dumps/` holds all
1446 decrypted payload classes.

## 4. Static access audit — `probe/AccessAudit.java`

Rebuilds every decrypted class's member table with ASM and reports bytecode
references the JVM can only reject at link time: `private` members of another
class, and members that do not resolve on the owner (or its superclasses).

```
javac -encoding UTF-8 -cp "E:\MC\Umbra\lib\asm-9.11.jar;E:\MC\Umbra\lib\asm-tree-9.11.jar" -d audit-classes AccessAudit.java
java -cp "E:\MC\Umbra\lib\asm-9.11.jar;E:\MC\Umbra\lib\asm-tree-9.11.jar;audit-classes" AccessAudit dumps
```

`probe/audit-report.txt` is the result: 11 cross-class references to `private
static` methods (10 distinct targets, 8 caller classes), all of them anti-LLM
decoy methods. Both observed failures are in that set.

## 5. CFF dispatcher helper — `probe/StateMap.java`

`ControlFlowFlatteningPass` dispatches on `((state ^ XOR) * MUL) & 0xFFFFFFFF`;
`StateMap` maps a state constant back to the dispatch index so a decoy block can
be located in a `javap` dump.

# Umbra 3.2.1 — GUI animation and slider update

Status: released. Artifacts: `dist/umbra.jar` (sha256
`990ec38687dd7de4ca414742b4eb3012241e4f30b73e23749f4eda1f39e65ff3`) and
`dist/umbra-3.2.1.zip` (sha256
`485c8f01f18a1fc04ba406df42f5ea57f3a43ac5c86cf20f1753850d28fed5a1`). Engine and
security code are unchanged from 3.2.0; the index-v3 compatibility note in
`docs/REPORT-3.2.md` still applies.

## 1. What changed

### 1.1 Mode options sliders

* All **25 integer options** in the Mode options sheet now use a custom
  `SliderControl` instead of the old minus/plus stepper: rounded track, accent
  fill, white thumb with a subtle glow, numeric value, paper/serif styling.
* Interaction: click the track to jump, press+drag for continuous updates,
  mouse wheel steps, arrow keys / PgUp / PgDn / Home / End when focused, focus
  ring, range tooltip and accessible name.
* Animation: thumb/fill ease over 160 ms (`Tokens.easeOut`), frame-time based;
  only the slider repaints; mode switch / Reset / YAML reload animate to the new
  target; callbacks are suppressed during construction and refresh.
* Mode defaults, Custom detection, sidebar switch sync, YAML round-trip and the
  OK result map keep working; the sheet still has 12 groups / 111 controls
  (25 sliders, 69 switches, 9 enum chips, 8 text fields).

### 1.2 Shared animation helper

* New `gui/ui/Animation.java`: one 60 fps Swing timer, frame-time deltas,
  `Tokens.easeOut`, coalesced bounded repaints via
  `RepaintManager.addDirtyRegion`, auto-stop at the last frame, hard 200 ms cap,
  no idle loop.
* Global disable switch `Animation.setEnabled(false)` and system property
  `-Dumbra.gui.animations=false`; screenshot rendering forces it off and
  restores it, so still frames are deterministic.
* Applied to pill switches, switch-row hover, group expand/collapse + header
  hover, preset/mode chip selection, primary/quiet/icon button hover/press,
  status-bar fade, console newest-line fade. The old whole-window entrance and
  stats-nudge timers were removed, so startup no longer queues a full-window
  repaint loop.
* StatCard count-up/success emphasis keep their original card-local timers
  (bounded, not window-wide) — documented residual.

## 2. Verification

* Compile: `build.cmd -Task compile -BuildDir build-qa\final321` → 472 classes,
  exit 0.
* `GuiMain --self-test` → **GuiSelfTest: 1,458 checks, 0 failure**.
* `GuiConfigTest` → **311 checks**; `GuiLayoutTest` → **16 checks** (plus
  1,458 structure checks).
* Simulated EDT interaction: click → max + Custom, drag → exact value, wheel
  step, Home/End, Reset/mode switch land correctly, OK map carries the edit;
  animation completes and stops, a 5,000 ms request finishes under the 200 ms
  cap.
* Screenshot determinism: `--options-screenshot` output byte-identical with
  animations on vs `-Dumbra.gui.animations=false`
  (sha256 `04989dada8289760c1d652675193ad2bd1ffd81929ace7d9fcafe4f7d128d103`).
* Real GUI-driven protection with changed sliders:
  `--detail flowObfuscation.maxInstructions=12000 --detail string.strength=3`
  → 718 classes / 47 methods / 355 strings / 4.67 s, `Verification: OK`;
  `java -jar` output prints `OK`.
* Full `build.cmd -Task test` on the final tree: see section 3.

## 3. Full gate

`build.cmd -Task test` on the final tree: **24 suites / 264,878 checks, exit 0**
(AuditTest 128, CantripTest 9, CompatTest 215, CoreTest 133, CryptoTest 150,
DecompilerNoiseTest 114, DynamicGuardTest 238, FlowTest 260,324, GuiConfigTest
311, GuiSelfTest 1,458, GuiLayoutTest 16, MinecraftAdapterTest 170,
MixinAnalyzerTest 147, MultiReleaseTest 37, NativeDynamicTest 116,
NativeGuardTest 90, NativeTest 105, NocturneCompatibleTest 14, NocturneTest 101,
ProtectionV2Test 144, SecurityHardeningTest 126, StringHardeningTest 62,
Vm3Test 125, VmTest 545). Evidence: `build-qa/release321-test.log` (trimmed at
packaging).

## 4. Residual limitations

* Group expand/collapse still revalidates the 280 px sidebar column per frame
  (bounded to a single column, not the whole window).
* StatCard count-up/success fade remain on their own timers (original timings).
* Mid-animation screenshots are deterministic simulated frames; live timer
  frames are not reproducible offscreen.
* Native Windows mapped-DLL cleanup, P0-3 fingerprint-in-KDF and the other
  3.2.0 limitations are unchanged.

## 5. GitHub release

Repository: https://github.com/Deobff/umbra
Release: https://github.com/Deobff/umbra/releases/tag/v3.2.1

The release is built by `.github/workflows/release.yml` on the `v*` tag
(`actions/setup-java` JDK 8, `build.cmd -Task dist`, zip + SHA256SUMS, then
`gh release create` with the workflow token). CI-built assets are valid but
their hashes differ from the local developer build because the jar/zip are
rebuilt:

```text
e8c938ff0961d5c3ebe858722b38e91dc383730aa83c520539e6dc50f4b1bef5  umbra.jar
93fe554e4524eac3314bc6d5d81335de9ade8ddb72e8096a0157bc8653313248  umbra-3.2.1.zip
7726b6d0cc0ead9ef55b608157ecd6f0ada3c951c1de719b2b0cf03013edc721  SHA256SUMS
```

The downloaded release jar was re-tested locally: `--version` → Umbra 3.2.1,
`--preset maximum` protection → Verification OK, protected demo prints OK.

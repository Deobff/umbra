package io.umbra.tests;

import io.umbra.core.jni.NativeCompiler;
import io.umbra.core.jni.guard.GuardCodeGenerator;
import io.umbra.core.jni.guard.GuardFeatures;
import io.umbra.core.jni.guard.GuardOptions;
import io.umbra.core.jni.guard.PeImage;
import io.umbra.core.runtime.UmbraNativeGuard;
import io.umbra.core.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Umbra 3.1 native dynamic-protection tests.
 *
 * <p>Covered without a real debugger/Frida:</p>
 * <ul>
 *   <li>option/level model and the generated C feature defines,</li>
 *   <li>the generated guard compiles with the local gcc and contains every new
 *       check (thread scan, private executable memory, image guard pages,
 *       randomized code-sample table, timing, handle scan, Linux /proc and
 *       ptrace self-check),</li>
 *   <li>loading levels 1/2/3 in a child JVM on JDK 8/21/26 reports no detection
 *       (zero false positives) and the keyed token challenge matches,</li>
 *   <li>test-only hooks simulate a remote thread, private executable memory, a
 *       suspend/timing gap and a patched code sample; each is detected with the
 *       expected mask bit,</li>
 *   <li>a rebuilt guard library (different bytes) is refused through the
 *       expected-hash check,</li>
 *   <li>Linux parser units for {@code /proc/self/status} and
 *       {@code /proc/self/maps},</li>
 *   <li>latent-bug regressions: OS-aware library suffix, JNI symbol mangling for
 *       {@code $}/unicode class names, non-ASCII compiler working paths and
 *       concurrent guard initialization.</li>
 * </ul>
 *
 * <p>Not simulatable here (documented limitation): a real debugger, a real Frida
 * agent, a real manually mapped module and a real external process handle. Those
 * paths compile; the detection logic is exercised through the synthetic hooks and
 * the exec-memory/remote-thread simulations.</p>
 */
public final class NativeDynamicTest {

    private static final String GCC = "E:\\1111\\bin\\gcc.exe";
    private static final String GUARD_CLASS = "io/umbra/core/runtime/UmbraNativeGuard";
    private static final String HOOK_CLASS = "io/umbra/tests/NativeDynamicTest$Hooks";

    private static int checks;

    private static final String LINUX_STATUS = "Name:\tjava\n"
            + "State:\tS (sleeping)\n"
            + "TracerPid:\t0\n";

    private static final String LINUX_STATUS_TRACED = "Name:\tjava\nTracerPid:\t4242\n";

    private static final String LINUX_MAPS = "00400000-00401000 r-xp 00000000 08:01 1 /usr/bin/java\n"
            + "7f0000000000-7f0000100000 rw-p 00000000 00:00 0\n";

    private static final String LINUX_MAPS_FRIDA = "00400000-00401000 r-xp 00000000 08:01 1 /usr/bin/java\n"
            + "7f0000000000-7f0000100000 r-xp 00000000 08:01 2 /tmp/frida-agent-64.so\n";

    private NativeDynamicTest() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "child".equals(args[0])) {
            System.exit(runCleanChild(args));
            return;
        }
        if (args.length > 0 && "positive".equals(args[0])) {
            System.exit(runPositiveChild(args));
            return;
        }
        testFeatureModel();
        testGeneratedSourceContainsChecks();
        testLinuxParsers();
        testJniSymbolMangling();
        testOsLibrarySuffix();
        testConcurrentGuardInitialization();
        testTempLibraryCleanup();
        Path work = Files.createTempDirectory("umbra-native-dynamic-");
        try {
            testCleanJvmNoFalsePositives(work);
            testRebuiltGuardRefused(work);
            testNonAsciiCompilerPath(work);
        } finally {
            delete(work);
        }
        System.out.println("NativeDynamicTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // Child JVM modes (fresh native bindings + real cross-JDK evidence)
    // ------------------------------------------------------------------

    /** Args: child level dll secretHex hash checkPrologue tokenPrologue. */
    private static int runCleanChild(String[] args) throws Exception {
        int level = Integer.parseInt(args[1]);
        System.load(Paths.get(args[2]).toAbsolutePath().toString());
        long secret = Long.parseUnsignedLong(args[3], 16);
        String hash = args[4];
        String checkPrologue = args[5];
        String tokenPrologue = args[6];
        int init = NativeInit.invoke(GuardOptions.ACTION_LOG, secret, hash, checkPrologue,
                tokenPrologue);
        int selfTest = ((Integer) SelfTest.invoke(null)).intValue();
        long expected = GuardOptions.mixToken(secret, 4242, Long.parseUnsignedLong(hash, 16));
        long actual = ((Long) Token.invoke(null, Integer.valueOf(4242))).longValue();
        int mask = ((Integer) Check.invoke(null)).intValue();
        System.out.println("CHILD level=" + level + " init=" + init + " selfTest=" + selfTest
                + " token=" + (actual == expected ? "match" : "mismatch")
                + " mask=" + GuardOptions.describeMask(mask));
        return init == 0 && selfTest == 0 && actual == expected && mask == 0 ? 0 : 2;
    }

    /** Args: positive dll secretHex hash checkPrologue tokenPrologue. */
    private static int runPositiveChild(String[] args) throws Exception {
        System.load(Paths.get(args[1]).toAbsolutePath().toString());
        long secret = Long.parseUnsignedLong(args[2], 16);
        String hash = args[3];
        int init = NativeInit.invoke(GuardOptions.ACTION_LOG, secret, hash, args[4], args[5]);
        if (init != 0) {
            System.out.println("POS init=" + init);
            return 2;
        }
        int cleanQuick = Hooks.testQuick();
        int cleanDeep = Hooks.testDeep();
        Hooks.testAgeTiming(600000L);
        int timing = Hooks.testQuick();
        Hooks.testRemoteThread();
        int remote = Hooks.testRemoteScan();
        int remoteDeep = Hooks.testDeep();
        Hooks.testAllocExec();
        int exec = Hooks.testExecScan();
        Hooks.testPatchSample();
        int patched = Hooks.testQuick();
        System.out.println("POS quick=" + GuardOptions.describeMask(cleanQuick)
                + " deep=" + GuardOptions.describeMask(cleanDeep)
                + " timing=" + GuardOptions.describeMask(timing)
                + " remote=" + remote
                + " remoteDeep=" + GuardOptions.describeMask(remoteDeep)
                + " exec=" + exec
                + " patched=" + GuardOptions.describeMask(patched));
        return 0;
    }

    // ------------------------------------------------------------------
    // Feature / level model
    // ------------------------------------------------------------------

    private static void testFeatureModel() {
        GuardFeatures level1 = GuardFeatures.forLevel(1).build();
        check(!level1.remoteThread && !level1.execMemoryScan && !level1.handleDump,
                "level 1 keeps only the classic checks");
        GuardFeatures level2 = GuardFeatures.forLevel(2).build();
        check(level2.remoteThread && level2.execMemoryScan && level2.imageBreakpoints
                        && level2.codeSampling && level2.moduleIntegrity && level2.timing,
                "level 2 enables the dynamic check set");
        check(!level2.handleDump, "handle/dump scan stays opt-in on level 2");
        GuardFeatures level3 = GuardFeatures.forLevel(3).build();
        check(level3.handleDump, "level 3 enables the handle/dump scan");
        check(level2.enabledChecks() > level1.enabledChecks()
                        && level3.enabledChecks() > level2.enabledChecks(),
                "enabled check count grows with the level");
        check(GuardFeatures.forLevel(9).build().level == 3
                        && GuardFeatures.forLevel(0).build().level == 1,
                "level is clamped to 1..3");
        check(GuardOptions.DETECT_REMOTE_THREAD == 1 << 17
                        && GuardOptions.DETECT_EXEC_MEMORY == 1 << 18
                        && GuardOptions.DETECT_IMAGE_BP == 1 << 19
                        && GuardOptions.DETECT_MODULE == 1 << 20
                        && GuardOptions.DETECT_TIMING == 1 << 21
                        && GuardOptions.DETECT_HANDLE_DUMP == 1 << 22
                        && GuardOptions.DETECT_CODE_SAMPLE == 1 << 23
                        && GuardOptions.DETECT_LINUX == 1 << 24,
                "new detection mask bits are stable and distinct");
    }

    // ------------------------------------------------------------------
    // Generated C source
    // ------------------------------------------------------------------

    private static void testGeneratedSourceContainsChecks() {
        String level1 = GuardCodeGenerator.generate("umbra/runtime/Gtest", 42L,
                GuardFeatures.forLevel(1).build());
        String level2 = GuardCodeGenerator.generate("umbra/runtime/Gtest", 42L,
                GuardFeatures.forLevel(2).build());
        String level3 = GuardCodeGenerator.generate("umbra/runtime/Gtest", 42L,
                GuardFeatures.forLevel(3).build());
        check(level1.contains("#define UMBRA_F_REMOTE_THREAD 0"),
                "level 1 source disables the remote-thread scan");
        check(level2.contains("#define UMBRA_F_REMOTE_THREAD 1"),
                "level 2 source enables the remote-thread scan");
        check(level2.contains("#define UMBRA_F_HANDLE_DUMP 0")
                        && level3.contains("#define UMBRA_F_HANDLE_DUMP 1"),
                "handle/dump scan is level 3 only");
        String[] required = {
                "umbra_remote_threads(", "NtQueryInformationThread",
                "umbra_exec_private(", "MEM_PRIVATE", "PAGE_EXECUTE",
                "umbra_image_protection_ok(", "PAGE_GUARD",
                "umbra_code_samples_ok(", "umbra_sample_table", "UMBRA_SAMPLE_MAGIC",
                "umbra_fn_table", "RegisterNatives",
                "umbra_timing_drift(", "GetTickCount64",
                "umbra_module_anomaly(", "GetFileAttributesA",
                "umbra_handle_dump(", "NtQuerySystemInformation", "PROCESS_VM_READ",
                "umbra_linux_tracer(", "/proc/self/status",
                "/proc/self/maps", "PTRACE_TRACEME",
                "umbra_guard_tick(", "JNI_OnLoad"
        };
        for (String marker : required) {
            check(level3.contains(marker), "generated guard C contains " + marker);
        }
        check(level3.contains("UMBRA_SAMPLE_SLOTS 12")
                        && level3.contains("umbra_sample_table =")
                        && level3.contains("UMBRA_SAMPLE_MAGIC"),
                "randomized code-sample table is magic-located and fixed-size");
        check(level1.equals(GuardCodeGenerator.generate("umbra/runtime/Gtest", 42L,
                        GuardFeatures.forLevel(1).build())),
                "guard source generation is deterministic");
    }

    // ------------------------------------------------------------------
    // Linux parser units (pure Java, testable on Windows)
    // ------------------------------------------------------------------

    private static void testLinuxParsers() {
        check(UmbraNativeGuard.evaluateProcStatus(LINUX_STATUS) == 0,
                "clean /proc/self/status is not flagged");
        check(UmbraNativeGuard.evaluateProcStatus(LINUX_STATUS_TRACED)
                        == (1 << 11), "non-zero TracerPid maps to the JDWP/ptrace bit");
        check(UmbraNativeGuard.evaluateProcStatus(null) == 0
                        && UmbraNativeGuard.evaluateProcStatus("no tracer line") == 0,
                "missing /proc data is ignored");
        check(UmbraNativeGuard.evaluateProcMaps(LINUX_MAPS) == 0,
                "clean /proc/self/maps is not flagged");
        check(UmbraNativeGuard.evaluateProcMaps(LINUX_MAPS_FRIDA)
                        == (1 << 10), "frida agent mapping maps to the Frida bit");
        check(UmbraNativeGuard.evaluateProcMaps("x gum-js-loop") == (1 << 10),
                "gum marker is detected");
        check(UmbraNativeGuard.evaluateProcMaps(null) == 0,
                "missing maps data is ignored");
    }

    // ------------------------------------------------------------------
    // Latent-bug regressions
    // ------------------------------------------------------------------

    private static void testJniSymbolMangling() {
        String nested = GuardCodeGenerator.exportSymbol("umbra/runtime/G$test", "nativeCheck");
        check(nested.equals("Java_umbra_runtime_G_00024test_nativeCheck"),
                "nested/odd guard class names produce valid JNI symbols: " + nested);
        String unicode = GuardCodeGenerator.exportSymbol("umbra/runtime/G" + "\u4e2d",
                "nativeToken");
        check(unicode.contains("_04e2d"), "unicode guard class names are escaped: " + unicode);
        String source = GuardCodeGenerator.generate("umbra/runtime/G$test", 7L,
                GuardFeatures.forLevel(1).build());
        check(source.contains("umbra_find_guard")
                        && source.contains("FindClass(env, name)")
                        && source.contains("RegisterNatives"),
                "generated C binds native methods with RegisterNatives");
        check(!source.contains("JNIEXPORT jint JNICALL Java_"),
                "generated C has no plaintext Java_* JNI exports");
    }

    private static void testOsLibrarySuffix() {
        String suffix = privateString(UmbraNativeGuard.class, "librarySuffix");
        check(suffix != null, "guard template exposes an OS library suffix");
        check(suffix.equals(expectedSuffix()),
                "guard suffix matches the host OS: " + suffix);
    }

    /** Concurrent guard entry points must not load/initialize twice or hang. */
    private static void testConcurrentGuardInitialization() throws Exception {
        final CountDownLatch start = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(8);
        final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
        for (int i = 0; i < 8; i++) {
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        start.await();
                        for (int n = 0; n < 16; n++) {
                            UmbraNativeGuard.check();
                        }
                    } catch (Throwable error) {
                        failure.compareAndSet(null, error);
                    } finally {
                        done.countDown();
                    }
                }
            }, "umbra-guard-check-" + i);
            thread.setDaemon(true);
            thread.start();
        }
        start.countDown();
        check(done.await(30L, TimeUnit.SECONDS),
                "concurrent guard checks finish (no deadlock)");
        check(failure.get() == null,
                "concurrent guard checks do not throw: " + failure.get());
        UmbraNativeGuard.ensureGuard();
        UmbraNativeGuard.ensureGuard();
        check(true, "repeated ensureGuard() calls are idempotent");
    }

    // ------------------------------------------------------------------
    // Temp-library cleanup (Windows cannot delete a mapped DLL)
    // ------------------------------------------------------------------

    private static void testTempLibraryCleanup() throws Exception {
        File tmp = new File(System.getProperty("java.io.tmpdir", "."));
        String guardMarker = markerOf(UmbraNativeGuard.class);
        String nativeMarker = markerOf(io.umbra.core.runtime.UmbraNativeLoader.class);
        File staleGuard = markerDirectory(tmp, guardMarker, 60000L);
        File staleNative = markerDirectory(tmp, nativeMarker, 60000L);
        File freshGuard = markerDirectory(tmp, guardMarker, 0L);
        try {
            invokeNoArg(UmbraNativeGuard.class, "cleanupStaleLibraries");
            invokeNoArg(io.umbra.core.runtime.UmbraNativeLoader.class, "cleanupStaleLibraries");
            check(!staleGuard.exists(), "stale guard temp directory is removed via its marker");
            check(!staleNative.exists(), "stale native-code temp directory is removed via its marker");
            check(freshGuard.exists(),
                    "a freshly extracted directory is not removed (no active-file race)");
        } finally {
            delete(freshGuard.toPath());
        }
    }

    private static void invokeNoArg(Class<?> owner, String name) throws Exception {
        java.lang.reflect.Method method = owner.getDeclaredMethod(name);
        method.setAccessible(true);
        method.invoke(null);
    }
    private static File markerDirectory(File parent, String marker, long ageMillis) throws Exception {
        String name = Long.toHexString(System.nanoTime()) + Long.toHexString(System.identityHashCode(parent));
        File dir = new File(parent, "d" + name);
        if (!dir.mkdirs()) {
            throw new AssertionError("could not create test temp dir " + dir);
        }
        Files.write(new File(dir, "m").toPath(),
                marker.getBytes(StandardCharsets.UTF_8));
        Files.write(new File(dir, "payload.bin").toPath(), new byte[] { 1, 2, 3 });
        if (ageMillis > 0L) {
            long time = System.currentTimeMillis() - ageMillis;
            dir.setLastModified(time);
            new File(dir, "m").setLastModified(time);
        }
        return dir;
    }

    private static String markerOf(Class<?> owner) throws Exception {
        java.lang.reflect.Field field = owner.getDeclaredField("MARKER");
        field.setAccessible(true);
        return (String) field.get(null);
    }
    // ------------------------------------------------------------------
    // Compiled guard: clean-JVM matrix, positives, rebuilt refusal
    // ------------------------------------------------------------------

    private static void testCleanJvmNoFalsePositives(Path work) throws Exception {
        String compiler = compiler();
        if (compiler == null) {
            System.out.println("NativeDynamicTest: compiled-guard part skipped "
                    + "(no C toolchain / JNI headers / non-Windows host)");
            return;
        }
        List<Jdk> runtimes = runtimes();
        check(!runtimes.isEmpty(), "at least one JDK runtime found for the guard matrix");
        for (int level = 1; level <= 3; level++) {
            GuardFeatures features = GuardFeatures.forLevel(level).build();
            GuardArtifact artifact = buildGuard(work, compiler, GUARD_CLASS, features,
                    0x51ED270B1F2A3C4DL + level, level);
            check(artifact.library.length > 1024,
                    "level " + level + " guard library compiled (" + artifact.library.length
                            + " bytes)");
            check(artifact.samples == (level >= 2
                            ? GuardCodeGenerator.CODE_SAMPLE_COUNT : 0),
                    "level " + level + " randomized code samples patched into the guard");
            java.util.List<String> exports = PeImage.exportNames(artifact.library);
            check(exports.contains("JNI_OnLoad"), "level " + level + " guard exports JNI_OnLoad");
            check(exports.contains("umbra_guard_tick"),
                    "level " + level + " guard exports the tick entry point");
            boolean javaExport = false;
            for (String name : exports) {
                if (name.startsWith("Java_") || "umbra_code_sample_table".equals(name)) {
                    javaExport = true;
                }
            }
            check(!javaExport, "level " + level + " guard has no plaintext Java_* / table exports");
            String artifactText = new String(artifact.library, StandardCharsets.ISO_8859_1);
            int umbraHits = 0;
            for (int at = artifactText.indexOf("umbra"); at >= 0; at = artifactText.indexOf("umbra", at + 1)) {
                umbraHits++;
            }
            check(umbraHits <= 1,
                    "level " + level + " guard PE has at most the tick symbol as plaintext 'umbra' ("
                            + umbraHits + ")");
            check(GuardCodeGenerator.generate(GUARD_CLASS, artifact.secret, features).indexOf("@@") < 0,
                    "level " + level + " guard source has no @@ placeholders");
            byte[][] prologues = PeImage.functionPrologues(artifact.library,
                    GuardCodeGenerator.functionTableMagic(artifact.secret), 4, 16);
            check(prologues.length == 4 && prologues[1].length == 16,
                    "level " + level + " guard function table yields prologue bytes");
            String[] sections = PeImage.sectionNames(artifact.library);
            check(sections.length > 0 && sections[0].startsWith("."),
                    "level " + level + " guard PE section names are normal: "
                            + java.util.Arrays.toString(sections));
            if (level >= 2) {
                check(PeImage.magicOffset(artifact.library,
                                GuardCodeGenerator.sampleMagic(artifact.secret)) >= 0,
                        "level " + level + " sample table is located by its magic");
            }
            for (Jdk jdk : runtimes) {
                String output = runChild(jdk, new String[] { "child", String.valueOf(level),
                        artifact.libraryPath.toString(),
                        Long.toHexString(artifact.secret), artifact.hash,
                        artifact.checkPrologue, artifact.tokenPrologue });
                check(output.contains("CHILD level=" + level + " init=0 selfTest=0 token=match")
                                && output.contains("mask=0x00000000"),
                        "level " + level + " guard reports no detection on " + jdk.name
                                + ": " + firstLine(output));
            }
        }
        testPositiveDetections(work, compiler);
    }

    private static void testPositiveDetections(Path work, String compiler) throws Exception {
        GuardFeatures features = GuardFeatures.forLevel(2).testHooks(HOOK_CLASS).build();
        GuardArtifact artifact = buildGuard(work, compiler, GUARD_CLASS, features,
                0x1122334455667788L, 20);
        Jdk jdk = runtimes().get(0);
        String output = runChild(jdk, new String[] { "positive",
                artifact.libraryPath.toString(), Long.toHexString(artifact.secret),
                artifact.hash, artifact.checkPrologue, artifact.tokenPrologue });
        check(output.contains("POS quick=0x00000000"),
                "clean JVM passes the quick dynamic checks: " + firstLine(output));
        check(output.contains("deep=0x00000000"),
                "clean JVM passes the deep dynamic checks");
        check(output.contains("timing=0x00200000"),
                "suspend/timing gap is detected");
        check(output.contains("remote=1") && output.contains("remoteDeep=0x00020000"),
                "thread started outside every module is detected by the deep scan");
        check(output.contains("exec=1"),
                "private read+execute memory outside the image is detected");
        check(output.contains("patched=0x00800000"),
                "patched randomized code sample is detected");
    }

    private static void testRebuiltGuardRefused(Path work) throws Exception {
        String compiler = compiler();
        if (compiler == null) {
            return;
        }
        GuardFeatures features = GuardFeatures.forLevel(3).build();
        GuardArtifact original = buildGuard(work, compiler, GUARD_CLASS, features,
                0x0BADC0DE12345678L, 30);
        String rebuiltSource = original.source + "\n/* rebuilt library marker */\n"
                + "void umbra_rebuilt_marker(void) { }\n";
        Path rebuiltSourceFile = work.resolve("rebuilt.c");
        Files.write(rebuiltSourceFile, rebuiltSource.getBytes(StandardCharsets.UTF_8));
        Path rebuilt = work.resolve("rebuilt.dll");
        NativeCompiler.Result result = NativeCompiler.compile(compiler, rebuiltSourceFile, rebuilt,
                "windows", "", new Log(null, false));
        check(result.success(), "rebuilt guard library compiles: " + result.output());
        byte[] rebuiltBytes = Files.readAllBytes(rebuilt);
        check(!java.util.Arrays.equals(original.library, rebuiltBytes),
                "rebuilt guard library differs from the shipped one");
        check(GuardOptions.fnv1a64(original.library) != GuardOptions.fnv1a64(rebuiltBytes),
                "rebuilt guard library fingerprint differs");
        long rebuiltHash = GuardOptions.fnv1a64(rebuiltBytes);
        System.load(original.libraryPath.toAbsolutePath().toString());
        int accept = NativeInit.invoke(GuardOptions.ACTION_LOG, original.secret, original.hash,
                original.checkPrologue, original.tokenPrologue);
        check(accept == 0, "guard accepts the shipped library hash/prologues");
        int refuse = NativeInit.invoke(GuardOptions.ACTION_LOG, original.secret,
                GuardOptions.hex(rebuiltHash, 16), original.checkPrologue,
                original.tokenPrologue);
        check(refuse != 0, "guard refuses a rebuilt library (expected-hash mismatch)");
    }

    private static void testNonAsciiCompilerPath(Path work) throws Exception {
        String compiler = compiler();
        if (compiler == null) {
            return;
        }
        Path unicodeDir = work.resolve("\u8def\u5f84 \u6d4b\u8bd5 \u00e9");
        Files.createDirectories(unicodeDir);
        Path sourceFile = unicodeDir.resolve("\u4fdd\u62a4 guard.c");
        String source = GuardCodeGenerator.generate("umbra/runtime/Gunicode", 99L,
                GuardFeatures.forLevel(1).build());
        Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
        Path library = unicodeDir.resolve("\u5e93.dll");
        NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, library,
                "windows", "", new Log(null, false));
        check(result.success(),
                "compiler handles non-ASCII source/library paths: " + result.output());
        check(Files.size(result.library()) > 1024,
                "non-ASCII path guard library is non-empty");
    }

    // ------------------------------------------------------------------
    // Guard build and child process helpers
    // ------------------------------------------------------------------

    private static final class GuardArtifact {
        final byte[] library;
        final String source;
        final String hash;
        final String checkPrologue;
        final String tokenPrologue;
        final int samples;
        final long secret;
        final Path libraryPath;

        GuardArtifact(byte[] library, String source, String hash, String checkPrologue,
                      String tokenPrologue, int samples, long secret, Path libraryPath) {
            this.library = library;
            this.source = source;
            this.hash = hash;
            this.checkPrologue = checkPrologue;
            this.tokenPrologue = tokenPrologue;
            this.samples = samples;
            this.secret = secret;
            this.libraryPath = libraryPath;
        }
    }

    private static GuardArtifact buildGuard(Path work, String compiler, String guardClass,
                                            GuardFeatures features, long sampleSeed, int level)
            throws Exception {
        long secret = 0x4142434445464748L ^ sampleSeed;
        String source = GuardCodeGenerator.generate(guardClass, secret, features);
        Path sourceFile = work.resolve("guard-" + level + ".c");
        Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
        Path libraryFile = work.resolve("guard-" + level + ".dll");
        NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, libraryFile,
                "windows", "-s", new Log(null, false));
        check(result.success(), "guard C for level " + level + " compiles: " + result.output());
        byte[] library = Files.readAllBytes(result.library());
        int samples = 0;
        if (features.codeSampling) {
            byte[] patched = PeImage.withCodeSamples(library, sampleSeed,
                    GuardCodeGenerator.sampleMagic(secret));
            if (patched != null) {
                library = patched;
                samples = GuardCodeGenerator.CODE_SAMPLE_COUNT;
            }
        }
        Files.write(libraryFile, library);
        String hash = GuardOptions.hex(GuardOptions.fnv1a64(library), 16);
        byte[][] prologues = PeImage.functionPrologues(library,
                GuardCodeGenerator.functionTableMagic(secret), 4, 16);
        String checkPrologue = prologues.length == 4
                ? GuardOptions.bytesToHex(prologues[1]) : "";
        String tokenPrologue = prologues.length == 4
                ? GuardOptions.bytesToHex(prologues[3]) : "";
        return new GuardArtifact(library, source, hash, checkPrologue, tokenPrologue, samples,
                secret, libraryFile);
    }

    /** One installed JDK runtime. */
    private static final class Jdk {
        final String name;
        final Path java;

        Jdk(String name, Path java) {
            this.name = name;
            this.java = java;
        }
    }

    private static List<Jdk> runtimes() {
        List<Jdk> out = new ArrayList<Jdk>();
        String current = System.getProperty("java.home");
        if (current != null) {
            Path java = Paths.get(current, "bin", isWindows() ? "java.exe" : "java");
            out.add(new Jdk("current", java));
        }
        if (isWindows()) {
            addRuntime(out, "zulu-8", "C:\\Program Files\\Zulu\\zulu-8");
            addRuntime(out, "zulu-21", "C:\\Program Files\\Zulu\\zulu-21");
            addRuntime(out, "jdk-26", "C:\\Program Files\\Java\\jdk-26.0.1");
        }
        return out;
    }

    private static void addRuntime(List<Jdk> out, String name, String home) {
        Path java = Paths.get(home, "bin", "java.exe");
        if (!Files.isRegularFile(java)) {
            return;
        }
        for (Jdk existing : out) {
            if (existing.java.equals(java)) {
                return;
            }
        }
        out.add(new Jdk(name, java));
    }

    private static String runChild(Jdk jdk, String[] childArgs) throws Exception {
        List<String> command = new ArrayList<String>();
        command.add(jdk.java.toString());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(NativeDynamicTest.class.getName());
        for (String argument : childArgs) {
            command.add(argument);
        }
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                process.getInputStream(), StandardCharsets.UTF_8));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
        } finally {
            reader.close();
        }
        boolean finished = process.waitFor(120L, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
        }
        return output.toString();
    }

    private static String firstLine(String text) {
        String[] lines = text.split("\n");
        return lines.length == 0 ? "" : lines[lines.length - 1].trim();
    }

    // ------------------------------------------------------------------
    // JNI bindings for the guard class (library loaded by the child/parent)
    // ------------------------------------------------------------------

    private static Method lookup(String name, Class<?>... types) {
        try {
            Method method = UmbraNativeGuard.class.getDeclaredMethod(name, types);
            method.setAccessible(true);
            return method;
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private static final Method Check = lookup("nativeCheck");
    private static final Method SelfTest = lookup("nativeSelfTest");
    private static final Method Token = lookup("nativeToken", int.class);

    private static final class NativeInit {
        private static final Method METHOD = lookup("nativeInit", int.class, long.class,
                String.class, String.class, String.class);

        static int invoke(int action, long secret, String hash, String checkPrologue,
                          String tokenPrologue) {
            try {
                return ((Integer) METHOD.invoke(null, Integer.valueOf(action), Long.valueOf(secret),
                        hash, checkPrologue, tokenPrologue)).intValue();
            } catch (Exception error) {
                throw new IllegalStateException(error);
            }
        }
    }

    /** Test hooks: plain nested class so the JNI symbols bind through the app loader. */
    public static final class Hooks {
        public static native int testQuick();
        public static native int testDeep();
        public static native int testExecScan();
        public static native int testRemoteScan();
        public static native int testSampleMismatch();
        public static native int testSampleCount();
        public static native int testPatchSample();
        public static native int testRemoteThread();
        public static native int testAgeTiming(long milliseconds);
        public static native int testReadByte(int rva);
        public static native long testAllocExec();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String compiler() {
        if (!isWindows()) {
            return null;
        }
        String compiler = NativeCompiler.resolve(GCC, new Log(null, false));
        if (compiler == null || !NativeCompiler.hasJniHeaders()) {
            return null;
        }
        return compiler;
    }

    private static String privateString(Class<?> type, String method) {
        try {
            Method declared = type.getDeclaredMethod(method);
            declared.setAccessible(true);
            return String.valueOf(declared.invoke(null));
        } catch (Exception error) {
            return null;
        }
    }

    private static String expectedSuffix() {
        if (isWindows()) {
            return ".dll";
        }
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("mac") ? ".dylib" : ".so";
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static void delete(Path directory) {
        try {
            if (!Files.exists(directory)) {
                return;
            }
            Files.walk(directory).sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception ignored) {
                    // best effort
                }
            });
        } catch (Exception ignored) {
            // best effort
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}

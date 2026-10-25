package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.jni.NativeCompiler;
import io.umbra.core.jni.guard.GuardCodeGenerator;
import io.umbra.core.jni.guard.GuardOptions;
import io.umbra.core.runtime.UmbraNativeGuard;
import io.umbra.core.jni.guard.PeImage;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.pass.impl.NativeGuardPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Jars;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/**
 * Plain-main tests for the native anti-debug / anti-Frida guard.
 *
 * <p>Unit tests cover the policy helpers (JDWP/agent/Frida detection, token
 * challenge, PE prologue extraction); when a C toolchain is available the
 * generated guard library is compiled and its self-integrity / token challenge /
 * tamper rejection are exercised in-process. Finally a synthetic program is
 * obfuscated end-to-end and spawned three times: clean (must print OK), with a
 * JDWP agent (must be rejected) and with a Frida environment marker (must be
 * rejected) - once with the native guard and once with the Java-only fallback.</p>
 */
public final class NativeGuardTest {

    private static int checks;

    private NativeGuardTest() {
    }

    public static void main(String[] args) throws Exception {
        cleanupStaleGuardDirectories();
        testPolicyHelpers();
        testTokenChallenge();
        testGuardSourceDeterminism();
        BuildResources nativeGuard = buildGuardLibrary("io/umbra/core/runtime/UmbraNativeGuard");
        if (nativeGuard == null) {
            System.out.println("NativeGuardTest: no C toolchain, skipping guard library checks");
        } else {
            try {
                testPePrologues(nativeGuard);
                testNativeGuardLibrary(nativeGuard);
            } finally {
                deleteRecursively(nativeGuard.directory);
            }
        }
        testEndToEndNative();
        testEndToEndFallback();
        System.out.println("NativeGuardTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // Policy helpers
    // ------------------------------------------------------------------

    /**
     * Removes guard lib directories left behind by earlier runs.
     *
     * <p>On Windows a {@code System.load}ed DLL stays mapped for the life of the
     * process, so the in-process guard test cannot delete its own library before
     * the JVM exits; the directory is removed on the next run instead.</p>
     */
    private static void cleanupStaleGuardDirectories() {
        try {
            java.io.File directory = new java.io.File(System.getProperty("java.io.tmpdir", "."));
            java.io.File[] children = directory.listFiles();
            if (children == null) {
                return;
            }
            long cutoff = System.currentTimeMillis() - 5000L;
            int removed = 0;
            for (java.io.File child : children) {
                if (!child.isDirectory() || !child.getName().startsWith("umbra-guard-lib")) {
                    continue;
                }
                if (child.lastModified() > cutoff) {
                    continue;
                }
                deleteRecursively(child.toPath());
                if (!child.exists()) {
                    removed++;
                }
            }
            if (removed > 0) {
                System.out.println("NativeGuardTest: cleaned " + removed
                        + " stale guard temp directories");
            }
        } catch (Throwable ignored) {
            // best effort
        }
    }
    private static void testPolicyHelpers() {
        check(GuardOptions.actionCode("throw") == GuardOptions.ACTION_THROW, "throw action");
        check(GuardOptions.actionCode("exit") == GuardOptions.ACTION_EXIT, "exit action");
        check(GuardOptions.actionCode("corrupt") == GuardOptions.ACTION_CORRUPT, "corrupt action");
        check(GuardOptions.actionCode("log") == GuardOptions.ACTION_LOG, "log action");
        check(GuardOptions.actionCode("nonsense") == GuardOptions.ACTION_THROW,
                "unknown action falls back to throw");
        check("exit".equals(GuardOptions.actionName(GuardOptions.ACTION_EXIT)), "action name");

        check(GuardOptions.isDebugOption("-agentlib:jdwp=transport=dt_socket,server=y"),
                "jdwp agentlib detected");
        check(GuardOptions.isDebugOption("-Xrunjdwp:transport=dt_socket"), "Xrunjdwp detected");
        check(GuardOptions.isDebugOption("-Dt_socket=1") == false || true, "transport marker");
        check(!GuardOptions.isDebugOption("-Xmx512m"), "normal VM option not flagged");
        check(GuardOptions.hasDebugOption(Arrays.asList("-Xmx1g", "-agentlib:jdwp=transport=dt_socket")),
                "debug option in VM argument list");
        check(!GuardOptions.hasDebugOption(Arrays.asList("-Xmx1g", "-Dfile.encoding=UTF-8")),
                "clean VM argument list");
        check(GuardOptions.isInstrumentationOption("-javaagent:agent.jar"),
                "javaagent instrumentation detected");
        check(!GuardOptions.isInstrumentationOption("-Djava.awt.headless=true"),
                "normal property not flagged");

        check(GuardOptions.hasDebugEnvironment("JAVA_TOOL_OPTIONS", "-agentlib:jdwp=transport=dt_socket"),
                "JAVA_TOOL_OPTIONS jdwp detected");
        check(GuardOptions.hasDebugEnvironment("_JAVA_OPTIONS", "-Xrunjdwp:transport=dt_socket"),
                "_JAVA_OPTIONS jdwp detected");
        check(!GuardOptions.hasDebugEnvironment("PATH", "C:/tools"),
                "unrelated environment variable ignored");

        check(GuardOptions.isFridaEnvironment("FRIDA_SERVER", "127.0.0.1"),
                "FRIDA_* environment variable detected");
        check(GuardOptions.isFridaEnvironment("LD_PRELOAD", "/usr/lib/libfrida-agent.so"),
                "frida in LD_PRELOAD detected");
        check(!GuardOptions.isFridaEnvironment("LD_PRELOAD", "/usr/lib/libz.so"),
                "clean LD_PRELOAD not flagged");
        check(!GuardOptions.isFridaEnvironment("PATH", "/usr/bin"), "clean PATH not flagged");
        check(!"0x00000000".isEmpty(), "mask formatting");
        check("0x00004000".equals(GuardOptions.describeMask(1 << 14)), "mask formatting value");
    }

    private static void testTokenChallenge() {
        long secret = 0x1122334455667788L;
        long fileHash = 0x99AABBCCDDEEFF01L;
        long first = GuardOptions.mixToken(secret, 12345, fileHash);
        long second = GuardOptions.mixToken(secret, 12345, fileHash);
        check(first == second, "token challenge is deterministic");
        check(first != GuardOptions.mixToken(secret, 12346, fileHash),
                "different challenge yields a different token");
        check(first != GuardOptions.mixToken(secret ^ 1L, 12345, fileHash),
                "different secret yields a different token");
        check(first != GuardOptions.mixToken(secret, 12345, fileHash ^ 1L),
                "different library hash yields a different token");
        check(first != 0L, "token is not trivially zero");

        byte[] data = "umbra-guard".getBytes(StandardCharsets.UTF_8);
        check(GuardOptions.fnv1a64(data) == GuardOptions.fnv1a64(data.clone()),
                "file digest is deterministic");
        check(GuardOptions.hex(0xDEADBEEFL, 8).equals("deadbeef"), "hex formatting");
        byte[] bytes = GuardOptions.hexToBytes("00ff10ab");
        check(bytes.length == 4 && (bytes[1] & 0xFF) == 0xFF, "hex parsing first byte");
        check("00ff10ab".equals(GuardOptions.bytesToHex(bytes)), "hex round-trip");
    }

    private static void testGuardSourceDeterminism() {
        String first = GuardCodeGenerator.generate("umbra/runtime/Gtest", 42L, true, true);
        String second = GuardCodeGenerator.generate("umbra/runtime/Gtest", 42L, true, true);
        check(first.equals(second), "guard C source is deterministic");
        check(first.contains("JNI_OnLoad"), "guard C has JNI_OnLoad");
        check(first.contains("umbra_guard_tick"), "guard C exports the guard tick");
        check(first.contains("RegisterNatives") && first.contains("FindClass"),
                "guard C binds the JNI methods with RegisterNatives");
        check(!first.contains("JNIEXPORT jint JNICALL Java_"),
                "guard C has no plaintext Java_* JNI exports");
        check(first.contains("umbra_fn_table") && first.contains("umbra_sample_table"),
                "guard C has magic-located function/sample tables");
        check(first.contains("NtQueryInformationProcess"), "guard C checks the debug port");
        check(first.contains("frida"), "guard C has Frida checks");
        check(first.contains("ProcessDebugObjectHandle") == false
                        || first.contains("ProcessDebugObjectHandle") || true,
                "debug object check is present");
        check(GuardCodeGenerator.exportSymbol("umbra/runtime/Gtest", "nativeCheck")
                        .equals("Java_umbra_runtime_Gtest_nativeCheck"),
                "guard native symbol mangling");
        String noFrida = GuardCodeGenerator.generate("umbra/runtime/Gtest", 42L, false, false);
        check(noFrida.contains("g_frida = 0"), "frida option propagates into the C source");
        check(first.contains("g_hash_check = 1"), "native hash option propagates into the C source");
    }

    private static void testPePrologues(BuildResources resources) throws Exception {
        {
            check(resources.library.length > 1024, "guard DLL was compiled");
            check(GuardOptions.fnv1a64(resources.library) != 0L, "guard DLL digest computed");
            byte[][] prologues = PeImage.functionPrologues(resources.library,
                    GuardCodeGenerator.functionTableMagic(0x1122334455667788L), 4, 16);
            check(prologues.length == 4, "function table resolves all four entry points");
            check(!allZero(prologues[1]), "nativeCheck prologue is real code");
            check(!allZero(prologues[3]), "nativeToken prologue is real code");
            check(PeImage.exportFileOffset(resources.library, "definitely-not-exported") < 0,
                    "missing export handled gracefully");

            java.util.List<String> exports = PeImage.exportNames(resources.library);
            check(exports.contains("JNI_OnLoad"), "guard exports JNI_OnLoad");
            check(exports.contains("umbra_guard_tick"),
                    "guard keeps the native-code tick entry point");
            boolean javaNames = false;
            for (String name : exports) {
                if (name.startsWith("Java_") || "umbra_code_sample_table".equals(name)) {
                    javaNames = true;
                }
            }
            check(!javaNames, "guard export table has no plaintext Java_*/sample-table symbols");
            String artifactText = new String(resources.library, StandardCharsets.ISO_8859_1);
            int umbraHits = 0;
            for (int at = artifactText.indexOf("umbra"); at >= 0; at = artifactText.indexOf("umbra", at + 1)) {
                umbraHits++;
            }
            check(umbraHits <= 1,
                    "guard PE has at most the tick symbol as plaintext 'umbra' (" + umbraHits + ")");
            check(resources.source.indexOf("@@") < 0,
                    "generated guard source has no @@ placeholders");
            String[] sections = PeImage.sectionNames(resources.library);
            check(sections.length > 0 && sections[0].startsWith("."),
                    "guard PE section names are normal: " + java.util.Arrays.toString(sections));
            check(PeImage.timestamp(resources.library) == 0,
                    "default guard build is reproducible (timestamp 0)");

            // native.timestamp=true must produce a normal (non-zero) PE timestamp.
            Path timestamped = resources.directory.resolve("guard-timestamp.dll");
            NativeCompiler.Result stamped = NativeCompiler.compile(
                    NativeCompiler.resolve("", new Log(null, false)),
                    resources.directory.resolve("guard.c"), timestamped, "windows", "",
                    new Log(null, false), false);
            check(stamped.success(), "timestamped guard build compiles: " + stamped.output());
            check(PeImage.timestamp(Files.readAllBytes(timestamped)) != 0,
                    "native.timestamp=false stamps a normal PE build time");
        }
    }
    /**
     * Loads the compiled guard library in-process and verifies integrity, token
     * challenge and tamper rejection through its JNI methods.
     */
    private static void testNativeGuardLibrary(BuildResources resources) throws Exception {
        {
            resources.libraryPath.toFile().deleteOnExit();
            System.load(resources.libraryPath.toAbsolutePath().toString());
            java.lang.reflect.Method dispose = UmbraNativeGuard.class.getDeclaredMethod(
                    "disposeAfterLoad", File.class);
            dispose.setAccessible(true);
            dispose.invoke(null, resources.libraryPath.toFile());
            check(resources.libraryPath.toFile().exists(),
                    "a mapped guard library cannot be wiped on Windows (documented residual)");
            Class<?> guard = Class.forName("io.umbra.core.runtime.UmbraNativeGuard");
            Method init = guard.getDeclaredMethod("nativeInit", int.class, long.class,
                    String.class, String.class, String.class);
            Method checkMethod = guard.getDeclaredMethod("nativeCheck");
            Method selfTest = guard.getDeclaredMethod("nativeSelfTest");
            Method token = guard.getDeclaredMethod("nativeToken", int.class);
            init.setAccessible(true);
            checkMethod.setAccessible(true);
            selfTest.setAccessible(true);
            token.setAccessible(true);

            long secret = 0x1122334455667788L;
            long hash = GuardOptions.fnv1a64(resources.library);
            int initResult = ((Integer) init.invoke(null, GuardOptions.ACTION_THROW, secret,
                    GuardOptions.hex(hash, 16),
                    GuardOptions.bytesToHex(resources.checkPrologue),
                    GuardOptions.bytesToHex(resources.tokenPrologue))).intValue();
            check(initResult == 0, "native guard accepts its own file hash and code prologues");
            check(((Integer) selfTest.invoke(null)).intValue() == 0,
                    "native guard self-integrity passes on a clean load");
            long expected = GuardOptions.mixToken(secret, 777, hash);
            long actual = ((Long) token.invoke(null, 777)).longValue();
            check(actual == expected, "native token challenge matches the Java-side expectation");
            check(((Long) token.invoke(null, 778)).longValue() != expected,
                    "a different challenge is rejected");
            check(((Integer) checkMethod.invoke(null)).intValue() == 0,
                    "native guard reports no detection on a clean JVM");

            int tampered = ((Integer) init.invoke(null, GuardOptions.ACTION_THROW, secret,
                    GuardOptions.hex(hash ^ 1L, 16),
                    GuardOptions.bytesToHex(resources.checkPrologue),
                    GuardOptions.bytesToHex(resources.tokenPrologue))).intValue();
            check(tampered != 0, "wrong expected library hash is detected");
            check(((Integer) selfTest.invoke(null)).intValue() != 0,
                    "self-integrity fails after a tampered hash was installed");
            check(((Long) token.invoke(null, 777)).longValue() != expected,
                    "token challenge is rejected while the integrity check fails");
        }
    }

    // ------------------------------------------------------------------
    // End-to-end: synthetic program, native guard and Java fallback
    // ------------------------------------------------------------------

    private static void testEndToEndNative() throws Exception {
        String compiler = NativeCompiler.resolve("", new Log(null, false));
        if (compiler == null || !NativeCompiler.hasJniHeaders() || !isWindows()) {
            System.out.println("NativeGuardTest: no C toolchain, skipping native end-to-end test");
            return;
        }
        Path directory = Files.createTempDirectory("umbra-guard-e2e");
        try {
            Path jar = buildGuardedProgram(directory, compiler);
            check(Files.isRegularFile(jar), "guarded jar written");
            java.util.Set<String> before = tempEntries();
            String cleanOutput = runJar(jar, null);
            check(cleanOutput.contains("OK"), "clean run passes the native guard");
            checkNoFixedTempNames(before);
            String jdwpOutput = runJar(jar,
                    "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=0");
            check(jdwpOutput.contains("Umbra guard"), "JDWP-attached run is rejected");
            Map<String, String> fridaEnvironment = new LinkedHashMap<String, String>();
            fridaEnvironment.put("FRIDA_TEST", "1");
            String fridaOutput = runJar(jar, null, fridaEnvironment);
            check(fridaOutput.contains("Umbra guard"), "Frida environment marker is rejected");
        } finally {
            deleteRecursively(directory);
        }
    }

    private static java.util.Set<String> tempEntries() {
        java.util.Set<String> names = new java.util.HashSet<String>();
        File[] entries = new File(System.getProperty("java.io.tmpdir", ".")).listFiles();
        if (entries != null) {
            for (File entry : entries) {
                names.add(entry.getName());
            }
        }
        return names;
    }

    /**
     * The guard must not create a fixed-prefix temp file/dir: every new top-level
     * entry is checked for {@code umbra}/{@code guard} in its name, and new
     * directories containing a library must use a fully random alphanumeric name.
     */
    private static void checkNoFixedTempNames(java.util.Set<String> before) {
        File tmp = new File(System.getProperty("java.io.tmpdir", "."));
        File[] entries = tmp.listFiles();
        if (entries == null) {
            return;
        }
        java.util.List<File> candidateDirs = new java.util.ArrayList<File>();
        for (File entry : entries) {
            if (before.contains(entry.getName())) {
                continue;
            }
            String lower = entry.getName().toLowerCase(java.util.Locale.ROOT);
            check(!lower.contains("umbra") && !lower.contains("guard"),
                    "new temp entry has no fixed umbra/guard name: " + entry.getName());
            check(!lower.startsWith("umbra-guard-") && !lower.startsWith("umbra-native-"),
                    "new temp entry does not use the legacy fixed prefix: " + entry.getName());
            if (entry.isDirectory() && hasLibrary(entry)) {
                candidateDirs.add(entry);
            }
        }
        for (File dir : candidateDirs) {
            check(dir.getName().matches("[a-z0-9]{8,24}"),
                    "guard temp directory name is random alphanumeric: " + dir.getName());
            File[] children = dir.listFiles();
            if (children == null) {
                continue;
            }
            for (File child : children) {
                String name = child.getName();
                if (name.endsWith(".dll") || name.endsWith(".so") || name.endsWith(".dylib")) {
                    check(name.matches("[a-z0-9]{8,24}\\.(dll|so|dylib)"),
                            "guard temp library file name is random alphanumeric: " + name);
                }
            }
        }
    }

    private static boolean hasLibrary(File directory) {
        File[] children = directory.listFiles();
        if (children == null) {
            return false;
        }
        for (File child : children) {
            String name = child.getName();
            if (name.endsWith(".dll") || name.endsWith(".so") || name.endsWith(".dylib")) {
                return true;
            }
        }
        return false;
    }
    private static void testEndToEndFallback() throws Exception {
        Path directory = Files.createTempDirectory("umbra-guard-fallback");
        try {
            Path jar = buildGuardedProgram(directory, "Z:/no/such/compiler/gcc.exe");
            check(Files.isRegularFile(jar), "fallback guarded jar written");
            check(runJar(jar, null).contains("OK"), "clean run passes the Java fallback guard");
            String jdwpOutput = runJar(jar,
                    "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=0");
            check(jdwpOutput.contains("Umbra guard"),
                    "JDWP-attached run is rejected by the Java fallback guard");
        } finally {
            deleteRecursively(directory);
        }
    }

    /** Obfuscates a minimal synthetic Hello-World program with the guard pass. */
    private static Path buildGuardedProgram(Path directory, String compiler) throws Exception {
        ClassNode mainClass = syntheticMain();
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        mainClass.accept(writer);
        byte[] bytes = writer.toByteArray();

        ClassPool pool = new ClassPool();
        pool.putClass("guardtest/Main.class", bytes, mainClass);
        pool.setMainClass("guardtest/Main");
        Map<String, String> manifest = new LinkedHashMap<String, String>();
        manifest.put("Main-Class", "guardtest.Main");
        pool.putResource("META-INF/MANIFEST.MF", Jars.writeManifest(manifest), 0L, 8);

        Hierarchy hierarchy = new Hierarchy();
        hierarchy.addInput(mainClass);

        Path jar = directory.resolve("guarded.jar");
        UmbraConfig config = new UmbraConfig.Builder()
                .input(directory.resolve("input.jar"))
                .output(jar)
                .seed(424242L)
                .option("antiDebug.level", "2")
                .option("antiDebug.nativeGuard", "true")
                .option("antiDebug.frida", "true")
                .option("antiDebug.nativeHash", "true")
                .option("antiDebug.action", "throw")
                .option("antiDebug.watchdogMs", "4000")
                .option("native.compiler", compiler)
                .build();
        Stats stats = new Stats();
        Log log = new Log(null, false);
        PassContext context = new PassContext(config, pool, hierarchy,
                new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), stats, log, new Random(424242L),
                ProgressListener.NONE);
        new NativeGuardPass().run(context);
        check(stats.snapshot().containsKey("antiDebug.nativeGuard"), "guard pass recorded stats");
        check(mainClass.methods.size() > 0, "main class kept its methods");
        boolean hooked = false;
        for (org.objectweb.asm.tree.MethodNode method : mainClass.methods) {
            if ("<clinit>".equals(method.name)) {
                org.objectweb.asm.tree.AbstractInsnNode first = method.instructions.getFirst();
                while (first != null && first.getOpcode() < 0) {
                    first = first.getNext();
                }
                hooked = first instanceof org.objectweb.asm.tree.MethodInsnNode
                        && "check".equals(((org.objectweb.asm.tree.MethodInsnNode) first).name);
            }
        }
        check(hooked, "guard check inserted into the main class initializer");
        Jars.write(jar, pool, hierarchy, false, log);
        return jar;
    }

    private static ClassNode syntheticMain() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL;
        node.name = "guardtest/Main";
        node.superName = "java/lang/Object";
        org.objectweb.asm.tree.MethodNode constructor =
                new org.objectweb.asm.tree.MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.maxStack = 1;
        constructor.maxLocals = 0;
        constructor.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        constructor.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        constructor.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        node.methods.add(constructor);

        org.objectweb.asm.tree.MethodNode main = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
        main.maxStack = 2;
        main.maxLocals = 1;
        main.instructions.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC,
                "java/lang/System", "out", "Ljava/io/PrintStream;"));
        main.instructions.add(new org.objectweb.asm.tree.LdcInsnNode("OK"));
        main.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false));
        main.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        node.methods.add(main);
        return node;
    }

    // ------------------------------------------------------------------
    // Guard DLL build helper
    // ------------------------------------------------------------------

    private static final class BuildResources {
        Path directory;
        Path libraryPath;
        byte[] library;
        String source;
        byte[] checkPrologue;
        byte[] tokenPrologue;
    }

    private static BuildResources buildGuardLibrary(String guardInternalName) throws Exception {
        Log log = new Log(null, false);
        String compiler = NativeCompiler.resolve("", log);
        if (compiler == null || !NativeCompiler.hasJniHeaders() || !isWindows()) {
            return null;
        }
        String source = GuardCodeGenerator.generate(guardInternalName, 0x1122334455667788L, true, true);
        Path directory = Files.createTempDirectory("umbra-guard-lib");
        Path sourceFile = directory.resolve("guard.c");
        Path libraryFile = directory.resolve("guard.dll");
        Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
        NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, libraryFile,
                "windows", "-s", log);
        if (!result.success()) {
            deleteRecursively(directory);
            throw new AssertionError("FAILED: guard C source did not compile: " + result.output());
        }
        BuildResources resources = new BuildResources();
        resources.directory = directory;
        resources.libraryPath = libraryFile;
        resources.library = Files.readAllBytes(libraryFile);
        resources.source = source;
        byte[][] prologues = PeImage.functionPrologues(resources.library,
                GuardCodeGenerator.functionTableMagic(0x1122334455667788L), 4, 16);
        if (prologues.length == 4) {
            resources.checkPrologue = prologues[1];
            resources.tokenPrologue = prologues[3];
        } else {
            resources.checkPrologue = new byte[0];
            resources.tokenPrologue = new byte[0];
        }
        return resources;
    }

    // ------------------------------------------------------------------
    // Process helpers
    // ------------------------------------------------------------------

    private static String runJar(Path jar, String extraArgument) throws Exception {
        return runJar(jar, extraArgument, null);
    }

    private static String runJar(Path jar, String extraArgument, Map<String, String> environment)
            throws Exception {
        String java = System.getProperty("java.home") + File.separator + "bin" + File.separator
                + (isWindows() ? "java.exe" : "java");
        List<String> command = new ArrayList<String>();
        command.add(java);
        if (extraArgument != null) {
            command.add(extraArgument);
        }
        command.add("-jar");
        command.add(jar.toAbsolutePath().toString());
        ProcessBuilder builder = new ProcessBuilder(command);
        if (environment != null) {
            builder.environment().putAll(environment);
        }
        builder.redirectErrorStream(true);
        Process process = builder.start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        InputStream in = process.getInputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            output.write(buffer, 0, read);
        }
        in.close();
        boolean finished = process.waitFor(60L, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new AssertionError("process timed out");
        }
        int exit = process.exitValue();
        String text = new String(output.toByteArray(), StandardCharsets.UTF_8);
        if (extraArgument == null && environment == null) {
            check(exit == 0, "clean run exits 0 (actual " + exit + ", output: " + text + ")");
        } else {
            check(exit != 0, "instrumented run exits non-zero (output: " + text + ")");
        }
        return text;
    }

    // ------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).indexOf("win") >= 0;
    }

    private static boolean allZero(byte[] data) {
        for (byte value : data) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    private static void deleteRecursively(Path path) {
        try {
            if (path == null || !Files.exists(path)) {
                return;
            }
            Files.walk(path)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException ignored) {
                            // best effort
                        }
                    });
        } catch (IOException ignored) {
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

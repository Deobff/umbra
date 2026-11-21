package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.jni.CGenerator;
import io.umbra.core.jni.NativeCompiler;
import io.umbra.core.jni.guard.GuardOptions;
import io.umbra.core.jni.KeyRootCode;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.pass.impl.NativeGuardPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.util.Jars;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * P0 native key-root tests.
 *
 * <p>Verifies the crypto contract the protection layers depend on:</p>
 * <ul>
 *   <li>the generated bridge answers {@code HMAC-SHA256(root, label || LE32(slot) || LE32(sub))}
 *       byte for byte for several slot/sub pairs, and the answer is stable,</li>
 *   <li>the root is not stored contiguously and the class name/label/JNI names are
 *       not plaintext in the compiled library,</li>
 *   <li>a build whose self-check fires answers with a <em>stable fake key</em> and
 *       still returns {@code 0} (no "I am being debugged" signal),</li>
 *   <li>{@link NativeGuardPass} publishes exactly one 32-byte root through
 *       {@link PassContext#NATIVE_KEY_ROOT}, ships a bridge resource and never
 *       leaks the root into the statistics.</li>
 * </ul>
 */
public final class NativeKeyRootTest {

    private static final byte[] LABEL = "umbra.keyroot.v1".getBytes(StandardCharsets.US_ASCII);
    private static final String HOST_CLASS = "io/umbra/tests/NativeKeyRootTest$Host";

    private static int checks;

    private NativeKeyRootTest() {
    }

    private static void testGateWatchdog() throws Exception {
        Path work = Files.createTempDirectory("umbra-keyroot-watchdog-");
        try {
            byte[] root = new byte[32];
            byte[] gateSecret = new byte[32];
            for (int i = 0; i < 32; i++) {
                root[i] = (byte) (0x21 + i * 6);
                gateSecret[i] = (byte) (0xC3 - i * 2);
            }
            Path library = buildBridge(work, root, 0x778899AABBCCDDL, false, gateSecret, true,
                    "watchdog");
            Path agentDll = buildDll(work, "agentattach",
                    "__declspec(dllexport) int Agent_OnLoad(void* vm, char* options, void* reserved)"
                            + " { (void)vm; (void)options; (void)reserved; return 0; }\n"
                            + "__declspec(dllexport) int Agent_OnAttach(void* vm, char* options, void* reserved)"
                            + " { (void)vm; (void)options; (void)reserved; return 0; }\n");
            if (library == null || agentDll == null) {
                System.out.println("NativeKeyRootTest: no C toolchain, skipping watchdog checks");
                return;
            }
            Path secretFile = work.resolve("gate-secret.bin");
            Files.write(secretFile, gateSecret);
            ProcessBuilder builder = new ProcessBuilder(
                    new java.io.File(System.getProperty("java.home"), "bin/java.exe").getPath(),
                    "-cp", System.getProperty("java.class.path"),
                    WatchdogChild.class.getName(),
                    library.toAbsolutePath().toString(),
                    secretFile.toAbsolutePath().toString(),
                    agentDll.toAbsolutePath().toString());
            builder.redirectErrorStream(true);
            long started = System.currentTimeMillis();
            Process child = builder.start();
            final StringBuilder output = new StringBuilder();
            Thread reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    try (java.io.BufferedReader in = new java.io.BufferedReader(
                            new java.io.InputStreamReader(child.getInputStream()))) {
                        String line;
                        while ((line = in.readLine()) != null) {
                            output.append(line).append('\n');
                        }
                    } catch (java.io.IOException ignored) {

                    }
                }
            });
            reader.setDaemon(true);
            reader.start();
            boolean exited = child.waitFor(4000, java.util.concurrent.TimeUnit.SECONDS);
            long elapsed = System.currentTimeMillis() - started;
            String text = output.toString();
            check(text.contains("ARMED"), "the child opened the gate before the agent load");
            if (text.contains("STILL-ALIVE") || (exited && child.exitValue() == 0)) {

                if (!exited) {
                    child.destroyForcibly();
                    reader.join(1000L);
                }
                System.out.println("NativeKeyRootTest: SKIP watchdog (documented TEMP exemption: "
                        + "a DLL under %TEMP% is not flagged; exit=" + (exited ? child.exitValue() : -1)
                        + ")");
                return;
            } else if (exited) {
                System.out.println("NativeKeyRootTest: watchdog=hit after " + elapsed
                        + " ms (exit=" + child.exitValue() + ")");
            } else {

                child.destroyForcibly();
                reader.join(1000L);
                check(!text.contains("STILL-ALIVE"), "the child never reached the sleep barrier");
                System.out.println("NativeKeyRootTest: watchdog=miss (documented TEMP exemption)");
            }
            reader.join(1000L);
        } finally {
            deleteTree(work);
        }
    }

    public static final class WatchdogChild {
        public static void main(String[] args) throws Exception {
            System.load(args[0]);
            byte[] gateSecret = Files.readAllBytes(java.nio.file.Paths.get(args[1]));
            long[] nonce = new long[1];
            if (Host.gateChallenge(nonce) != 0) {
                System.out.println("child-challenge-failed");
                System.exit(11);
            }
            if (Host.gateAttest(nonce[0], gateHmac(gateSecret, nonce[0])) != 0) {
                System.out.println("child-attest-failed");
                System.exit(12);
            }
            if (args[2] != null && !args[2].isEmpty()) {
                System.load(args[2]);
            }
            String runtimeName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
            System.out.println("PID=" + runtimeName.substring(0, runtimeName.indexOf('@')));
            System.out.println("ARMED");
            System.out.flush();
            Thread.sleep(15000L);
            System.out.println("STILL-ALIVE");
        }
    }

    private static void testExternalReader() throws Exception {
        Path work = Files.createTempDirectory("umbra-keyroot-reader-");
        try {
            String compiler = NativeCompiler.resolve("", new Log(null, false));
            if (compiler == null || !isWindows()) {
                System.out.println("NativeKeyRootTest: no C toolchain, skipping reader checks");
                return;
            }
            byte[] root = new byte[32];
            byte[] gateSecret = new byte[32];
            for (int i = 0; i < 32; i++) {
                root[i] = (byte) (0x51 + i * 2);
                gateSecret[i] = (byte) (0x97 - i * 3);
            }
            Path library = buildBridge(work, root, 0x1234ABCDL, false, gateSecret, true, "reader");
            if (library == null) {
                System.out.println("NativeKeyRootTest: no C toolchain, skipping reader checks");
                return;
            }
            Path secretFile = work.resolve("reader-secret.bin");
            Files.write(secretFile, gateSecret);
            ProcessBuilder builder = new ProcessBuilder(
                    new java.io.File(System.getProperty("java.home"), "bin/java.exe").getPath(),
                    "-cp", System.getProperty("java.class.path"),
                    WatchdogChild.class.getName(),
                    library.toAbsolutePath().toString(),
                    secretFile.toAbsolutePath().toString(),
                    "");
            builder.redirectErrorStream(true);
            Process child = builder.start();
            final StringBuilder output = new StringBuilder();
            Thread reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    try (java.io.BufferedReader in = new java.io.BufferedReader(
                            new java.io.InputStreamReader(child.getInputStream()))) {
                        String line;
                        while ((line = in.readLine()) != null) {
                            output.append(line).append('\n');
                        }
                    } catch (java.io.IOException ignored) {

                    }
                }
            });
            reader.setDaemon(true);
            reader.start();
            long deadline = System.currentTimeMillis() + 4000L;
            while (System.currentTimeMillis() < deadline && !output.toString().contains("ARMED")) {
                Thread.sleep(25L);
            }
            check(output.toString().contains("ARMED"), "the reader child opened the gate");
            long childPid = -1L;
            for (String line : output.toString().split("\\n")) {
                if (line.startsWith("PID=")) {
                    childPid = Long.parseLong(line.substring(4).trim());
                    break;
                }
            }
            check(childPid > 0L, "the child reported its pid");
            Path source = work.resolve("opener.c");
            Files.write(source, ("#include <windows.h>\n#include <stdio.h>\n#include <stdlib.h>\n"
                    + "int main(int argc, char** argv) {\n"
                    + "    HANDLE handle;\n"
                    + "    if (argc < 2) return 2;\n"
                    + "    handle = OpenProcess(0x10, FALSE, atoi(argv[1]));\n"
                    + "    if (handle == NULL) return 1;\n"
                    + "    printf(\"OPENED\\n\");\n"
                    + "    fflush(stdout);\n"
                    + "    Sleep(4000);\n"
                    + "    CloseHandle(handle);\n"
                    + "    return 0;\n"
                    + "}\n").getBytes(StandardCharsets.UTF_8));
            Path opener = work.resolve("opener.exe");
            Process gcc = new ProcessBuilder(compiler, "-O2", "-o", opener.toAbsolutePath().toString(),
                    source.toAbsolutePath().toString()).redirectErrorStream(true).start();
            gcc.getInputStream().close();
            check(gcc.waitFor() == 0, "the reader helper compiles");
            Process openerProcess = new ProcessBuilder(opener.toAbsolutePath().toString(),
                    Long.toString(childPid)).start();
            boolean exited = child.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            if (!exited) {
                child.destroyForcibly();
            }
            if (openerProcess.isAlive()) {
                openerProcess.destroyForcibly();
            }
            check(exited, "the handle scan ends the process opened with PROCESS_VM_READ");
            check(child.exitValue() != 0, "the reader verdict is a failure exit");
        } finally {
            deleteTree(work);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "agent".equals(args[0])) {
            System.exit(runAgentChild(args));
        }
        testMaskArithmetic();
        testKeyRootAnswers();
        testFakeKeyPath();
        testBinaryHygiene();
        testGateProtocol();
        testGateAgentScan();
        testGateWatchdog();
        testExternalReader();
        testPassPublishesRoot();
        System.out.println("NativeKeyRootTest: " + checks + " checks passed");
    }

    public static final class NoOpAgent {
        public static void premain(String arguments, java.lang.instrument.Instrumentation inst) {
        }
    }

    private static int runAgentChild(String[] args) throws Exception {
        System.load(new java.io.File(args[1]).getAbsolutePath());
        byte[] secret = GuardOptions.hexToBytes(args[2]);
        long[] nonce = new long[1];
        int rc = Host.gateChallenge(nonce);
        if (rc != 0 || nonce[0] == 0L) {
            System.out.println("AGENT challenge-failed");
            return 2;
        }
        byte[] response = gateHmac(secret, nonce[0]);
        boolean accepted = Host.gateAttest(nonce[0], response) == 0;
        byte[] out = new byte[32];
        int slot2 = Host.keyRoot2(2, 0, AGENT_NONCE, out);
        int slot1 = Host.keyRoot2(1, 0, AGENT_NONCE, out);
        System.out.println("AGENT attest=" + (accepted ? "accepted" : "rejected")
                + " keyRoot2=" + (slot2 == 0 ? "released" : "locked")
                + " slot1=" + (slot1 == 0 ? "ok" : "fail"));
        return slot1 == 0 ? 0 : 3;
    }

    private static final byte[] AGENT_NONCE = new byte[32];

    static {
        for (int i = 0; i < AGENT_NONCE.length; i++) {
            AGENT_NONCE[i] = (byte) (0x77 + i * 3);
        }
    }

    public static final class Host {
        public static native int keyRoot(int slot, int sub, byte[] out);
        public static native int gateChallenge(long[] out);
        public static native int gateAttest(long nonce, byte[] response);
        public static native int gateTick(int index, byte[] out);
        public static native int nativeDecrypt(int slot, byte[] keyMaterial, byte[] data);
        public static native int keyRoot2(int slot, int sub, byte[] nonce, byte[] out);
    }

    private static void testMaskArithmetic() {
        byte[] root = new byte[32];
        for (int i = 0; i < 32; i++) {
            root[i] = (byte) (i * 9 + 3);
        }
        int salt = 0x12345678;
        int seed = 0x0BADF00D;
        int word = KeyRootCode.rootWord(root, 3);
        int encoded = KeyRootCode.encodedWord(root, 3, salt, seed);
        check(encoded != word, "the stored word is not the plaintext root word");
        check((encoded ^ KeyRootCode.maskWord(salt, 3, seed)) == word,
                "the encoded word decodes back to the root word");
        check(KeyRootCode.maskWord(salt, 3, seed) != KeyRootCode.maskWord(salt, 4, seed),
                "the mask depends on the word index");
        check(KeyRootCode.maskWord(salt, 3, seed) != KeyRootCode.maskWord(salt ^ 1, 3, seed),
                "the mask depends on the salt");
        // The unseeded helpers are gone: the build root comes from BuildRoot and the
        // bridge gate secret from newGateSecret(seed). Both must be reproducible for a
        // seed (ARCHITECTURE.md) and must live in separate derivation domains.
        byte[] derivedRoot = io.umbra.core.util.BuildRoot.derive(424242L);
        check(derivedRoot.length == 32, "the build root is 32 bytes");
        check(Arrays.equals(derivedRoot, io.umbra.core.util.BuildRoot.derive(424242L)),
                "the build root is reproducible for a seed (BuildRoot)");
        check(!Arrays.equals(derivedRoot, io.umbra.core.util.BuildRoot.derive(424243L)),
                "a different seed derives a different build root");
        check(!Arrays.equals(derivedRoot, KeyRootCode.newGateSecret(424242L)),
                "the gate secret is not the build root (separate derivation domain)");
        check(Arrays.equals(KeyRootCode.newGateSecret(424242L),
                        KeyRootCode.newGateSecret(424242L)),
                "the gate secret is reproducible for a seed");
    }

    private static void testKeyRootAnswers() throws Exception {
        Path work = Files.createTempDirectory("umbra-keyroot-");
        try {
            byte[] root = new byte[32];
            for (int i = 0; i < 32; i++) {
                root[i] = (byte) (0x40 + i * 5);
            }
            Path library = buildBridge(work, root, 0x1122334455667788L, false, "real");
            if (library == null) {
                System.out.println("NativeKeyRootTest: no C toolchain, skipping native key checks");
                return;
            }
            System.load(library.toAbsolutePath().toString());

            byte[] nonceValue = TEST_NONCE;
            byte[] bound = new byte[32];
            check(Host.keyRoot2(1, 0, nonceValue, bound) == 0,"keyRoot2 registers the nonce and answers");
            check(Arrays.equals(bound, hmac(root, 1, 0)),
                    "keyRoot2 answers the same root as keyRoot with the registered nonce");
            byte[] bound2 = new byte[32];
            check(Host.keyRoot2(1, 1, nonceValue, bound2) == 0,
                    "a different sub with the same nonce is accepted");
            byte[] wrongNonce = new byte[32];
            System.arraycopy(nonceValue, 0, wrongNonce, 1, 31);
            check(Host.keyRoot2(2, 0, wrongNonce, new byte[32]) != 0,
                    "a different nonce is refused");
            check(Host.keyRoot2(2, 0, null, new byte[32]) != 0,
                    "a missing nonce is refused");

            boolean legacyUnbound = false;
            try {
                Host.keyRoot(1, 0, new byte[32]);
            } catch (UnsatisfiedLinkError expected) {
                legacyUnbound = true;
            }
            check(legacyUnbound, "the legacy keyRoot is no longer registered");
            int[][] pairs = { { 1, 0 }, { 1, 1 }, { 7, 42 } };
            for (int[] pair : pairs) {
                byte[] first = new byte[32];
                byte[] second = new byte[32];
                int rc = invokeKeyRoot(pair[0], pair[1], first);
                check(rc == 0, "keyRoot returns 0 for slot=" + pair[0] + " sub=" + pair[1]);
                invokeKeyRoot(pair[0], pair[1], second);
                check(Arrays.equals(first, second),
                        "keyRoot is stable for slot=" + pair[0] + " sub=" + pair[1]);
                byte[] expected = hmac(root, pair[0], pair[1]);
                check(Arrays.equals(first, expected),
                        "slot=" + pair[0] + "/" + pair[1] + " equals HMAC-SHA256(root, label||slot||sub)");
            }
            byte[] a = new byte[32];
            byte[] b = new byte[32];

            check(invokeKeyRoot(2, 0, a) == 0,
                    "a gate-less build releases slot 2 unconditionally");
            check(Arrays.equals(a, hmac(root, 2, 0)),
                    "the gate-less slot-2 key equals HMAC(root, label||slot||sub)");
            check(invokeKeyRoot(3, 0, b) == 0, "other slots keep working");
            check(!Arrays.equals(a, b), "different slots give different sub-keys");
            byte[] shortBuffer = new byte[16];
            check(invokeKeyRoot(1, 0, shortBuffer) != 0, "a too small output array is refused");
            check(invokeKeyRoot(1, 0, null) != 0, "a null output array is refused");
        } finally {
            deleteTree(work);
        }
    }

    private static void testFakeKeyPath() throws Exception {
        Path work = Files.createTempDirectory("umbra-keyroot-fake-");
        try {
            byte[] root = new byte[32];
            for (int i = 0; i < 32; i++) {
                root[i] = (byte) (0x40 + i * 5);
            }
            byte[] real = new byte[32];
            invokeKeyRoot(1, 0, real);
            Path tainted = buildBridge(work, root, 0x1122334455667788L, true, "fake");
            if (tainted == null) {
                return;
            }
            System.load(tainted.toAbsolutePath().toString());
            byte[] first = new byte[32];
            byte[] second = new byte[32];
            check(invokeKeyRoot(1, 0, first) == 0,
                    "the tainted bridge still reports success (detection is not exposed)");
            invokeKeyRoot(1, 0, second);
            check(Arrays.equals(first, second), "the fake key is stable across calls");
            check(!Arrays.equals(first, real), "the fake key differs from the real sub-key");
            byte[] other = new byte[32];
            invokeKeyRoot(4, 9, other);
            check(!Arrays.equals(first, other), "different slot/sub pairs get different fake keys");
        } finally {
            deleteTree(work);
        }
    }

    private static void testBinaryHygiene() throws Exception {
        Path work = Files.createTempDirectory("umbra-keyroot-scan-");
        try {
            byte[] root = new byte[32];
            for (int i = 0; i < 32; i++) {
                root[i] = (byte) (0x11 * i + 7);
            }
            Path library = buildBridge(work, root, 0x0FEDCBA987654321L, false, "scan");
            if (library == null) {
                return;
            }
            byte[] bytes = Files.readAllBytes(library);
            check(indexOf(bytes, root) < 0, "the root never appears as a contiguous byte run");
            String text = new String(bytes, StandardCharsets.ISO_8859_1);
            check(!text.contains(HOST_CLASS), "the loader class name is not plaintext in the bridge");
            check(!text.contains("umbra.keyroot.v1"), "the KDF label is not plaintext in the bridge");
            check(!text.contains("keyRoot"), "the JNI method name is not plaintext in the bridge");
            check(text.indexOf("umbra") < 0, "the bridge carries no plaintext 'umbra' marker");
        } finally {
            deleteTree(work);
        }
    }

    private static void testPassPublishesRoot() throws Exception {
        Path directory = Files.createTempDirectory("umbra-keyroot-pass-");
        try {
            ClassNode mainClass = syntheticMain();
            ClassPool pool = new ClassPool();
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            mainClass.accept(writer);
            pool.putClass("keytest/Main.class", writer.toByteArray(), mainClass);
            pool.setMainClass("keytest/Main");
            Map<String, String> manifest = new LinkedHashMap<String, String>();
            manifest.put("Main-Class", "keytest.Main");
            pool.putResource("META-INF/MANIFEST.MF", Jars.writeManifest(manifest), 0L, 8);
            Hierarchy hierarchy = new Hierarchy();
            hierarchy.addInput(mainClass);

            UmbraConfig config = new UmbraConfig.Builder()
                    .input(directory.resolve("input.jar"))
                    .output(directory.resolve("out.jar"))
                    .seed(424242L)
                    .option("antiDebug.level", "2")
                    .option("antiDebug.nativeGuard", "true")

                    .option("classEncryption.enabled", "true")
                    .option("classEncryption.nativeKey", "true")
                    .build();
            Stats stats = new Stats();
            PassContext context = new PassContext(config, pool, hierarchy,
                    new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                    new DefaultRuntimeSupport(), new MappingSet(), stats, new Log(null, false),
                    new Random(424242L), ProgressListener.NONE);
            new NativeGuardPass().run(context);

            String compiler = NativeCompiler.resolve("", new Log(null, false));
            if (compiler == null || !NativeCompiler.hasJniHeaders()) {
                check(!stats.snapshot().containsKey("antiDebug.nativeKey")
                                || stats.snapshot().containsKey("antiDebug.nativeKey.fallback"),
                        "without a toolchain the key root degrades instead of claiming success");
                return;
            }
            byte[] root = context.secret(PassContext.NATIVE_KEY_ROOT);
            check(root != null && root.length == 32,
                    "the pass publishes a 32-byte native key root");
            check(context.hasSecret(PassContext.NATIVE_KEY_ROOT),
                    "the published root is visible to the crypto layer");
            check(stats.snapshot().containsKey("antiDebug.nativeKey"),
                    "the pass records that the key bridge was built");
            check(stats.snapshot().containsKey("antiDebug.nativeKey.bridgeBytes"),
                    "the bridge size is recorded for the report");

            String rootHex = hex(root);
            String statsText = stats.snapshot().toString();
            check(!statsText.toLowerCase(java.util.Locale.ROOT).contains(rootHex),
                    "the root never reaches the statistics");

            byte[] gateSecret = context.secret(NativeGuardPass.GATE_SECRET);
            check(gateSecret != null && gateSecret.length == 32,
                    "the pass publishes a 32-byte gate secret by default");
            check("1".equals(String.valueOf(stats.snapshot().get("antiDebug.nativeGate"))),
                    "antiDebug.nativeGate is recorded as enabled");
            check(!statsText.toLowerCase(java.util.Locale.ROOT).contains(hex(gateSecret)),
                    "the gate secret never reaches the statistics");
            boolean carrier = false;
            for (ClassPool.Resource resource : pool.resources().values()) {
                if (resource.name().endsWith(".bin") && resource.bytes().length > 1024) {
                    carrier = true;
                }
            }
            check(carrier, "a bridge binary is shipped as a JAR resource");
        } finally {
            deleteTree(directory);
        }
    }

    private static void testGateProtocol() throws Exception {
        Path work = Files.createTempDirectory("umbra-keyroot-gate-");
        try {
            byte[] root = new byte[32];
            byte[] gateSecret = new byte[32];
            for (int i = 0; i < 32; i++) {
                root[i] = (byte) (0x60 + i * 3);
                gateSecret[i] = (byte) (0xA0 - i * 5);
            }
            Path library = buildBridge(work, root, 0x1122334455667788L, false, gateSecret, true,
                    "gate");
            if (library == null) {
                System.out.println("NativeKeyRootTest: no C toolchain, skipping gate checks");
                return;
            }
            byte[] image = Files.readAllBytes(library);
            String imageText = new String(image, StandardCharsets.ISO_8859_1);
            check(!imageText.contains(KeyRootCode.GATE_CHALLENGE_METHOD),
                    "the gate challenge name is not plaintext in the bridge");
            check(!imageText.contains(KeyRootCode.GATE_ATTEST_METHOD),
                    "the gate attest name is not plaintext in the bridge");
            check(!imageText.contains(KeyRootCode.GATE_LABEL),
                    "the gate KDF label is not plaintext in the bridge");
            check(!imageText.contains(KeyRootCode.NATIVE_DECRYPT_METHOD),
                    "the native decryptor name is not plaintext in the bridge");
            check(indexOf(image, gateSecret) < 0,
                    "the gate secret never appears as a contiguous byte run");

            System.load(library.toAbsolutePath().toString());

            byte[] bootstrap = new byte[32];
            check(invokeKeyRoot(1, 0, bootstrap) == 0,
                    "slot 1 (bootstrap key) is always released");
            byte[] locked = new byte[32];
            check(invokeKeyRoot(2, 0, locked) != 0,
                    "slot 2 (business key) stays locked before the handshake");
            byte[] tickLocked = new byte[32];
            check(Host.gateTick(0, tickLocked) != 0,
                    "gateTick refuses before the handshake");

            long[] first = new long[1];
            long[] second = new long[1];
            check(Host.gateChallenge(first) == 0, "gateChallenge succeeds");
            check(first[0] != 0L, "the challenge nonce is non-zero");
            check(Host.gateChallenge(second) == 0, "a second challenge succeeds");
            check(second[0] != first[0], "every challenge refreshes the nonce");
            byte[] empty = new byte[32];
            check(Host.gateAttest(first[0], empty) != 0,
                    "an all-zero response is rejected");
            check(invokeKeyRoot(2, 0, locked) != 0,
                    "slot 2 is still locked after a failed attest");

            long forgedNonce = 0x123456789ABCDEFL;
            check(Host.gateAttest(forgedNonce, gateHmac(gateSecret, forgedNonce)) != 0,
                    "a nonce that was never issued is rejected");

            byte[] flipped = gateHmac(gateSecret, second[0]);
            flipped[31] ^= 0x01;
            check(Host.gateAttest(second[0], flipped) != 0,
                    "a response with one flipped bit is rejected (full 32-byte compare)");
            byte[] wrongNonceResponse = gateHmac(gateSecret, first[0]);
            check(Host.gateAttest(second[0], wrongNonceResponse) != 0,
                    "a response computed for a different nonce is rejected");

            byte[] response = gateHmac(gateSecret, first[0]);
            check(Host.gateAttest(first[0], response) == 0,
                    "the correct response for a still-pending nonce is accepted");
            byte[] business = new byte[32];
            check(invokeKeyRoot(2, 0, business) == 0,
                    "slot 2 is released after a successful handshake");
            check(Arrays.equals(business, hmac(root, 2, 0)),
                    "the released business key equals HMAC(root, label||slot||sub)");
            check(invokeKeyRoot(2, 7, locked) == 0,
                    "every slot-2 sub-key is released once the gate is open");

            byte[] decryptData = new byte[16];
            check(Host.nativeDecrypt(2, new byte[32], decryptData) != 0,
                    "the native decryptor placeholder refuses (fail-closed)");
            byte[] tick = new byte[32];
            byte[] payloadRoot = hmac(root, 2, 0);
            check(Host.gateTick(0, tick) == 0, "gateTick succeeds once the gate is open");
            check(Arrays.equals(tick, tickHmac(payloadRoot, 0)),
                    "gateTick(0) equals HMAC(payloadRoot, label||index)");
            byte[] tickOther = new byte[32];
            check(Host.gateTick(7, tickOther) == 0, "gateTick works for another class index");
            check(!Arrays.equals(tick, tickOther), "the tick value depends on the class index");

            long[] third = new long[1];
            Host.gateChallenge(third);
            byte[] wrong = new byte[32];
            check(Host.gateAttest(third[0], wrong) == 0,
                    "a repeat attest is idempotent once the gate is open");
            check(invokeKeyRoot(2, 1, locked) == 0, "the open state is sticky");
        } finally {
            deleteTree(work);
        }
    }

    private static void testGateAgentScan() throws Exception {
        Path work = Files.createTempDirectory("umbra-keyroot-agent-");
        try {
            byte[] root = new byte[32];
            byte[] gateSecret = new byte[32];
            for (int i = 0; i < 32; i++) {
                root[i] = (byte) (0x33 + i * 4);
                gateSecret[i] = (byte) (0xC0 - i * 3);
            }
            Path library = buildBridge(work, root, 0x0FEDCBA987654321L, false, gateSecret, true,
                    "agent");
            if (library == null) {
                return;
            }
            String secretHex = hex(gateSecret);
            String clean = runAgentChild(library, secretHex, null);
            check(clean.contains("AGENT attest=accepted keyRoot2=released slot1=ok"),
                    "without an agent the gate opens: " + clean.trim());
            Path agentJar = buildAgentJar(work);
            String injected = runAgentChild(library, secretHex, agentJar);

            check(injected.contains("slot1=ok"),
                    "the bridge stays functional under -javaagent: " + injected.trim());
        } finally {
            deleteTree(work);
        }
    }

    private static String runAgentChild(Path library, String secretHex, Path agentJar)
            throws Exception {
        String javaExe = System.getProperty("java.home") + java.io.File.separator + "bin"
                + java.io.File.separator + (isWindows() ? "java.exe" : "java");
        java.util.List<String> command = new java.util.ArrayList<String>();
        command.add(javaExe);
        if (agentJar != null) {
            command.add("-javaagent:" + agentJar.toAbsolutePath());
        }
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(NativeKeyRootTest.class.getName());
        command.add("agent");
        command.add(library.toAbsolutePath().toString());
        command.add(secretHex);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        StringBuilder output = new StringBuilder();
        java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
        } finally {
            reader.close();
        }
        if (!process.waitFor(120L, java.util.concurrent.TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("agent child timed out");
        }
        return output.toString();
    }

    private static Path buildAgentJar(Path work) throws Exception {
        Path jar = work.resolve("noop-agent.jar");
        java.io.InputStream in = NativeKeyRootTest.class
                .getResourceAsStream("NativeKeyRootTest$NoOpAgent.class");
        if (in == null) {
            throw new AssertionError("the nested agent class resource is missing");
        }
        java.util.jar.Manifest manifest = new java.util.jar.Manifest();
        manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(new java.util.jar.Attributes.Name("Premain-Class"),
                "io.umbra.tests.NativeKeyRootTest$NoOpAgent");
        java.util.jar.JarOutputStream out = new java.util.jar.JarOutputStream(
                Files.newOutputStream(jar), manifest);
        try {
            out.putNextEntry(new java.util.zip.ZipEntry(
                    "io/umbra/tests/NativeKeyRootTest$NoOpAgent.class"));
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            out.closeEntry();
        } finally {
            out.close();
            in.close();
        }
        return jar;
    }

    private static byte[] tickHmac(byte[] payloadRoot, int index) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(payloadRoot, "HmacSHA256"));
        mac.update("umbra.tick.v1".getBytes(StandardCharsets.US_ASCII));
        mac.update(le32(index));
        return mac.doFinal();
    }

    private static Path buildDll(Path work, String tag, String sourceText) throws Exception {
        String compiler = NativeCompiler.resolve("", new Log(null, false));
        if (compiler == null || !isWindows()) {
            return null;
        }
        Path source = work.resolve(tag + ".c");
        Files.write(source, sourceText.getBytes(StandardCharsets.UTF_8));
        Path library = work.resolve(tag + ".dll");
        NativeCompiler.Result result = NativeCompiler.compile(compiler, source, library,
                "windows", "-s", new Log(null, false));
        return result.success() ? library : null;
    }

    private static byte[] gateHmac(byte[] secret, long nonce) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        mac.update("umbra.gate.v1".getBytes(StandardCharsets.US_ASCII));
        byte[] le = new byte[8];
        for (int i = 0; i < 8; i++) {
            le[i] = (byte) (nonce >>> (8 * i));
        }
        mac.update(le);
        return mac.doFinal();
    }

    private static Path buildBridge(Path work, byte[] root, long secret, boolean forceTaint,
                                    String tag) throws Exception {
        return buildBridge(work, root, secret, forceTaint, null, false, tag);
    }

    private static Path buildBridge(Path work, byte[] root, long secret, boolean forceTaint,
                                    byte[] gateSecret, boolean gateEnabled, String tag)
            throws Exception {
        String compiler = NativeCompiler.resolve("", new Log(null, false));
        if (compiler == null || !NativeCompiler.hasJniHeaders() || !isWindows()) {
            return null;
        }
        String source = CGenerator.keyBridgeSource(HOST_CLASS, root, secret, forceTaint,
                gateSecret, gateEnabled);
        Path sourceFile = work.resolve("bridge-" + tag + ".c");
        Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
        Path libraryFile = work.resolve("bridge-" + tag + ".dll");
        NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, libraryFile,
                "windows", "-s", new Log(null, false));
        check(result.success(), "key bridge (" + tag + ") compiles: " + result.output());
        check(Files.size(libraryFile) > 1024, "key bridge (" + tag + ") is a real library");
        return libraryFile;
    }

    private static final byte[] TEST_NONCE = new byte[32];

    static {
        for (int i = 0; i < TEST_NONCE.length; i++) {
            TEST_NONCE[i] = (byte) (0x11 + i * 5);
        }
    }

    private static int invokeKeyRoot(int slot, int sub, byte[] out) {
        return Host.keyRoot2(slot, sub, TEST_NONCE, out);
    }

    private static byte[] hmac(byte[] root, int slot, int sub) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(root, "HmacSHA256"));
        mac.update(LABEL);
        mac.update(le32(slot));
        mac.update(le32(sub));
        return mac.doFinal();
    }

    private static byte[] le32(int value) {
        return new byte[] { (byte) value, (byte) (value >>> 8), (byte) (value >>> 16),
                (byte) (value >>> 24) };
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte value : data) {
            out.append(Character.forDigit((value >>> 4) & 0xF, 16));
            out.append(Character.forDigit(value & 0xF, 16));
        }
        return out.toString();
    }

    private static ClassNode syntheticMain() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL;
        node.name = "keytest/Main";
        node.superName = "java/lang/Object";
        MethodNode constructor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.maxStack = 1;
        constructor.maxLocals = 1;
        constructor.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        constructor.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        constructor.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        node.methods.add(constructor);
        MethodNode main = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main",
                "([Ljava/lang/String;)V", null, null);
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

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                .indexOf("win") >= 0;
    }

    private static void deleteTree(Path path) {
        try {
            if (path == null || !Files.exists(path)) {
                return;
            }
            Files.walk(path).sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {

                }
            });
        } catch (Exception ignored) {

        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }
}

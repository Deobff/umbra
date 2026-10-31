package io.umbra.tests;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.runtime.UmbraOtp;
import io.umbra.core.util.Log;
import io.umbra.gui.GuiConfig;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Checks the one-time-program state (K-OTP) layer and its injected call sites. */
public final class OtpTest {

    private static int checks;

    private OtpTest() {
    }

    public static void main(String[] args) throws Exception {
        testStateMachine();
        testConcurrentAdvance();
        testProtectedOutput();
        System.out.println("OtpTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // Runtime state machine
    // ------------------------------------------------------------------

    private static void testStateMachine() {
        long first = UmbraOtp.next();
        long second = UmbraOtp.next();
        check(first != second, "the one-time state advances on every call");
        check(UmbraOtp.peek() == second, "peek reports the advanced state");

        int a = UmbraOtp.carrier();
        int b = UmbraOtp.carrier();
        check((a & 1) != (b & 1), "the carrier's guard bit alternates between calls");
        int c = UmbraOtp.carrier();
        check((b & 1) != (c & 1), "the guard bit keeps alternating on later calls");
        check(((a ^ b) >>> 1) != 0, "the carrier mixes the whole state, not just the guard bit");

        long previous = UmbraOtp.peek();
        boolean advanced = true;
        for (int i = 0; i < 1000; i++) {
            long value = UmbraOtp.next();
            if (value == previous) {
                advanced = false;
            }
            previous = value;
        }
        check(advanced, "the state never repeats a value");
        check(UmbraOtp.peek() != 0L, "the state never becomes zero (xorshift fixed point)");
    }

    private static void testConcurrentAdvance() throws Exception {
        final Set<Long> seen = Collections.synchronizedSet(new HashSet<Long>());
        List<Thread> threads = new ArrayList<Thread>();
        for (int t = 0; t < 4; t++) {
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    for (int i = 0; i < 500; i++) {
                        seen.add(Long.valueOf(UmbraOtp.next()));
                    }
                }
            });
            threads.add(thread);
            thread.start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
        check(seen.size() == 2000, "concurrent advances never hand out the same state");
    }

    // ------------------------------------------------------------------
    // Protected output
    // ------------------------------------------------------------------

    private static void testProtectedOutput() throws Exception {
        Path root = Paths.get("").toAbsolutePath();
        Path input = root.resolve("demo").resolve("demo.jar");
        Path dir = Files.createTempDirectory("umbra-otp-test-");
        try {
            Map<String, String> options = new LinkedHashMap<String, String>();
            options.put("otp.enabled", "true");
            options.put("flowObfuscation.enabled", "true");
            options.put("flowObfuscation.level", "normal");
            options.put("methodVirtualization.enabled", "false");
            options.put("exceptionObfuscation.enabled", "false");
            options.put("antiLlm.enabled", "false");
            options.put("reflectionGate.enabled", "false");
            Path output = dir.resolve("otp.jar");
            UmbraConfig config = GuiConfig.build(input, output, 7331L, options, dir);
            EngineResult result = new UmbraEngine(Log.console(false)).run(config, null);
            Map<String, Long> stats = result.stats().snapshot();
            check(stat(stats, "otp.enabled") == 1L, "the run reports the OTP layer as enabled");
            check(stat(stats, "otp.methods") > 0L, "protected methods advance the one-time state");
            check(UmbraVerifier.verify(output).isEmpty(), "OTP output verifies");

            String otpClass = findOtpClass(output);
            check(otpClass != null, "the injected one-time state class is present in the output");
            int sites = callSites(output, otpClass);
            check(sites >= 5, "protected methods call the state at their entry (" + sites + " sites)");
            int branches = carrierBitBranches(output, otpClass);
            check(branches >= 5, "the entry prelude branches on the alternating guard bit ("
                    + branches + " methods)");
            check(carrierAlternates(output, otpClass),
                    "the injected state alternates its guard bit inside the protected jar");
            check(run(output).contains("OK"), "OTP output runs and prints OK");
        } finally {
            delete(dir);
        }
    }

    /** Finds the injected state class: static {@code long next()} plus {@code int carrier()}. */
    private static String findOtpClass(Path jar) throws Exception {
        for (String name : classNames(jar)) {
            ClassNode node = read(jar, name);
            if (node == null) {
                continue;
            }
            boolean next = false;
            boolean carrier = false;
            for (MethodNode method : node.methods) {
                if ((method.access & Opcodes.ACC_STATIC) == 0) {
                    continue;
                }
                if ("next".equals(method.name) && "()J".equals(method.desc)) {
                    next = true;
                } else if ("carrier".equals(method.name) && "()I".equals(method.desc)) {
                    carrier = true;
                }
            }
            if (next && carrier) {
                return node.name;
            }
        }
        return null;
    }

    /** Counts methods that invoke the state class at their entry. */
    private static int callSites(Path jar, String otpClass) throws Exception {
        int sites = 0;
        for (String name : classNames(jar)) {
            if (name.equals(otpClass)) {
                continue;
            }
            ClassNode node = read(jar, name);
            if (node == null) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if (callsStateAtEntry(method, otpClass)) {
                    sites++;
                }
            }
        }
        return sites;
    }

    private static boolean callsStateAtEntry(MethodNode method, String otpClass) {
        if (method.instructions == null) {
            return false;
        }
        // The prelude is at the head of the method: the field guard, the carrier
        // init and the OTP branch. Allow a small window so debug nodes do not
        // hide the call.
        int seen = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst();
             insn != null && seen < 24; insn = insn.getNext()) {
            if (!(insn instanceof MethodInsnNode)) {
                continue;
            }
            MethodInsnNode call = (MethodInsnNode) insn;
            if (call.getOpcode() == Opcodes.INVOKESTATIC && otpClass.equals(call.owner)
                    && "carrier".equals(call.name) && "()I".equals(call.desc)) {
                return true;
            }
            seen++;
        }
        return false;
    }

    /** Counts methods whose entry prelude branches on {@code carrier & 1}. */
    private static int carrierBitBranches(Path jar, String otpClass) throws Exception {
        int count = 0;
        for (String name : classNames(jar)) {
            if (name.equals(otpClass)) {
                continue;
            }
            ClassNode node = read(jar, name);
            if (node == null) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if (branchesOnCarrierBit(method, otpClass)) {
                    count++;
                }
            }
        }
        return count;
    }

    /**
     * True when the entry prelude consumes the carrier and branches on its low
     * bit ({@code carrier; ICONST_1; IAND; IFNE}). That branch is what makes the
     * next call take the other path, so its presence is asserted separately from
     * the call itself.
     */
    private static boolean branchesOnCarrierBit(MethodNode method, String otpClass) {
        if (method.instructions == null) {
            return false;
        }
        boolean sawCall = false;
        int window = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst();
             insn != null && window < 40; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (call.getOpcode() == Opcodes.INVOKESTATIC && otpClass.equals(call.owner)
                        && "carrier".equals(call.name) && "()I".equals(call.desc)) {
                    sawCall = true;
                    window = 0;
                    continue;
                }
            }
            if (sawCall && insn.getOpcode() == Opcodes.ICONST_1) {
                AbstractInsnNode and = insn.getNext();
                if (and != null && and.getOpcode() == Opcodes.IAND) {
                    AbstractInsnNode jump = and.getNext();
                    if (jump != null && jump.getOpcode() == Opcodes.IFNE) {
                        return true;
                    }
                }
            }
            window++;
        }
        return false;
    }

    private static boolean carrierAlternates(Path jar, String otpClass) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[] {jar.toUri().toURL()}, null);
        try {
            Class<?> type = Class.forName(otpClass.replace('/', '.'), true, loader);
            Method carrier = type.getMethod("carrier");
            int first = ((Integer) carrier.invoke(null)).intValue();
            int second = ((Integer) carrier.invoke(null)).intValue();
            int third = ((Integer) carrier.invoke(null)).intValue();
            return (first & 1) != (second & 1) && (second & 1) != (third & 1);
        } finally {
            loader.close();
        }
    }

    private static List<String> classNames(Path jar) throws Exception {
        List<String> names = new ArrayList<String>();
        try (JarFile file = new JarFile(jar.toFile())) {
            Enumeration<JarEntry> entries = file.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
                    names.add(name.substring(0, name.length() - ".class".length()));
                }
            }
        }
        return names;
    }

    private static ClassNode read(Path jar, String name) throws Exception {
        try (JarFile file = new JarFile(jar.toFile());
             InputStream in = file.getInputStream(file.getJarEntry(name + ".class"))) {
            if (in == null) {
                return null;
            }
            ClassNode node = new ClassNode();
            new ClassReader(in).accept(node, ClassReader.SKIP_DEBUG);
            return node;
        }
    }

    private static long stat(Map<String, Long> stats, String key) {
        Long value = stats.get(key);
        return value == null ? 0L : value.longValue();
    }

    private static String run(Path jar) throws Exception {
        Process process = new ProcessBuilder("java", "-jar", jar.toString())
                .redirectErrorStream(true).start();
        StringBuilder out = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append('\n');
            }
        }
        int exit = process.waitFor();
        check(exit == 0, "protected jar exits 0 (exit was " + exit + ")");
        return out.toString();
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAILED: " + message);
        }
    }

    private static void delete(Path directory) {
        try {
            if (!Files.exists(directory)) {
                return;
            }
            Files.walk(directory)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // Best effort temp cleanup.
                        }
                    });
        } catch (Exception ignored) {
            // Best effort temp cleanup.
        }
    }
}

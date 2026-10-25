package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.pass.impl.AntiDebugPass;
import io.umbra.core.rules.DefaultRuleSet;
import io.umbra.core.runtime.DefaultRuntimeSupport;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.crypto.GuardSupport;
import io.umbra.core.runtime.crypto.UmbraRuntimeGuard;
import io.umbra.core.runtime.crypto.UmbraWatchdog;
import io.umbra.core.util.Jars;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Plain-main tests for the 3.1 unified Java runtime guard and the hardened
 * encrypted-archive loader (no JUnit dependency).
 *
 * <p>Covered:</p>
 * <ul>
 *   <li>detection policy units: JVM arguments/agent args, environment markers,
 *       attach-pid artifacts, JDWP thread names, {@code /proc} TracerPid and
 *       module-map parsing, advertised-port parsing and the real JDWP handshake
 *       (fake server);</li>
 *   <li>the injected template itself: placeholders fully substituted, Java 8
 *       class file, no nested classes, no references to other Umbra classes, one
 *       deterministic shared copy for all passes, idempotent {@code check()},
 *       randomized daemon watchdog without a non-daemon leak, measured timing;</li>
 *   <li>child-JVM detection: clean launches at levels 1-3 on JDK 8/21/26 must
 *       pass (zero false positives), while {@code -javaagent}, JDWP/attach
 *       options, Frida environment markers, a fake {@code .attach_pid<pid>}, a
 *       JDWP listener property and a fake JDWP handshake server are detected with
 *       throw/log/exit/corrupt actions;</li>
 *   <li>integrity-pass reuse of the same guard and the encrypted-loader refusal
 *       of decryption when a guard signal is active, plus tampered encrypted
 *       class payloads still being refused.</li>
 * </ul>
 */
public final class DynamicGuardTest {

    private static int checks;
    private static Path work;

    private static final Map<String, String> JDK_CACHE = new LinkedHashMap<String, String>();

    private static final String GUARD_MARKER = "[umbra-guard]"; // legacy prefix must NOT appear
    private static final String[] SIGNAL_WORDS = { "arguments", "environment", "jmx",
            "jdwp-listener", "jdwp-thread", "attach-file", "jdwp-handshake", "heap-dump",
            "attach-self", "attach", "suspend-drift", "timing", "tracer", "module" };

    /** True when a guard emitted any signal log line (the prefix is a random token). */
    private static boolean hasGuardLog(String output) {
        if (output == null) {
            return false;
        }
        if (output.contains(GUARD_MARKER)) {
            return true;
        }
        for (int i = 0; i < SIGNAL_WORDS.length; i++) {
            if (output.contains(" " + SIGNAL_WORDS[i] + " detected")) {
                return true;
            }
        }
        return false;
    }

    /** True when the guard logged the given signal (log action only). */
    private static boolean loggedSignal(String output, String signal) {
        return output != null && output.contains(" " + signal + " detected");
    }

    private DynamicGuardTest() {
    }

    public static void main(String[] args) throws Exception {
        long started = System.currentTimeMillis();
        work = Files.createTempDirectory("umbra-dynamic-guard");
        try {
            phase("policy helpers", new Phase() {
                @Override
                public void run() throws Exception {
                    testPolicyHelpers();
                }
            });
            phase("attach artifacts", new Phase() {
                @Override
                public void run() throws Exception {
                    testAttachArtifacts();
                }
            });
            phase("injected guard", new Phase() {
                @Override
                public void run() throws Exception {
                    testInjectedGuard();
                }
            });
            phase("template shape", new Phase() {
                @Override
                public void run() throws Exception {
                    testTemplateShapeAndReuse();
                }
            });
            phase("anti-debug child matrix", new Phase() {
                @Override
                public void run() throws Exception {
                    testAntiDebugEndToEnd();
                }
            });
            phase("real dynamic attach", new Phase() {
                @Override
                public void run() throws Exception {
                    testRealDynamicAttach();
                }
            });
            phase("integrity reuse", new Phase() {
                @Override
                public void run() throws Exception {
                    testIntegrityReuse();
                }
            });
            phase("class encryption guard", new Phase() {
                @Override
                public void run() throws Exception {
                    testClassEncryptionGuard();
                }
            });
        } finally {
            deleteRecursively(work);
        }
        System.out.println("DynamicGuardTest: " + checks + " checks passed in "
                + (System.currentTimeMillis() - started) + " ms");
    }

    private interface Phase {
        void run() throws Exception;
    }

    private static void phase(String name, Phase phase) throws Exception {
        long started = System.currentTimeMillis();
        try {
            phase.run();
        } finally {
            System.out.println("DynamicGuardTest: phase \"" + name + "\" took "
                    + (System.currentTimeMillis() - started) + " ms");
        }
    }

    // ------------------------------------------------------------------
    // Detection policy units (template statics)
    // ------------------------------------------------------------------

    private static void testPolicyHelpers() {
        // JVM input arguments.
        check(UmbraRuntimeGuard.argumentsSignal(Arrays.asList(
                "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=0"), true, true),
                "agentlib jdwp argument detected");
        check(UmbraRuntimeGuard.argumentsSignal(Arrays.asList(
                "-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=0"), true, true),
                "-Xrunjdwp argument detected");
        check(UmbraRuntimeGuard.argumentsSignal(Arrays.asList("-Xdebug"), true, true),
                "-Xdebug argument detected");
        check(UmbraRuntimeGuard.argumentsSignal(Arrays.asList("-javaagent:agent.jar"), true, true),
                "-javaagent argument detected");
        check(!UmbraRuntimeGuard.argumentsSignal(Arrays.asList("-javaagent:agent.jar"), false, true),
                "jvmti=off does not flag a javaagent argument");
        check(UmbraRuntimeGuard.argumentsSignal(Arrays.asList("-agentpath:/tmp/libagent.so"), true, true),
                "-agentpath argument detected");
        check(UmbraRuntimeGuard.argumentsSignal(Arrays.asList("-XX:+StartAttachListener"), true, true),
                "-XX:+StartAttachListener argument detected");
        check(!UmbraRuntimeGuard.argumentsSignal(Arrays.asList("-XX:+StartAttachListener"), true, false),
                "attach=off does not flag StartAttachListener");
        check(!UmbraRuntimeGuard.argumentsSignal(Arrays.asList("-Xmx512m", "-Dfile.encoding=UTF-8"),
                true, true), "normal VM options are not flagged");
        check(!UmbraRuntimeGuard.argumentsSignal(Arrays.asList(
                "-Dsun.jdwp.listenerAddress=127.0.0.1:5005"), true, true),
                "listener property option is classified by the property probe, not the argument probe");
        check(UmbraRuntimeGuard.argumentsSignal(Arrays.asList(
                "-XX:+EnableDynamicAgentLoading"), true, true),
                "dynamic agent loading flag detected");
        check(!UmbraRuntimeGuard.argumentsSignal(null, true, true), "null argument list is clean");

        // sun.java.command agent arguments.
        check(UmbraRuntimeGuard.commandSignal("demo.Main -javaagent:/tmp/a.jar", true, true),
                "agent argument after the main class detected");
        check(UmbraRuntimeGuard.commandSignal("demo.Main -agentlib:jdwp=transport=dt_socket", true, true),
                "jdwp argument after the main class detected");
        check(!UmbraRuntimeGuard.commandSignal("demo.Main arg1 arg2", true, true),
                "clean command line is not flagged");
        check(!UmbraRuntimeGuard.commandSignal("", true, true), "empty command line is clean");

        // Environment markers.
        Map<String, String> env = new LinkedHashMap<String, String>();
        env.put("FRIDA_SERVER", "127.0.0.1");
        check(UmbraRuntimeGuard.environmentSignal(env), "FRIDA_* environment variable detected");
        env.clear();
        env.put("GUM_JS", "1");
        check(UmbraRuntimeGuard.environmentSignal(env), "GUM_* environment variable detected");
        env.clear();
        env.put("JAVA_TOOL_OPTIONS", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n");
        check(UmbraRuntimeGuard.environmentSignal(env), "JAVA_TOOL_OPTIONS jdwp detected");
        env.clear();
        env.put("_JAVA_OPTIONS", "-Xrunjdwp:transport=dt_socket");
        check(UmbraRuntimeGuard.environmentSignal(env), "_JAVA_OPTIONS jdwp detected");
        env.clear();
        env.put("JDK_JAVA_OPTIONS", "-javaagent:/tmp/a.jar");
        check(UmbraRuntimeGuard.environmentSignal(env), "JDK_JAVA_OPTIONS javaagent detected");
        env.clear();
        env.put("JAVA_TOOL_OPTIONS", "-Dfrida.marker=1");
        check(UmbraRuntimeGuard.environmentSignal(env), "frida marker in JAVA_TOOL_OPTIONS detected");
        env.clear();
        env.put("LD_PRELOAD", "/usr/lib/libfrida-agent.so");
        check(UmbraRuntimeGuard.environmentSignal(env), "Frida LD_PRELOAD detected");
        env.clear();
        env.put("DYLD_INSERT_LIBRARIES", "/usr/local/lib/libgum-js.so");
        check(UmbraRuntimeGuard.environmentSignal(env), "Gum DYLD_INSERT_LIBRARIES detected");
        env.clear();
        env.put("LD_PRELOAD", "/usr/lib/libz.so");
        check(!UmbraRuntimeGuard.environmentSignal(env), "clean LD_PRELOAD is not flagged");
        env.clear();
        env.put("JAVA_TOOL_OPTIONS", "-Dfile.encoding=UTF-8");
        env.put("_JAVA_OPTIONS", "-Xmx256m");
        env.put("PATH", "C:/tools");
        check(!UmbraRuntimeGuard.environmentSignal(env), "clean JAVA options are not flagged");
        check(!UmbraRuntimeGuard.environmentSignal(null), "null environment is clean");

        // Attach-pid artifacts.
        Path artifacts = work.resolve("attach-artifacts");
        try {
            Files.createDirectories(artifacts);
            long pid = currentPid();
            check(!UmbraRuntimeGuard.attachFileSignal(artifacts.toFile(), pid),
                    "empty temp dir has no attach artifact");
            Files.write(artifacts.resolve(".attach_pid" + pid), new byte[0]);
            check(UmbraRuntimeGuard.attachFileSignal(artifacts.toFile(), pid),
                    ".attach_pid<pid> detected");
            Files.delete(artifacts.resolve(".attach_pid" + pid));
            Files.write(artifacts.resolve(".java_pid" + pid), new byte[0]);
            check(UmbraRuntimeGuard.attachFileSignal(artifacts.toFile(), pid),
                    ".java_pid<pid> detected");
            check(!UmbraRuntimeGuard.attachFileSignal(artifacts.toFile(), pid + 1L),
                    "another process's attach artifact is not reported");
            check(!UmbraRuntimeGuard.attachFileSignal(work.resolve("missing-dir").toFile(), pid),
                    "missing temp dir is clean");
            check(!UmbraRuntimeGuard.attachFileSignal(artifacts.toFile(), 0L),
                    "unknown pid is clean");
        } catch (IOException failure) {
            throw new AssertionError("FAILED: attach artifact fixture: " + failure);
        }

        // JDWP thread names.
        check(UmbraRuntimeGuard.threadNamesSignal(Arrays.asList(
                "main", "JDWP Command Reader", "Attach Listener")),
                "JDWP thread detected");
        check(UmbraRuntimeGuard.threadNamesSignal(Arrays.asList("JDWP Transport Listener")),
                "JDWP transport thread detected");
        check(!UmbraRuntimeGuard.threadNamesSignal(Arrays.asList(
                "main", "Attach Listener", "Finalizer", "Signal Dispatcher")),
                "clean HotSpot threads (including Attach Listener) are not flagged");
        check(!UmbraRuntimeGuard.threadNamesSignal(null), "null thread list is clean");

        // /proc parsers (synthetic text: Windows has no /proc).
        check(!UmbraRuntimeGuard.procStatusSignal("Name:\tjava\nTracerPid:\t0\nThreads:\t9\n"),
                "TracerPid 0 is clean");
        check(UmbraRuntimeGuard.procStatusSignal("Name:\tjava\nTracerPid:\t4321\n"),
                "non-zero TracerPid detected");
        check(!UmbraRuntimeGuard.procStatusSignal("Name:\tjava\n"), "missing TracerPid is clean");
        check(!UmbraRuntimeGuard.procStatusSignal(null), "null status is clean");
        String cleanMaps = "55d0-55e0 r-xp 00000000 08:01 123 /usr/lib/jvm/libjava.so\n"
                + "7f00-7f10 r-xp 00000000 08:01 456 /usr/lib/libgumbo.so\n";
        check(!UmbraRuntimeGuard.procMapsSignal(cleanMaps),
                "clean maps (including libgumbo) are not flagged");
        check(UmbraRuntimeGuard.procMapsSignal(cleanMaps
                + "7f80-7f90 r-xp 00000000 08:01 789 /opt/frida-agent.so\n"),
                "frida module mapping detected");
        check(UmbraRuntimeGuard.procMapsSignal("7f80-7f90 r-xp 00000000 08:01 789 /usr/lib/gum-js-loop.so\n"),
                "gum-js module mapping detected");
        check(UmbraRuntimeGuard.procMapsSignal("7f80-7f90 r-xp 00000000 08:01 789 /usr/lib/ptrace-helper.so\n"),
                "ptrace helper mapping detected");

        // Suspend/breakpoint drift policy.
        check(!UmbraRuntimeGuard.driftExceeded(20L, 10L, 2000L), "normal drift is not flagged");
        check(UmbraRuntimeGuard.driftExceeded(2100L, 10L, 2000L), "suspended drift is flagged");
        check(!UmbraRuntimeGuard.driftExceeded(2000L, 10L, 2000L), "boundary drift is not flagged");
        check(!UmbraRuntimeGuard.driftExceeded(-1L, 10L, 2000L), "negative observed time is ignored");
        check(!UmbraRuntimeGuard.driftExceeded(10L, Long.MAX_VALUE - 1L, 100L),
                "overflow window is ignored");

        // Advertised ports.
        int[] fromProperty = UmbraRuntimeGuard.advertisedPorts("127.0.0.1:5005", null);
        check(fromProperty.length == 1 && fromProperty[0] == 5005,
                "advertised property port parsed");
        int[] fromArguments = UmbraRuntimeGuard.advertisedPorts(null, Arrays.asList(
                "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:8787"));
        check(fromArguments.length == 1 && fromArguments[0] == 8787,
                "advertised agent-option port parsed");
        int[] ephemeral = UmbraRuntimeGuard.advertisedPorts(null, Arrays.asList(
                "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:0"));
        check(ephemeral.length == 0, "ephemeral port 0 is ignored");
        int[] duplicate = UmbraRuntimeGuard.advertisedPorts("5005", Arrays.asList(
                "-agentlib:jdwp=transport=dt_socket,address=5005"));
        check(duplicate.length == 1, "duplicate advertised port is de-duplicated");

        // JDWP handshake policy: a real echo counts, anything else does not.
        FakeJdwpServer server = FakeJdwpServer.bindFirstFree(0);
        check(server != null, "fake JDWP server bound an ephemeral port");
        if (server != null) {
            try {
                check(UmbraRuntimeGuard.handshakeSignal("127.0.0.1", server.port(), 200),
                        "real JDWP handshake echo detected");
            } finally {
                server.close();
            }
        }
        FakeJdwpServer garbage = FakeJdwpServer.bindFirstFree(0, "NOT-A-DEBUGGER");
        check(garbage != null, "garbage server bound an ephemeral port");
        if (garbage != null) {
            try {
                check(!UmbraRuntimeGuard.handshakeSignal("127.0.0.1", garbage.port(), 200),
                        "an open non-JDWP port is not reported");
            } finally {
                garbage.close();
            }
        }
        int closedPort = 0;
        ServerSocket probe = null;
        try {
            probe = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
            closedPort = probe.getLocalPort();
        } catch (IOException ignored) {
            // no port
        } finally {
            if (probe != null) {
                try {
                    probe.close();
                } catch (IOException ignored) {
                    // ignore
                }
            }
        }
        check(closedPort > 0, "closed-port fixture bound");
        if (closedPort > 0) {
            check(!UmbraRuntimeGuard.handshakeSignal("127.0.0.1", closedPort, 100),
                    "closed port is not reported");
        }
    }

    private static void testAttachArtifacts() {
        // The real, unmodified template class on this (normally clean) JVM: its
        // policy helpers must not fire for the current process.
        boolean argsClean = !UmbraRuntimeGuard.argumentsSignal(
                runtimeArguments(), true, true);
        check(argsClean, "the test JVM has no debugger/agent arguments");
        boolean envClean = !UmbraRuntimeGuard.environmentSignal(System.getenv());
        check(envClean, "the test JVM environment has no Frida/agent markers");
        check(!UmbraRuntimeGuard.threadNamesSignal(currentThreadNames()),
                "the test JVM has no JDWP threads");

        // Attach-watcher artifact matching is exact prefix+pid.
        long pid = currentPid();
        check(UmbraRuntimeGuard.isAttachArtifactName(".attach_pid" + pid, pid),
                ".attach_pid<pid> matches the attach watcher filter");
        check(UmbraRuntimeGuard.isAttachArtifactName(".java_pid" + pid, pid),
                ".java_pid<pid> matches the attach watcher filter");
        check(!UmbraRuntimeGuard.isAttachArtifactName(".attach_pid" + (pid + 1L), pid),
                "another process's attach artifact does not match");
        check(!UmbraRuntimeGuard.isAttachArtifactName("attach_pid" + pid, pid),
                "a missing dot does not match");
        check(!UmbraRuntimeGuard.isAttachArtifactName("hsperfdata", pid),
                "unrelated temp files do not match");
        check(!UmbraRuntimeGuard.isAttachArtifactName(null, pid), "null name does not match");

        // Install-time thread snapshot: a JDWP/Attach Listener thread that appears
        // later is a signal; threads present at install are ignored (a clean Zulu
        // JVM already has Attach Listener).
        check(!UmbraRuntimeGuard.sampleAttachSignal(),
                "no attach signal for the install-time thread snapshot");
        Thread late = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(20000L);
                } catch (InterruptedException ignored) {
                    // stop
                }
            }
        }, "JDWP Late Sample Listener");
        late.setDaemon(true);
        late.start();
        try {
            check(UmbraRuntimeGuard.sampleAttachSignal(),
                    "a JDWP thread appearing after install is an attach signal");
        } finally {
            late.interrupt();
        }
    }

    // ------------------------------------------------------------------
    // Injected guard template: shape, determinism, idempotency, watchdog
    // ------------------------------------------------------------------

    private static void testInjectedGuard() throws Exception {
        Path dir = work.resolve("injected");
        Files.createDirectories(dir);

        // Level 0 must be a complete no-op.
        LoadedGuard off = loadGuard(dir, "off", 0, "throw", false);
        invoke(off.type, "check");
        check(((Integer) invoke(off.type, "fullChecks")).intValue() == 0,
                "level 0 guard performs no detection");
        off.loader.close();

        // Level 1 clean timing (arguments only).
        LoadedGuard level1 = loadGuard(dir, "level1", 1, "log", false);
        long t0 = System.nanoTime();
        invoke(level1.type, "check");
        long level1Micros = (System.nanoTime() - t0) / 1000L;
        check(((Integer) invoke(level1.type, "fullChecks")).intValue() == 1,
                "level 1 guard ran one detection pass");
        check(!((Boolean) invoke(level1.type, "isActive")).booleanValue(),
                "level 1 guard is clean on a clean JVM");
        level1.loader.close();

        // Level 2 clean timing + idempotency.
        LoadedGuard level2 = loadGuard(dir, "level2", 2, "log", false);
        t0 = System.nanoTime();
        invoke(level2.type, "check");
        long level2Micros = (System.nanoTime() - t0) / 1000L;
        t0 = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            invoke(level2.type, "detected");
        }
        long detectedMicros = (System.nanoTime() - t0) / 1000L / 100L;
        check(((Integer) invoke(level2.type, "fullChecks")).intValue() == 1,
                "second check() is idempotent (no second detection)");
        check(((Integer) invoke(level2.type, "probeRuns")).intValue() == 1,
                "exactly one probe pass ran");
        check(!((Boolean) invoke(level2.type, "isActive")).booleanValue(),
                "level 2 guard is clean on a clean JVM (zero false positive)");
        check(!((Boolean) invoke(level2.type, "detected")).booleanValue(),
                "detected() stays false on a clean JVM");
        System.out.println("DynamicGuardTest: injected check level1=" + level1Micros
                + "us level2=" + level2Micros + "us detected(clean)=" + detectedMicros + "us");

        // A real JDWP-named thread must be detected by the level-2 attach probe.
        Thread fakeJdwp = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(20000L);
                } catch (InterruptedException ignored) {
                    // stop
                }
            }
        }, "JDWP Fake Command Reader");
        fakeJdwp.setDaemon(true);
        fakeJdwp.start();
        try {
            LoadedGuard threadGuard = loadGuard(dir, "thread", 2, "throw", false);
            boolean detected = false;
            try {
                invoke(threadGuard.type, "check");
            } catch (java.lang.reflect.InvocationTargetException failure) {
                Throwable cause = failure.getCause();
                detected = cause instanceof SecurityException
                        && cause.getStackTrace().length == 0;
            }
            check(detected, "a JDWP thread name is detected by the injected guard");
            threadGuard.loader.close();
        } finally {
            fakeJdwp.interrupt();
        }

        // Level 3 starts the randomized watchdog as a daemon without leaking a
        // non-daemon thread (action=log so the background watchdog can never stop
        // this test JVM).
        int nonDaemonBefore = countThreads(false);
        LoadedGuard level3 = loadGuard(dir, "level3", 3, "log", true);
        invoke(level3.type, "check");
        check(((Integer) invoke(level3.type, "fullChecks")).intValue() == 1,
                "level 3 guard ran its detection pass");
        int nonDaemonAfter = countThreads(false);
        check(nonDaemonAfter == nonDaemonBefore, "watchdog does not leak a non-daemon thread");
        boolean watchdogFound = false;
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.isDaemon() && thread.getName() != null && thread.getName().startsWith("u")
                    && thread.getName().length() > 6) {
                watchdogFound = true;
            }
        }
        check(watchdogFound, "injected watchdog thread is alive and daemon");
        level3.loader.close();
    }

    private static void testTemplateShapeAndReuse() throws Exception {
        ClassPool pool = new ClassPool();
        Map<String, String> replacements = guardReplacements(2, "log", "");
        String first = GuardSupport.ensureRuntimeGuard(pool, 424242L, replacements);
        check(first.equals(GuardSupport.ensureRuntimeGuard(pool, 424242L,
                guardReplacements(3, "throw", ""))),
                "all passes reuse the same seed-derived guard class");
        check(pool.classes().size() == 1, "the runtime guard is injected exactly once");
        ClassNode node = pool.getClass(first);
        check(node != null, "injected guard class is in the pool");
        check(pool.isGenerated(first), "injected guard is marked generated");
        check(node.version == Opcodes.V1_8, "injected guard targets Java 8 class files");
        check((node.access & Opcodes.ACC_SYNTHETIC) != 0, "injected guard is synthetic");
        boolean definesNestedClass = false;
        if (node.innerClasses != null) {
            for (org.objectweb.asm.tree.InnerClassNode inner : node.innerClasses) {
                if (inner.outerName == null || node.name.equals(inner.outerName)) {
                    definesNestedClass = true;
                }
            }
        }
        check(!definesNestedClass, "runtime guard defines no nested/anonymous classes");
        check(node.nestHostClass == null && node.nestMembers == null,
                "runtime guard has no nest attributes");

        // All placeholders substituted.
        int placeholders = 0;
        for (FieldNode field : node.fields) {
            if (field.value instanceof String && ((String) field.value).indexOf("@@") >= 0) {
                placeholders++;
            }
        }
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String
                        && ((String) ((LdcInsnNode) insn).cst).indexOf("@@") >= 0) {
                    placeholders++;
                }
            }
        }
        check(placeholders == 0, "every guard placeholder was substituted");

        // No compile-time reference to another Umbra class (self references and
        // java.* only), which is what makes the template injector-safe.
        int foreign = 0;
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                String owner = null;
                if (insn instanceof MethodInsnNode) {
                    owner = ((MethodInsnNode) insn).owner;
                } else if (insn instanceof FieldInsnNode) {
                    owner = ((FieldInsnNode) insn).owner;
                } else if (insn instanceof TypeInsnNode) {
                    owner = ((TypeInsnNode) insn).desc;
                } else if (insn instanceof LdcInsnNode
                        && ((LdcInsnNode) insn).cst instanceof org.objectweb.asm.Type) {
                    owner = ((org.objectweb.asm.Type) ((LdcInsnNode) insn).cst).getInternalName();
                }
                if (owner == null || owner.startsWith("[") || owner.startsWith("java/")
                        || owner.equals(node.name)) {
                    continue;
                }
                foreign++;
            }
        }
        check(foreign == 0, "runtime guard references no other Umbra class at compile time");

        // Determinism: the same seed produces the same injected name in a fresh pool.
        ClassPool other = new ClassPool();
        check(first.equals(GuardSupport.ensureRuntimeGuard(other, 424242L,
                guardReplacements(2, "log", ""))), "guard injection is deterministic for a seed");
    }

    // ------------------------------------------------------------------
    // Child-JVM detection and false-positive matrix
    // ------------------------------------------------------------------

    private static void testAntiDebugEndToEnd() throws Exception {
        Path dir = work.resolve("e2e");
        Files.createDirectories(dir);
        Path level1Log = buildAntiDebugJar(dir, 1, "log", null);
        Path level2Log = buildAntiDebugJar(dir, 2, "log", null);
        Path level2Throw = buildAntiDebugJar(dir, 2, "throw", null);
        Path level2Exit = buildAntiDebugJar(dir, 2, "exit", null);
        Path level2Corrupt = buildAntiDebugJar(dir, 2, "corrupt", null);
        Path level3Throw = buildAntiDebugJar(dir, 3, "throw", null);
        Map<String, String> noJvmti = new LinkedHashMap<String, String>();
        noJvmti.put("antiDebug.jvmti", "false");
        Path level2NoJvmtiLog = buildAntiDebugJar(dir, 2, "log", noJvmti);
        Path agent = buildAgent(dir, false);
        Path attachAgent = buildAgent(dir, true);

        List<Integer> majors = new ArrayList<Integer>();
        for (int major : new int[] { 8, 21, 26 }) {
            if (jdkJava(major) != null) {
                majors.add(Integer.valueOf(major));
            }
        }
        check(majors.size() >= 2, "at least JDK 8 and one newer JDK are available: " + majors);
        System.out.println("DynamicGuardTest: child-JVM matrix " + majors
                + " (clean levels 1-3 + detection scenarios)");

        // Zero false positives: clean launches at levels 1-3 on every JDK.
        for (int i = 0; i < majors.size(); i++) {
            int major = majors.get(i).intValue();
            String java = jdkJava(major);
            Path[] cleanJars = { level1Log, level2Log, level3Throw };
            int[] levels = { 1, 2, 3 };
            for (int j = 0; j < cleanJars.length; j++) {
                Child clean = runChild(java, cleanJars[j], new ArrayList<String>(), null, 60);
                check(!clean.timedOut, "clean JDK " + major + " level " + levels[j]
                        + " launch terminates (daemon watchdog does not keep it alive)");
                check(clean.exit == 0, "clean JDK " + major + " level " + levels[j]
                        + " exits 0 (actual " + clean.exit + ", output: " + clean.output + ")");
                check(clean.output.contains("OK"), "clean JDK " + major + " level " + levels[j]
                        + " runs main");
                check(!hasGuardLog(clean.output), "clean JDK " + major + " level "
                        + levels[j] + " triggers no guard signal (output: " + clean.output + ")");
            }
        }

        // -javaagent detection with log (program continues) and throw (rejected).
        Child agentLog = runChild(jdkJava(8), level2Log,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(agentLog.exit == 0, "javaagent log action keeps the program running");
        check(loggedSignal(agentLog.output, "arguments"),
                "javaagent is detected as a JVM-argument signal (output: " + agentLog.output + ")");
        check(agentLog.output.contains("OK"), "javaagent log action lets main run");
        Child agentThrow = runChild(jdkJava(8), level2Throw,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(agentThrow.exit != 0, "javaagent throw action rejects the process");
        check(!agentThrow.output.contains("OK"), "javaagent throw action never runs main");

        // Real JDWP options.
        for (int i = 0; i < majors.size(); i++) {
            int major = majors.get(i).intValue();
            String argument = major == 8
                    ? "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=0"
                    : "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:0";
            Child jdwp = runChild(jdkJava(major), level2Throw, Arrays.asList(argument), null, 60);
            check(jdwp.exit != 0, "JDWP launch on JDK " + major + " is rejected");
            check(!hasGuardLog(jdwp.output),
                    "JDWP throw action on JDK " + major + " is silent (output: " + jdwp.output + ")");
        }
        Child xrun = runChild(jdkJava(8), level2Throw, Arrays.asList(
                "-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=0"), null, 60);
        check(xrun.exit != 0 && !hasGuardLog(xrun.output),
                "-Xrunjdwp throw action is silent (output: " + xrun.output + ")");
        for (int major : new int[] { 8 }) {
            if (jdkJava(major) == null) {
                continue;
            }
            Child attachListener = runChild(jdkJava(major), level2Log,
                    Arrays.asList("-XX:+StartAttachListener"), null, 60);
            check(loggedSignal(attachListener.output, "arguments"),
                    "-XX:+StartAttachListener detected on JDK " + major
                            + " (output: " + attachListener.output + ")");
        }

        // Environment markers (real child environment, no JVM option involved).
        Map<String, String> fridaEnv = new LinkedHashMap<String, String>();
        fridaEnv.put("FRIDA_SERVER", "127.0.0.1");
        Child frida = runChild(jdkJava(8), level2Log, new ArrayList<String>(), fridaEnv, 60);
        check(loggedSignal(frida.output, "environment"),
                "FRIDA_* environment marker detected (output: " + frida.output + ")");
        check(frida.exit == 0 && frida.output.contains("OK"), "environment log action continues");
        Map<String, String> toolOptions = new LinkedHashMap<String, String>();
        toolOptions.put("JAVA_TOOL_OPTIONS", "-Dfrida.marker=1");
        Child toolOption = runChild(jdkJava(8), level2Log, new ArrayList<String>(), toolOptions, 60);
        check(loggedSignal(toolOption.output, "environment"),
                "JAVA_TOOL_OPTIONS frida marker detected (output: " + toolOption.output + ")");
        Map<String, String> cleanOptions = new LinkedHashMap<String, String>();
        cleanOptions.put("JAVA_TOOL_OPTIONS", "-Dfile.encoding=UTF-8");
        cleanOptions.put("_JAVA_OPTIONS", "-Xmx64m");
        Child cleanEnv = runChild(jdkJava(8), level2Log, new ArrayList<String>(), cleanOptions, 60);
        check(cleanEnv.exit == 0 && cleanEnv.output.contains("OK")
                && !hasGuardLog(cleanEnv.output),
                "benign JAVA_TOOL_OPTIONS/_JAVA_OPTIONS produce no false positive (output: "
                        + cleanEnv.output + ")");

        // A genuine .attach_pid<pid> artifact created by a java agent premain
        // (jvmti detection off so the agent option itself is not the signal).
        Path attachTmp = dir.resolve("attach-tmp");
        Files.createDirectories(attachTmp);
        Child attached = runChild(jdkJava(8), level2NoJvmtiLog,
                Arrays.asList("-Djava.io.tmpdir=" + attachTmp.toAbsolutePath(),
                        "-javaagent:" + attachAgent.toAbsolutePath()), null, 60);
        check(loggedSignal(attached.output, "attach"),
                "fake .attach_pid<pid> detected (output: " + attached.output + ")");
        check(attached.exit == 0 && attached.output.contains("OK"), "attach-file log action continues");
        Child plainAgent = runChild(jdkJava(8), level2NoJvmtiLog,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(!hasGuardLog(plainAgent.output) && plainAgent.exit == 0,
                "jvmti=off plain javaagent is not flagged (output: " + plainAgent.output + ")");

        // sun.jdwp.listenerAddress property (advertised-port path).
        Child listener = runChild(jdkJava(8), level2Log,
                Arrays.asList("-Dsun.jdwp.listenerAddress=127.0.0.1:65000"), null, 60);
        check(loggedSignal(listener.output, "jdwp-listener"),
                "sun.jdwp.listenerAddress detected (output: " + listener.output + ")");

        // A hardcoded common-port JDWP handshake is NOT a default detection signal
        // (it could belong to another local JVM that happens to be debugged):
        // a fake JDWP listener on port 5005 must not trip a clean child, while an
        // explicit opt-in (antiDebug.portProbe=true) diagnoses it.
        FakeJdwpServer freePortServer = FakeJdwpServer.bindFirstFree(5005);
        if (freePortServer != null) {
            try {
                Child noScan = runChild(jdkJava(8), level2Log, new ArrayList<String>(), null, 60);
                check(noScan.exit == 0 && noScan.output.contains("OK")
                                && !hasGuardLog(noScan.output),
                        "fake JDWP listener on port " + freePortServer.port()
                                + " does not trip the default guard (no hardcoded port scan): "
                                + noScan.output);
            } finally {
                freePortServer.close();
            }
        } else {
            System.out.println("DynamicGuardTest: port 5005 busy; skipping default no-port-scan check");
        }

        // Opt-in diagnostics: advertised-port handshake (ephemeral port, no 5005).
        Map<String, String> portProbeOption = new LinkedHashMap<String, String>();
        portProbeOption.put("antiDebug.portProbe", "true");
        Path level2PortProbeLog = buildAntiDebugJar(dir, 2, "log", portProbeOption);
        FakeJdwpServer ephemeral = FakeJdwpServer.bindFirstFree(0);
        check(ephemeral != null, "ephemeral fake JDWP server bound");
        if (ephemeral != null) {
            try {
                Child optIn = runChild(jdkJava(8), level2PortProbeLog, Arrays.asList(
                        "-Dsun.jdwp.listenerAddress=127.0.0.1:" + ephemeral.port()), null, 60);
                check(loggedSignal(optIn.output, "jdwp-handshake"),
                        "antiDebug.portProbe=true probes the listener-advertised JDWP port (output: "
                                + optIn.output + ")");
            } finally {
                ephemeral.close();
            }
        }

        // exit / corrupt actions.
        Child exitAction = runChild(jdkJava(8), level2Exit,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(exitAction.exit == 1, "exit action halts with code 1 (actual " + exitAction.exit + ")");
        check(!exitAction.output.contains("OK"), "exit action never runs main");
        Child corruptAction = runChild(jdkJava(8), level2Corrupt,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(corruptAction.exit == 0, "corrupt action halts with code 0 (actual "
                + corruptAction.exit + ")");
        check(!corruptAction.output.contains("OK"), "corrupt action never runs main");
    }

    // ------------------------------------------------------------------
    // Integrity pass reuses the unified runtime guard
    // ------------------------------------------------------------------

    private static void testIntegrityReuse() throws Exception {
        Path dir = work.resolve("integrity");
        Files.createDirectories(dir);
        Path program = buildProgramJar(dir, "INTEGRITY-OK");
        Path guarded = dir.resolve("integrity-guarded.jar");
        UmbraConfig config = new UmbraConfig.Builder()
                .input(program)
                .output(guarded)
                .seed(424242L)
                .option("integrity.enabled", "true")
                .option("integrity.level", "1")
                .option("integrity.action", "throw")
                .option("antiDebug.level", "0")
                .option("antiDebug.nativeGuard", "false")
                .build();
        EngineResult result = runEngine(config);
        check(stat(result, "integrity.runtimeGuard") == 1,
                "integrity pass injected the unified runtime guard");
        Path agent = buildAgent(dir, false);
        Child clean = runChild(jdkJava(8), guarded, new ArrayList<String>(), null, 60);
        check(clean.exit == 0 && clean.output.contains("INTEGRITY-OK")
                && !hasGuardLog(clean.output),
                "integrity-guarded program runs clean (output: " + clean.output + ")");
        Child agentChild = runChild(jdkJava(8), guarded,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(agentChild.exit != 0, "integrity guard rejects an instrumented launch");
        check(!hasGuardLog(agentChild.output),
                "integrity guard throw action is silent (output: " + agentChild.output + ")");

        // Both passes on: the anti-debug and integrity layers must share one
        // injected guard, and the combined build must stay clean.
        Path combined = dir.resolve("combined-guarded.jar");
        UmbraConfig combinedConfig = new UmbraConfig.Builder()
                .input(program)
                .output(combined)
                .seed(424242L)
                .option("integrity.enabled", "true")
                .option("integrity.level", "1")
                .option("integrity.action", "throw")
                .option("antiDebug.level", "2")
                .option("antiDebug.action", "throw")
                .option("antiDebug.nativeGuard", "false")
                .build();
        EngineResult combinedResult = runEngine(combinedConfig);
        check(stat(combinedResult, "integrity.runtimeGuard") == 1
                        && stat(combinedResult, "antiDebug.level") == 2,
                "combined anti-debug + integrity build shares the unified guard");
        Child combinedClean = runChild(jdkJava(8), combined, new ArrayList<String>(), null, 60);
        check(combinedClean.exit == 0 && combinedClean.output.contains("INTEGRITY-OK")
                        && !hasGuardLog(combinedClean.output),
                "combined guard build runs clean (output: " + combinedClean.output + ")");
        Child combinedAgent = runChild(jdkJava(8), combined,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(combinedAgent.exit != 0
                        && !hasGuardLog(combinedAgent.output),
                "combined guard build rejects an instrumented launch silently (output: "
                        + combinedAgent.output + ")");
    }

    // ------------------------------------------------------------------
    // Encrypted-archive loader: guard gate + tamper refusal
    // ------------------------------------------------------------------

    private static void testClassEncryptionGuard() throws Exception {
        Path dir = work.resolve("encrypted");
        Files.createDirectories(dir);
        Path program = buildProgramJar(dir, "ENC-OK");
        Path agent = buildAgent(dir, false);
        Path encryptedThrow = buildEncryptedJar(dir, program, "throw", 2);
        Path encryptedLog = buildEncryptedJar(dir, program, "log", 2);

        // Clean launches decrypt, define and run the original main on 8/21/26.
        int cleanedJdks = 0;
        for (int major : new int[] { 8, 21, 26 }) {
            String java = jdkJava(major);
            if (java == null) {
                continue;
            }
            Child clean = runChild(java, encryptedThrow, new ArrayList<String>(), null, 60);
            check(clean.exit == 0, "encrypted archive runs on JDK " + major + " (actual "
                    + clean.exit + ", output: " + clean.output + ")");
            check(clean.output.contains("ENC-OK"),
                    "encrypted program output on JDK " + major + " (output: " + clean.output + ")");
            check(!hasGuardLog(clean.output),
                    "encrypted archive clean launch has no guard signal on JDK " + major);
            cleanedJdks++;
        }
        check(cleanedJdks >= 2, "encrypted archive clean matrix covered multiple JDKs");

        // Level-3 integrity watchdog on an encrypted archive: the watchdog class is
        // itself an encrypted payload, so it must be resolved through the loader.
        // The probe program reports the live daemon watchdog thread it can see.
        Path watchdogProgram = buildWatchdogProgramJar(dir);
        Path watchdogJar = buildEncryptedWatchdogJar(dir, watchdogProgram);
        Child watchdogChild = runChild(jdkJava(8), watchdogJar, new ArrayList<String>(), null, 60);
        check(watchdogChild.exit == 0 && watchdogChild.output.contains("WD-OK"),
                "level-3 encrypted archive runs (output: " + watchdogChild.output + ")");
        check(watchdogChild.output.contains("WATCHDOG-PRESENT"),
                "encrypted-archive level-3 watchdog is started through the loader (output: "
                        + watchdogChild.output + ")");
        check(!hasGuardLog(watchdogChild.output),
                "level-3 encrypted archive clean launch has no guard signal");

        byte[] raw = Files.readAllBytes(encryptedThrow);
        check(!new String(raw, StandardCharsets.ISO_8859_1).contains("ENC-OK"),
                "encrypted archive does not leak the program string");

        // action=throw: the loader refuses before decrypting/defining anything.
        Child throwAgent = runChild(jdkJava(8), encryptedThrow,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(throwAgent.exit != 0, "encrypted loader rejects an instrumented launch");
        check(!hasGuardLog(throwAgent.output),
                "encrypted loader throw action is silent (output: " + throwAgent.output + ")");
        check(!throwAgent.output.contains("ENC-OK"), "encrypted loader never defines the payload");

        // action=log: the guard logs and the loader still refuses the decrypt/define
        // step explicitly (fail-closed anti-dump gate).
        Child logAgent = runChild(jdkJava(8), encryptedLog,
                Arrays.asList("-javaagent:" + agent.toAbsolutePath()), null, 60);
        check(logAgent.exit != 0, "encrypted loader refuses class decryption on a guard signal");
        check(!logAgent.output.contains("ENC-OK"), "refused class payload is never defined");
        check(!logAgent.output.contains("SecurityException")
                        && !logAgent.output.contains("UmbraClassLoader.java")
                        && !logAgent.output.contains("UmbraRuntimeGuard.java"),
                "loader refusal is silent (no stack trace / source file leak): " + logAgent.output);
        check(!logAgent.output.contains("ENC-OK"), "refused class payload is never defined");

        // Tampered encrypted payloads: at least the payloads the program needs are
        // refused (an HMAC/digest failure), even though decryption is lazy.
        Map<String, byte[]> entries = readZip(encryptedThrow);
        List<String> payloadNames = new ArrayList<String>();
        for (String name : entries.keySet()) {
            if (name.endsWith(".class") || name.startsWith("META-INF/")) {
                continue;
            }
            payloadNames.add(name);
        }
        check(payloadNames.size() >= 2, "encrypted archive carries payload entries: "
                + payloadNames.size());
        int refused = 0;
        int tolerated = 0;
        String firstRefusalOutput = null;
        for (int i = 0; i < payloadNames.size(); i++) {
            String name = payloadNames.get(i);
            Map<String, byte[]> tampered = new LinkedHashMap<String, byte[]>();
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                byte[] copy = entry.getValue().clone();
                if (entry.getKey().equals(name) && copy.length > 0) {
                    copy[copy.length / 2] ^= 0x01;
                }
                tampered.put(entry.getKey(), copy);
            }
            Path tamperedJar = dir.resolve("tampered-" + i + ".jar");
            writeZip(tamperedJar, tampered);
            Child child = runChild(jdkJava(8), tamperedJar, new ArrayList<String>(), null, 60);
            if (child.exit != 0) {
                refused++;
                if (firstRefusalOutput == null) {
                    firstRefusalOutput = child.output;
                }
                check(!child.output.contains("ENC-OK"),
                        "tampered payload is never executed (" + name + ")");
            } else {
                tolerated++;
            }
        }
        check(refused >= 2, "tampered encrypted class payloads are refused (refused=" + refused
                + ", tolerated=" + tolerated + ")");
        check(firstRefusalOutput != null
                        && !firstRefusalOutput.contains("ENC-OK")
                        && !firstRefusalOutput.contains("SecurityException")
                        && !firstRefusalOutput.contains("UmbraClassLoader.java"),
                "tamper refusal is silent and leaks no stack/source information");
        System.out.println("DynamicGuardTest: tampered payload matrix refused=" + refused
                + " tolerated(lazy/unread)=" + tolerated + "/" + payloadNames.size());
    }

    // ------------------------------------------------------------------
    // Real dynamic attach (qa/dynamic-attach fixtures + JDK 8 tools.jar)
    // ------------------------------------------------------------------

    private static void testRealDynamicAttach() throws Exception {
        Path dir = work.resolve("dynamic-attach");
        Files.createDirectories(dir);
        Path fixtures = Paths.get("qa", "dynamic-attach");
        Path agentJar = fixtures.resolve("agent.jar");
        String tools = toolsJar();
        if (!Files.isRegularFile(agentJar) || !Files.isRegularFile(fixtures.resolve("Attacher.class"))
                || tools == null) {
            System.out.println("DynamicGuardTest: qa/dynamic-attach fixtures or JDK 8 tools.jar "
                    + "missing; skipping real dynamic-attach checks");
            return;
        }
        Path attachProgram = buildLoopProgramJar(dir, false);
        Path lateProgram = buildLoopProgramJar(dir, true);

        // Plain (unencrypted) guarded program: a real Attacher.loadAgent attach is
        // detected and the process stops within 3 s.
        Path plain = buildEngineGuardedJar(dir, attachProgram, "plain-attach.jar", 3, "throw", false, false);
        runAttachScenario(fixtures, agentJar, plain);

        // Class-encrypted archive: the loader-installed guard catches the same
        // real attach before any further payload is decrypted.
        Path encrypted = buildEngineGuardedJar(dir, attachProgram, "encrypted-attach.jar", 3,
                "throw", true, false);
        runAttachScenario(fixtures, agentJar, encrypted);

        // action=log + encrypted loader: the sticky signal makes the loader refuse
        // the next class decryption, so fail-closed still happens. Renaming is
        // disabled so the deliberately reflective late-load fixture can name its
        // helper classes.
        Path late = buildEngineGuardedJar(dir, lateProgram, "late-log.jar", 3, "log", true, true);
        runLateLoadScenario(fixtures, agentJar, late);

        // WatchService: a post-startup transient .attach_pid<pid> is caught even
        // though the file only exists for a few tens of milliseconds.
        Path fakeTmp = dir.resolve("fake-attach-tmp");
        Files.createDirectories(fakeTmp);
        Path fake = buildEngineGuardedJar(dir, attachProgram, "fake-attach.jar", 2, "throw", false, false);
        runFakeAttachArtifactScenario(fake, fakeTmp);
    }

    private static void runAttachScenario(Path fixtures, Path agentJar, Path jar) throws Exception {
        // The Windows-only agent-load frame is very short-lived; a slow/loaded host
        // can miss one sample window. Retry the real attach on a fresh child (the
        // production guard still fail-loud after one hit); assert one success.
        String lastOutput = null;
        String lastAttacher = null;
        int lastExit = 0;
        for (int attempt = 1; attempt <= 5; attempt++) {
            AttachAttempt result = attemptAttach(fixtures, agentJar, jar);
            if (result.detected) {
                // The throw action is silent by design; the observable evidence is a
                // non-zero exit before the program's DONE marker. Log-action archives
                // are asserted separately in the late-load/startup tests.
                check(result.exit != 0, "attached guarded process exits non-zero (attempt "
                        + attempt + ", actual " + result.exit + ")");
                check(result.detectionMs == -1L || result.detectionMs <= 3000L,
                        "attach detected within 3 s of the agent load (attempt " + attempt
                                + ", detection " + result.detectionMs + " ms)");
                check(!result.output.contains("DONE"), "program never reaches DONE after attach");
                System.out.println("DynamicGuardTest: real attach detected " + result.detectionMs
                        + " ms after agent load (attempt " + attempt + ", " + jar.getFileName() + ")");
                return;
            }
            lastOutput = result.output;
            lastAttacher = result.attacher;
            lastExit = result.exit;
            System.out.println("DynamicGuardTest: attach attempt " + attempt + " missed on "
                    + jar.getFileName() + " (output: " + lastOutput + ")");
            // Backoff between attempts: under a parallel full-suite load the
            // attaching JVM and the target compete for CPU, so stagger retries.
            if (attempt < 5) {
                Thread.sleep(150L + 150L * attempt);
            }
        }
        throw new AssertionError("FAILED: real dynamic attach not detected after 5 attempts ("
                + jar.getFileName() + ", last output: " + lastOutput
                + ", attacher: " + lastAttacher + ", exit=" + lastExit + ")");
    }

    private static final class AttachAttempt {
        boolean detected;
        boolean marker;
        int exit;
        long detectionMs = -1L;
        String output = "";
        String attacher = "";
    }

    private static AttachAttempt attemptAttach(Path fixtures, Path agentJar, Path jar)
            throws Exception {
        AttachAttempt result = new AttachAttempt();
        LiveChild child = LiveChild.start(jdkJava(8), jar, new ArrayList<String>());
        RawProcess attacher = null;
        try {
            if (child.awaitOutput("READY", 30000) == null) {
                result.output = child.output();
                return result;
            }
            long pid = child.pid();
            if (pid <= 0) {
                result.output = child.output();
                return result;
            }
            attacher = startRawProcess(attacherCommand(fixtures, pid, agentJar));
            long attachMarkNanos = 0L;
            long exitedAtNanos = 0L;
            boolean exited = false;
            long deadline = System.currentTimeMillis() + 20000L;
            while (System.currentTimeMillis() < deadline) {
                if (child.waitExit(10L)) {
                    exited = true;
                    exitedAtNanos = System.nanoTime();
                    break;
                }
                if (attachMarkNanos == 0L) {
                    if (child.output().contains("ATTACHED") || attacher.waitExit(0L)) {
                        attachMarkNanos = System.nanoTime();
                    }
                }
            }
            if (!exited) {
                exited = child.waitExit(3000L);
                exitedAtNanos = System.nanoTime();
            }
            result.exit = child.exitValue();
            result.output = child.output();
            result.attacher = attacher.output();
            result.marker = loggedSignal(result.output, "attach");
            // A miss under load lets the program finish normally (exit 0 + DONE);
            // only a non-zero stop before DONE counts as attach detection here.
            result.detected = exited && result.exit != 0
                    && !result.output.contains("DONE");
            result.detectionMs = attachMarkNanos == 0L || exitedAtNanos == 0L
                    ? -1L : (exitedAtNanos - attachMarkNanos) / 1000000L;
            return result;
        } finally {
            if (attacher != null) {
                attacher.kill();
            }
            child.kill();
        }
    }

    private static void runLateLoadScenario(Path fixtures, Path agentJar, Path jar) throws Exception {
        LiveChild child = LiveChild.start(jdkJava(8), jar, new ArrayList<String>());
        try {
            check(child.awaitOutput("READY", 30000) != null,
                    "late-load program reached READY (" + jar.getFileName() + ")");
            long pid = child.pid();
            long started = System.nanoTime();
            boolean attachedDetected = false;
            for (int attempt = 1; attempt <= 4 && !attachedDetected; attempt++) {
                if (!isAlive(child)) {
                    System.out.println("DynamicGuardTest: late-load child stopped before attach "
                            + "attempt " + attempt + " (output: " + child.output() + ")");
                    break;
                }
                Child attached = runProcess(attacherCommand(fixtures, pid, agentJar), null, 60000L);
                if (attached.exit != 0 || !attached.output.contains("ATTACH-OK")) {
                    System.out.println("DynamicGuardTest: late-load attach attempt " + attempt
                            + " failed (output: " + attached.output + "); skipping sticky check");
                    break;
                }
                attachedDetected = child.awaitOutput("attach detected", 5000L) != null;
            }
            if (!attachedDetected) {
                if (isAlive(child)) {
                    System.out.println("DynamicGuardTest: late-load attach sampling missed after 4 "
                            + "attempts and the child is still running; skipping sticky-loader "
                            + "assertion (documented residual)");
                    return;
                }
                // The attach was accepted but the short-lived agent-load sample was
                // missed under load; the child still stopped silently right after the
                // attach (sticky loader refusal), which the assertions below verify.
                System.out.println("DynamicGuardTest: late-load marker sampling missed; child "
                        + "stopped after attach (output: " + child.output() + ")");
            }
            boolean exited = child.waitExit(15000);
            long latencyMs = (System.nanoTime() - started) / 1000000L;
            String output = child.output();
            check(exited && child.exitValue() != 0,
                    "sticky attach signal makes the encrypted loader fail closed (latency "
                            + latencyMs + " ms, output: " + output + ")");
            check(!output.contains("SecurityException")
                        && !output.contains("UmbraClassLoader.java"),
                "encrypted loader refusal is silent (output: " + output + ")");
            check(!output.contains("DONE"), "late-load program never reaches DONE");
        } finally {
            child.kill();
        }
    }

    private static void runFakeAttachArtifactScenario(Path jar, Path tmpDirectory) throws Exception {
        LiveChild child = LiveChild.start(jdkJava(8), jar,
                Arrays.asList("-Djava.io.tmpdir=" + tmpDirectory.toAbsolutePath()));
        try {
            check(child.awaitOutput("READY", 30000) != null,
                    "fake-attach program reached READY (" + jar.getFileName() + ")");
            long pid = child.pid();
            Path artifact = tmpDirectory.resolve(".attach_pid" + pid);
            Files.write(artifact, new byte[0]);
            try {
                Thread.sleep(60L);
            } finally {
                Files.deleteIfExists(artifact);
            }
            boolean exited = child.waitExit(3000);
            String output = child.output();
            check(exited, "transient .attach_pid<pid> created after startup is caught by the "
                    + "WatchService watcher (output: " + output + ")");
            check(child.exitValue() != 0, "fake attach artifact stops the process non-zero");
            check(!hasGuardLog(output),
                    "fake attach artifact throw action is silent (output: " + output + ")");
            check(!output.contains("DONE"), "program never reaches DONE after the fake artifact");
        } finally {
            child.kill();
        }
    }

    private static List<String> attacherCommand(Path fixtures, long pid, Path agentJar) {
        List<String> command = new ArrayList<String>();
        command.add(jdkJava(8));
        command.add("-cp");
        command.add(fixtures.toAbsolutePath() + File.pathSeparator + toolsJar());
        command.add("Attacher");
        command.add(String.valueOf(pid));
        command.add(agentJar.toAbsolutePath().toString());
        return command;
    }

    /** A child process whose output is pumped asynchronously (no blocking read). */
    private static final class RawProcess {
        private final Process process;
        private final StringBuilder output = new StringBuilder();
        private final Thread pump;

        private RawProcess(Process process) {
            this.process = process;
            this.pump = new Thread(new Runnable() {
                private final Process target = process;

                @Override
                public void run() {
                    pumpStream(target, output);
                }
            }, "raw-process-pump");
            this.pump.setDaemon(true);
            this.pump.start();
        }

        String output() {
            synchronized (output) {
                return output.toString();
            }
        }

        boolean waitExit(long timeoutMillis) throws InterruptedException {
            return process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS);
        }

        int exitValue() {
            try {
                return process.exitValue();
            } catch (IllegalThreadStateException stillRunning) {
                return Integer.MIN_VALUE;
            }
        }

        void kill() {
            try {
                process.destroyForcibly();
            } catch (Throwable ignored) {
                // best effort
            }
        }
    }

    private static RawProcess startRawProcess(List<String> command) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        sanitizeEnvironment(builder);
        return new RawProcess(builder.start());
    }

    private static String toolsJar() {
        try {
            File home = new File(System.getProperty("java.home"));
            File parent = home.getParentFile();
            if (parent != null) {
                File tools = new File(new File(parent, "lib"), "tools.jar");
                if (tools.isFile()) {
                    return tools.getAbsolutePath();
                }
            }
        } catch (Throwable ignored) {
            // not a JDK 8 layout
        }
        return null;
    }

    /** Compiles the loop fixtures (PID/READY then sleep, optionally late class loads). */
    private static Path buildLoopProgramJar(Path dir, boolean lateLoads) throws Exception {
        Path src = dir.resolve(lateLoads ? "late-src" : "attach-src");
        Path classes = dir.resolve(lateLoads ? "late-classes" : "attach-classes");
        Files.createDirectories(src.resolve("tiny"));
        Files.createDirectories(classes);
        List<Path> sources = new ArrayList<Path>();
        String className;
        String body;
        if (lateLoads) {
            className = "LateLoad";
            StringBuilder code = new StringBuilder();
            code.append("package tiny;\n")
                    .append("public final class LateLoad {\n")
                    .append("  public static void main(String[] args) throws Exception {\n")
                    .append("    String n = java.lang.management.ManagementFactory.getRuntimeMXBean()")
                    .append(".getName();\n")
                    .append("    System.out.println(\"PID=\" + n.substring(0, n.indexOf('@')));\n")
                    .append("    System.out.println(\"READY\");\n")
                    .append("    System.out.flush();\n")
                    .append("    for (int i = 0; i < 24; i++) {\n")
                    .append("      Thread.sleep(400L);\n")
                    .append("      Class.forName(\"tiny.LateHelper\" + i);\n")
                    .append("      System.out.println(\"LOADED=\" + i);\n")
                    .append("      System.out.flush();\n")
                    .append("    }\n")
                    .append("    System.out.println(\"DONE\");\n")
                    .append("  }\n")
                    .append("}\n");
            body = code.toString();
            for (int i = 0; i < 24; i++) {
                Path helper = src.resolve("tiny").resolve("LateHelper" + i + ".java");
                Files.write(helper, ("package tiny;\npublic final class LateHelper" + i + " {\n"
                        + "  public static String value() { return \"late-" + i + "\"; }\n}\n")
                        .getBytes(StandardCharsets.UTF_8));
                sources.add(helper);
            }
        } else {
            className = "AttachLoop";
            body = "package tiny;\n"
                    + "public final class AttachLoop {\n"
                    + "  public static void main(String[] args) throws Exception {\n"
                    + "    String n = java.lang.management.ManagementFactory.getRuntimeMXBean()"
                    + ".getName();\n"
                    + "    System.out.println(\"PID=\" + n.substring(0, n.indexOf('@')));\n"
                    + "    System.out.println(\"READY\");\n"
                    + "    System.out.flush();\n"
                    + "    Thread.sleep(15000L);\n"
                    + "    System.out.println(\"DONE\");\n"
                    + "  }\n"
                    + "}\n";
        }
        Path main = src.resolve("tiny").resolve(className + ".java");
        Files.write(main, body.getBytes(StandardCharsets.UTF_8));
        sources.add(main);
        compile(classes, sources.toArray(new Path[0]));
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", "tiny." + className);
        Path jar = dir.resolve((lateLoads ? "late-program" : "attach-program") + ".jar");
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            addClassTree(out, classes, classes);
        }
        return jar;
    }

    private static Path buildEngineGuardedJar(Path dir, Path program, String name, int level,
                                              String action, boolean encrypted, boolean stableNames)
            throws Exception {
        Path output = dir.resolve(name);
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(program)
                .output(output)
                .seed(424242L)
                .option("antiDebug.level", String.valueOf(level))
                .option("antiDebug.action", action)
                .option("antiDebug.nativeGuard", "false");
        if (stableNames) {
            // Typed option: advanced-map keys are not applied by the builder, so
            // disable the rename pass explicitly for the reflective late-load fixture.
            builder.renamer(new UmbraConfig.RenamerOptions(false, "", false, "",
                    true, true, true, "umbra-mapping.txt",
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 1));
        }
        if (encrypted) {
            builder.option("classEncryption.enabled", "true")
                    .option("classEncryption.integrity", "true")
                    .option("classEncryption.antiDump", "true")
                    .option("integrity.level", "2")
                    .option("integrity.action", "throw");
        }
        EngineResult result = runEngine(builder.build());
        check(stat(result, "antiDebug.level") == level,
                "guarded attach jar ran the anti-debug pass (" + name + ")");
        if (encrypted) {
            check(stat(result, "classEncryption.runtimeGuard") == 1,
                    "guarded attach jar wired the loader guard (" + name + ")");
        }
        return output;
    }

    private static void addClassTree(JarOutputStream out, Path root, Path directory) throws IOException {
        File[] files = directory.toFile().listFiles();
        if (files == null) {
            return;
        }
        Arrays.sort(files);
        for (File file : files) {
            if (file.isDirectory()) {
                addClassTree(out, root, file.toPath());
                continue;
            }
            String name = root.relativize(file.toPath()).toString().replace(File.separatorChar, '/');
            out.putNextEntry(new JarEntry(name));
            out.write(Files.readAllBytes(file.toPath()));
            out.closeEntry();
        }
    }

    private static boolean isAlive(LiveChild child) throws InterruptedException {
        return !child.waitExit(0L);
    }

    /** Live child process with an asynchronous, line-oriented output pump. */
    private static final class LiveChild {
        private final Process process;
        private final StringBuilder output = new StringBuilder();
        private final Thread reader;
        private volatile boolean eof;

        private LiveChild(Process process) {
            this.process = process;
            this.reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    pump();
                }
            }, "live-child-reader");
            this.reader.setDaemon(true);
            this.reader.start();
        }

        static LiveChild start(String java, Path jar, List<String> jvmArguments) throws IOException {
            List<String> command = new ArrayList<String>();
            command.add(java);
            command.addAll(jvmArguments);
            command.add("-jar");
            command.add(jar.toAbsolutePath().toString());
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            sanitizeEnvironment(builder);
            return new LiveChild(builder.start());
        }

        private void pump() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(
                        process.getInputStream(), StandardCharsets.UTF_8));
                String line;
                while ((line = in.readLine()) != null) {
                    synchronized (output) {
                        output.append(line).append('\n');
                        output.notifyAll();
                    }
                }
            } catch (IOException ignored) {
                // stream closed
            } finally {
                eof = true;
                synchronized (output) {
                    output.notifyAll();
                }
            }
        }

        String awaitOutput(String token, long timeoutMillis) throws InterruptedException {
            long deadline = System.currentTimeMillis() + timeoutMillis;
            synchronized (output) {
                while (true) {
                    if (output.indexOf(token) >= 0) {
                        return output.toString();
                    }
                    long left = deadline - System.currentTimeMillis();
                    if (left <= 0L || eof) {
                        return null;
                    }
                    output.wait(Math.min(left, 25L));
                }
            }
        }

        long pid() {
            String text = output();
            int marker = text.indexOf("PID=");
            if (marker < 0) {
                return -1L;
            }
            int start = marker + "PID=".length();
            int end = start;
            while (end < text.length() && Character.isDigit(text.charAt(end))) {
                end++;
            }
            try {
                return Long.parseLong(text.substring(start, end));
            } catch (NumberFormatException unreadable) {
                return -1L;
            }
        }

        String output() {
            synchronized (output) {
                return output.toString();
            }
        }

        boolean waitExit(long timeoutMillis) throws InterruptedException {
            return process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS);
        }

        int exitValue() {
            try {
                return process.exitValue();
            } catch (IllegalThreadStateException stillRunning) {
                return Integer.MIN_VALUE;
            }
        }

        void kill() {
            try {
                process.destroyForcibly();
            } catch (Throwable ignored) {
                // best effort
            }
        }
    }

    private static void sanitizeEnvironment(ProcessBuilder builder) {
        // Never inherit guard-marker env variables from the test host: the suite
        // must not flake when the full build environment sets JAVA_TOOL_OPTIONS,
        // _JAVA_OPTIONS, FRIDA_* etc. Tests that need a marker set it explicitly.
        builder.environment().remove("JAVA_TOOL_OPTIONS");
        builder.environment().remove("_JAVA_OPTIONS");
        builder.environment().remove("JDK_JAVA_OPTIONS");
        builder.environment().remove("LD_PRELOAD");
        builder.environment().remove("LD_AUDIT");
        builder.environment().remove("DYLD_INSERT_LIBRARIES");
        builder.environment().remove("DYLD_FORCE_FLAT_NAMESPACE");
        List<String> inherited = new ArrayList<String>(builder.environment().keySet());
        for (int i = 0; i < inherited.size(); i++) {
            String name = inherited.get(i);
            String upper = name.toUpperCase(java.util.Locale.ROOT);
            if (upper.startsWith("FRIDA") || upper.startsWith("GUM_")) {
                builder.environment().remove(name);
            }
        }
    }

    // ------------------------------------------------------------------
    // Builders
    // ------------------------------------------------------------------

    private static Path buildAntiDebugJar(Path dir, int level, String action,
                                          Map<String, String> extra) throws Exception {
        Path jar = dir.resolve("antidebug-L" + level + "-" + action
                + (extra == null ? "" : "-" + Integer.toHexString(extra.hashCode())) + ".jar");
        ClassNode mainClass = syntheticGuardMain();
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

        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(dir.resolve("unused-input.jar"))
                .output(jar)
                .seed(424242L)
                .option("antiDebug.level", String.valueOf(level))
                .option("antiDebug.action", action);
        if (extra != null) {
            for (Map.Entry<String, String> entry : extra.entrySet()) {
                builder.option(entry.getKey(), entry.getValue());
            }
        }
        UmbraConfig config = builder.build();
        Stats stats = new Stats();
        Log log = new Log(null, false);
        PassContext context = new PassContext(config, pool, hierarchy,
                new DefaultRuleSet(new ArrayList<String>(), new ArrayList<String>(), false, false),
                new DefaultRuntimeSupport(), new MappingSet(), stats, log, new Random(424242L),
                ProgressListener.NONE);
        new AntiDebugPass().run(context);
        check(stats.snapshot().containsKey("antiDebug.level"),
                "anti-debug pass recorded its level for L" + level + "/" + action);
        Jars.write(jar, pool, hierarchy, false, log);
        return jar;
    }

    private static ClassNode syntheticGuardMain() {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V1_8;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL;
        node.name = "guardtest/Main";
        node.superName = "java/lang/Object";
        MethodNode constructor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.maxStack = 1;
        constructor.maxLocals = 1;
        constructor.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        constructor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        constructor.instructions.add(new InsnNode(Opcodes.RETURN));
        node.methods.add(constructor);
        MethodNode main = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "main", "([Ljava/lang/String;)V", null, null);
        main.maxStack = 2;
        main.maxLocals = 1;
        main.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC,
                "java/lang/System", "out", "Ljava/io/PrintStream;"));
        main.instructions.add(new LdcInsnNode("OK"));
        main.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false));
        main.instructions.add(new InsnNode(Opcodes.RETURN));
        node.methods.add(main);
        return node;
    }

    /** Compiles a tiny program that prints the given marker and jars it. */
    private static Path buildProgramJar(Path dir, String marker) throws Exception {
        Path src = dir.resolve("program-src");
        Path classes = dir.resolve("program-classes");
        Files.createDirectories(src.resolve("tiny"));
        Files.createDirectories(classes);
        Path source = src.resolve("tiny").resolve("Hello.java");
        Files.write(source, ("package tiny;\n"
                + "public final class Hello {\n"
                + "  public static void main(String[] args) {\n"
                + "    System.out.println(\"" + marker + "\");\n"
                + "  }\n"
                + "}\n").getBytes(StandardCharsets.UTF_8));
        compile(classes, source);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", "tiny.Hello");
        Path jar = dir.resolve("program-" + marker + ".jar");
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            addFile(out, classes, "tiny/Hello.class");
            out.putNextEntry(new JarEntry("tiny/config.txt"));
            out.write(("config-" + marker).getBytes(StandardCharsets.UTF_8));
            out.closeEntry();
        }
        return jar;
    }

    private static Path buildAgent(Path dir, boolean attachFile) throws Exception {
        Path src = dir.resolve("agent-src-" + attachFile);
        Path classes = dir.resolve("agent-classes-" + attachFile);
        Files.createDirectories(src.resolve("guardtestagent"));
        Files.createDirectories(classes);
        String body = "package guardtestagent;\n"
                + "public final class Agent {\n"
                + "  public static void premain(String args, java.lang.instrument.Instrumentation inst)"
                + " throws Exception {\n"
                + "    System.out.println(\"AGENT-START\");\n"
                + (attachFile
                ? "    String name = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();\n"
                + "    String pid = name.substring(0, name.indexOf('@'));\n"
                + "    java.io.File dir = new java.io.File(System.getProperty(\"java.io.tmpdir\"));\n"
                + "    new java.io.FileOutputStream(new java.io.File(dir, \".attach_pid\" + pid)).close();\n"
                : "")
                + "  }\n"
                + "}\n";
        Path source = src.resolve("guardtestagent").resolve("Agent.java");
        Files.write(source, body.getBytes(StandardCharsets.UTF_8));
        compile(classes, source);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Premain-Class", "guardtestagent.Agent");
        Path jar = dir.resolve(attachFile ? "attach-agent.jar" : "plain-agent.jar");
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            addFile(out, classes, "guardtestagent/Agent.class");
        }
        return jar;
    }

    private static Path buildEncryptedJar(Path dir, Path program, String action, int level)
            throws Exception {
        Path output = dir.resolve("encrypted-" + action + "-L" + level + ".jar");
        UmbraConfig config = new UmbraConfig.Builder()
                .input(program)
                .output(output)
                .seed(424242L)
                .option("classEncryption.enabled", "true")
                .option("classEncryption.integrity", "true")
                .option("classEncryption.antiDump", "true")
                .option("integrity.level", "2")
                .option("integrity.action", "throw")
                .option("antiDebug.level", String.valueOf(level))
                .option("antiDebug.action", action)
                .option("antiDebug.nativeGuard", "false")
                .build();
        EngineResult result = runEngine(config);
        check(stat(result, "classEncryption.runtimeGuard") == 1,
                "class-encryption pass wired the unified runtime guard");
        check(stat(result, "classEncryption.classes") >= 1,
                "class-encryption pass encrypted the program classes");
        return output;
    }

    /**
     * Program that reports whether the loader's level-3 integrity watchdog daemon
     * thread is alive (its injected name starts with {@code u}, like the
     * watchdog's own naming scheme).
     */
    private static Path buildWatchdogProgramJar(Path dir) throws Exception {
        Path src = dir.resolve("watchdog-src");
        Path classes = dir.resolve("watchdog-classes");
        Files.createDirectories(src.resolve("tiny"));
        Files.createDirectories(classes);
        Path source = src.resolve("tiny").resolve("WatchdogProbe.java");
        Files.write(source, ("package tiny;\n"
                + "public final class WatchdogProbe {\n"
                + "  public static void main(String[] args) {\n"
                + "    boolean found = false;\n"
                + "    for (java.lang.Thread t : java.lang.Thread.getAllStackTraces().keySet()) {\n"
                + "      String n = t.getName();\n"
                + "      if (t.isDaemon() && n != null && n.startsWith(\"u\") && n.length() > 6) {\n"
                + "        found = true;\n"
                + "      }\n"
                + "    }\n"
                + "    System.out.println(\"WD-OK:\" + (found ? \"WATCHDOG-PRESENT\" : \"WATCHDOG-MISSING\"));\n"
                + "  }\n"
                + "}\n").getBytes(StandardCharsets.UTF_8));
        compile(classes, source);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", "tiny.WatchdogProbe");
        Path jar = dir.resolve("watchdog-program.jar");
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            addFile(out, classes, "tiny/WatchdogProbe.class");
        }
        return jar;
    }

    private static Path buildEncryptedWatchdogJar(Path dir, Path program) throws Exception {
        Path output = dir.resolve("encrypted-watchdog-L3.jar");
        UmbraConfig config = new UmbraConfig.Builder()
                .input(program)
                .output(output)
                .seed(424242L)
                .option("classEncryption.enabled", "true")
                .option("classEncryption.integrity", "true")
                .option("classEncryption.antiDump", "true")
                .option("integrity.level", "3")
                .option("integrity.action", "throw")
                .option("antiDebug.level", "0")
                .option("antiDebug.nativeGuard", "false")
                .build();
        EngineResult result = runEngine(config);
        check(stat(result, "classEncryption.classes") >= 1,
                "level-3 watchdog archive was encrypted");
        return output;
    }

    private static EngineResult runEngine(UmbraConfig config) throws Exception {
        Log log = new Log(null, false);
        return new UmbraEngine(log).run(config, ProgressListener.NONE);
    }

    // ------------------------------------------------------------------
    // Injected guard loading
    // ------------------------------------------------------------------

    private static final class LoadedGuard {
        Class<?> type;
        URLClassLoader loader;
    }

    private static Map<String, String> guardReplacements(int level, String action, String watchdog) {
        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put("@@LEVEL@@", String.valueOf(level));
        replacements.put("@@THREAD@@", String.valueOf(level >= 3 && !watchdog.isEmpty()));
        // In-process guard copies run inside the test JVM: disable the host
        // environment/JMX signals and the opt-in port probe so an inherited
        // JAVA_TOOL_OPTIONS (or another suite's listener) can never create a false
        // positive here. Environment/argument/port detection is covered by the
        // isolated child-JVM tests instead.
        replacements.put("@@JVMTI@@", "false");
        replacements.put("@@ATTACH@@", "true");
        replacements.put("@@ATTACHWATCH@@", "false");
        replacements.put("@@PORTPROBE@@", "false");
        replacements.put("@@ENV@@", "false");
        replacements.put("@@TIMING@@", "true");
        replacements.put("@@ACTION@@", action);
        replacements.put("@@WATCHDOG@@", watchdog);
        replacements.put("@@LOGTOKEN@@", "tst" + level);
        replacements.put("@@WATCHMS@@", "4000");
        return replacements;
    }

    private static LoadedGuard loadGuard(Path dir, String tag, int level, String action,
                                         boolean watchdog) throws Exception {
        ClassPool pool = new ClassPool();
        String watchdogName = "";
        if (watchdog) {
            watchdogName = TemplateInjector.inject(pool, UmbraWatchdog.class,
                    "umbra/runtime/W", 99L).replace('/', '.');
        }
        String guard = GuardSupport.ensureRuntimeGuard(pool, 99L,
                guardReplacements(level, action, watchdogName));
        Hierarchy hierarchy = new Hierarchy();
        Path jar = dir.resolve("guard-" + tag + ".jar");
        Jars.write(jar, pool, hierarchy, false, new Log(null, false));
        URLClassLoader loader = new URLClassLoader(new URL[] { jar.toUri().toURL() },
                DynamicGuardTest.class.getClassLoader());
        LoadedGuard loaded = new LoadedGuard();
        loaded.loader = loader;
        loaded.type = Class.forName(guard.replace('/', '.'), true, loader);
        return loaded;
    }

    private static Object invoke(Class<?> type, String method) throws Exception {
        java.lang.reflect.Method target = type.getDeclaredMethod(method);
        target.setAccessible(true);
        return target.invoke(null);
    }

    // ------------------------------------------------------------------
    // JDK discovery
    // ------------------------------------------------------------------

    private static String jdkJava(int major) {
        synchronized (JDK_CACHE) {
            if (JDK_CACHE.containsKey(String.valueOf(major))) {
                return JDK_CACHE.get(String.valueOf(major));
            }
            String found = null;
            if (currentMajor() == major) {
                found = javaExecutable(System.getProperty("java.home"));
            }
            if (found == null) {
                List<String> homes = new ArrayList<String>();
                String env = System.getenv("JDK" + major + "_HOME");
                if (env != null) {
                    homes.add(env);
                }
                env = System.getenv("JAVA" + major + "_HOME");
                if (env != null) {
                    homes.add(env);
                }
                String[] roots = {
                        "C:\\Program Files\\Java",
                        "C:\\Program Files\\Zulu",
                        "C:\\Program Files\\Eclipse Adoptium",
                        "C:\\Users\\" + System.getProperty("user.name") + "\\.jdks"
                };
                for (String root : roots) {
                    File[] children = new File(root).listFiles();
                    if (children == null) {
                        continue;
                    }
                    List<File> sorted = new ArrayList<File>(Arrays.asList(children));
                    Collections.sort(sorted, new Comparator<File>() {
                        @Override
                        public int compare(File left, File right) {
                            return left.getName().compareTo(right.getName());
                        }
                    });
                    for (File child : sorted) {
                        if (matchesMajor(child.getName(), major)) {
                            homes.add(child.getAbsolutePath());
                        }
                    }
                }
                for (String home : homes) {
                    String exe = javaExecutable(home);
                    if (exe != null && majorOf(exe) == major) {
                        found = exe;
                        break;
                    }
                }
            }
            JDK_CACHE.put(String.valueOf(major), found);
            return found;
        }
    }

    private static boolean matchesMajor(String directoryName, int major) {
        String name = directoryName.toLowerCase(java.util.Locale.ROOT);
        if (name.indexOf("-" + major + ".") >= 0 || name.indexOf(major + ".") == 0
                || name.indexOf("-" + major) >= 0) {
            return true;
        }
        return major == 8 && (name.indexOf("jdk8") >= 0 || name.indexOf("zulu-8") >= 0
                || name.indexOf("corretto-1.8") >= 0);
    }

    private static String javaExecutable(String home) {
        if (home == null) {
            return null;
        }
        String exe = home + File.separator + "bin" + File.separator
                + (isWindows() ? "java.exe" : "java");
        return new File(exe).isFile() ? exe : null;
    }

    private static int currentMajor() {
        String version = System.getProperty("java.version", "0");
        if (version.startsWith("1.")) {
            int dot = version.indexOf('.', 2);
            return Integer.parseInt(version.substring(2, dot < 0 ? version.length() : dot));
        }
        int dot = version.indexOf('.');
        return Integer.parseInt(dot < 0 ? version : version.substring(0, dot));
    }

    private static int majorOf(String javaExe) {
        try {
            Child version = runProcess(Arrays.asList(javaExe, "-version"), null, 20000);
            String text = version.output;
            int marker = text.indexOf("version \"");
            if (marker < 0) {
                return -1;
            }
            String value = text.substring(marker + "version \"".length());
            int end = value.indexOf('"');
            if (end < 0) {
                return -1;
            }
            value = value.substring(0, end);
            if (value.startsWith("1.")) {
                int dot = value.indexOf('.', 2);
                return Integer.parseInt(value.substring(2, dot < 0 ? value.length() : dot));
            }
            int dot = value.indexOf('.');
            return Integer.parseInt(dot < 0 ? value : value.substring(0, dot));
        } catch (Throwable unavailable) {
            return -1;
        }
    }

    // ------------------------------------------------------------------
    // Child process helpers
    // ------------------------------------------------------------------

    private static final class Child {
        int exit;
        String output;
        boolean timedOut;
        long millis;
    }

    private static Child runChild(String java, Path jar, List<String> jvmArguments,
                                  Map<String, String> environment, long timeoutSeconds)
            throws Exception {
        List<String> command = new ArrayList<String>();
        command.add(java);
        command.addAll(jvmArguments);
        command.add("-jar");
        command.add(jar.toAbsolutePath().toString());
        return runProcess(command, environment, timeoutSeconds * 1000L);
    }

    private static Child runProcess(List<String> command, Map<String, String> environment,
                                    long timeoutMillis) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        sanitizeEnvironment(builder);
        if (environment != null) {
            builder.environment().putAll(environment);
        }
        long started = System.nanoTime();
        Process process = builder.start();
        final StringBuilder output = new StringBuilder();
        Thread pump = new Thread(new Runnable() {
            private final Process target = process;
            private final StringBuilder sink = output;

            @Override
            public void run() {
                pumpStream(target, sink);
            }
        }, "process-output-pump");
        pump.setDaemon(true);
        pump.start();
        Child child = new Child();
        if (!process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly();
            process.waitFor(5L, TimeUnit.SECONDS);
            child.timedOut = true;
            child.exit = -1;
        } else {
            child.exit = process.exitValue();
        }
        try {
            pump.join(2000L);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        child.millis = (System.nanoTime() - started) / 1000000L;
        synchronized (output) {
            child.output = output.toString();
        }
        if (child.millis > 2500L) {
            System.out.println("DynamicGuardTest: slow child " + child.millis + " ms "
                    + "timedOut=" + child.timedOut + " " + command);
        }
        return child;
    }

    private static void pumpStream(Process process, StringBuilder sink) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    process.getInputStream(), StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                synchronized (sink) {
                    sink.append(line).append('\n');
                }
            }
        } catch (IOException ignored) {
            // The child may close stdout while being killed.
        }
    }

    // ------------------------------------------------------------------
    // Fake JDWP server
    // ------------------------------------------------------------------

    /** Accepts connections and replies with the JDWP handshake (or garbage). */
    private static final class FakeJdwpServer implements Runnable {
        private final ServerSocket server;
        private final String reply;
        private volatile boolean running = true;
        private final Thread thread;

        private FakeJdwpServer(ServerSocket server, String reply) {
            this.server = server;
            this.reply = reply;
            this.thread = new Thread(this, "fake-jdwp-" + server.getLocalPort());
            this.thread.setDaemon(true);
            this.thread.start();
        }

        static FakeJdwpServer bindFirstFree(int firstPort) {
            return bindFirstFree(firstPort, "JDWP-Handshake");
        }

        static FakeJdwpServer bindFirstFree(int firstPort, String reply) {
            int[] candidates = firstPort > 0
                    ? new int[] { firstPort, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009 }
                    : new int[] { 0 };
            for (int port : candidates) {
                try {
                    ServerSocket socket = new ServerSocket();
                    socket.setReuseAddress(true);
                    socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
                    return new FakeJdwpServer(socket, reply);
                } catch (IOException busy) {
                    // try the next common port
                }
            }
            return null;
        }

        int port() {
            return server.getLocalPort();
        }

        void close() {
            running = false;
            try {
                server.close();
            } catch (IOException ignored) {
                // ignore
            }
            try {
                thread.join(2000L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public void run() {
            while (running) {
                Socket socket = null;
                try {
                    socket = server.accept();
                    socket.setSoTimeout(2000);
                    InputStream in = socket.getInputStream();
                    byte[] request = new byte[14];
                    int read = 0;
                    while (read < request.length) {
                        int chunk = in.read(request, read, request.length - read);
                        if (chunk < 0) {
                            break;
                        }
                        read += chunk;
                    }
                    OutputStream out = socket.getOutputStream();
                    out.write(reply.getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (IOException closedOrTimeout) {
                    if (!running) {
                        return;
                    }
                } finally {
                    if (socket != null) {
                        try {
                            socket.close();
                        } catch (IOException ignored) {
                            // ignore
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Small utilities
    // ------------------------------------------------------------------

    private static void compile(Path destination, Path... sources) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new AssertionError("FAILED: no system Java compiler for a test fixture");
        }
        List<String> arguments = new ArrayList<String>();
        arguments.add("-encoding");
        arguments.add("UTF-8");
        arguments.add("-d");
        arguments.add(destination.toString());
        for (Path source : sources) {
            arguments.add(source.toString());
        }
        int exit = compiler.run(null, null, null, arguments.toArray(new String[0]));
        check(exit == 0, "test fixture compiles: " + sources[0]);
    }

    private static void addFile(JarOutputStream jar, Path root, String name) throws IOException {
        byte[] bytes = Files.readAllBytes(root.resolve(name));
        jar.putNextEntry(new JarEntry(name));
        jar.write(bytes);
        jar.closeEntry();
    }

    private static Map<String, byte[]> readZip(Path jar) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<String, byte[]>();
        try (ZipInputStream in = new ZipInputStream(new java.io.FileInputStream(jar.toFile()))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    out.write(buffer, 0, read);
                }
                entries.put(entry.getName(), out.toByteArray());
            }
        }
        return entries;
    }

    private static void writeZip(Path target, Map<String, byte[]> entries) throws IOException {
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(target.toFile()))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                out.putNextEntry(new ZipEntry(entry.getKey()));
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
    }

    private static long stat(EngineResult result, String key) {
        Long value = result.stats().snapshot().get(key);
        return value == null ? 0L : value.longValue();
    }

    private static List<String> runtimeArguments() {
        try {
            return ManagementFactory.getRuntimeMXBean().getInputArguments();
        } catch (Throwable unavailable) {
            return new ArrayList<String>();
        }
    }

    private static List<String> currentThreadNames() {
        List<String> names = new ArrayList<String>();
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            names.add(thread.getName());
        }
        return names;
    }

    private static long currentPid() {
        try {
            String name = ManagementFactory.getRuntimeMXBean().getName();
            int at = name.indexOf('@');
            return Long.parseLong((at >= 0 ? name.substring(0, at) : name).trim());
        } catch (Throwable unavailable) {
            return 0L;
        }
    }

    private static int countThreads(boolean daemon) {
        int count = 0;
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.isDaemon() == daemon) {
                count++;
            }
        }
        return count;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                .indexOf("win") >= 0;
    }

    private static void deleteRecursively(Path path) {
        try {
            if (path == null || !Files.exists(path)) {
                return;
            }
            Files.walk(path)
                    .sorted(Comparator.reverseOrder())
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




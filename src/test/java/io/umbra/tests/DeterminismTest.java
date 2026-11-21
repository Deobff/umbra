package io.umbra.tests;

import io.umbra.core.api.PassContext;
import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.Presets;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.MappingSet;
import io.umbra.core.engine.Stats;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.runtime.crypto.NativeKeySupport;
import io.umbra.core.util.BuildRoot;
import io.umbra.core.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * The reproducibility contract from ARCHITECTURE.md: "Passes must be
 * <strong>deterministic</strong> for a given {@code ctx.config().seed()}".
 *
 * <p>The contract used to be unenforced and untrue. One run in three produced a
 * different archive from the same seed (measured on {@code demo/demo.jar} with the
 * {@code balanced} preset: 1,272,439 / 1,272,422 / 1,272,417 bytes, 568 of 572
 * entries differing) because the build root and the class-encryption seed came
 * from <em>unseeded</em> {@code SecureRandom} instances. The only assertion that
 * existed compared entry <em>names</em>, which are seed-derived, so it passed.</p>
 *
 * <p>This test compares bytes. It also pins the two implementations of the root
 * derivation together ({@link BuildRoot} on the Java side,
 * {@link NativeKeySupport#ensureBuildRoot} on the bridge side), because the
 * compiled native half has to resolve exactly the same bytes or every payload the
 * loader binds is rejected at run time.</p>
 */
public final class DeterminismTest {

    private static int checks;

    public static void main(String[] args) throws Exception {
        Path demo = Paths.get("demo", "demo.jar");
        if (!Files.isRegularFile(demo)) {
            System.out.println("DeterminismTest: demo/demo.jar not present, skipping");
            return;
        }
        testRootDerivation();
        Path dir = Files.createTempDirectory("umbra-determinism");
        try {
            testReproducibility(demo, dir);
        } finally {
            deleteRecursively(dir);
        }
        System.out.println("DeterminismTest: " + checks + " checks passed");
    }

    /**
     * Both sides of the key root must derive the same bytes for the same seed.
     * Two separate contexts are used on purpose: {@code PassContext.keyRoot()}
     * caches what it published, so reusing one context would hide a disagreement.
     */
    private static void testRootDerivation() throws Exception {
        check(BuildRoot.LABEL.equals(NativeKeySupport.DETERMINISTIC_ROOT_LABEL),
                "BuildRoot label matches the native bridge label");
        check(BuildRoot.BYTES == NativeKeySupport.ROOT_BYTES,
                "BuildRoot key length matches the native bridge root length");

        long[] seeds = { 0L, 1L, 0x5A17L, 424242L, -1L, Long.MIN_VALUE, Long.MAX_VALUE };
        for (long seed : seeds) {
            byte[] viaBridge = NativeKeySupport.ensureBuildRoot(context(seed));
            byte[] viaContext = context(seed).keyRoot();
            check(Arrays.equals(viaBridge, viaContext),
                    "keyRoot() and ensureBuildRoot() agree for seed " + seed);
            check(Arrays.equals(viaContext, BuildRoot.derive(seed)),
                    "keyRoot() is the documented derivation for seed " + seed);
        }
        check(!Arrays.equals(BuildRoot.derive(1L), BuildRoot.derive(2L)),
                "different seeds derive different build roots");
    }

    private static void testReproducibility(Path demo, Path dir) throws Exception {
        Path first = dir.resolve("seed-424242-a.jar");
        Path second = dir.resolve("seed-424242-b.jar");
        Path otherSeed = dir.resolve("seed-999.jar");

        // Two independent JVM builds, exactly the way the CLI/plugins run it. An
        // in-process pair would share static caches (runtime package, key root,
        // template names) that a real single-shot build never reuses, and it misses
        // unseeded sources in static initializers - the reason the MBA coefficient
        // cache could drift per process without this test noticing.
        protectInChildProcess(demo, first, 424242L);
        protectInChildProcess(demo, second, 424242L);
        protectInChildProcess(demo, otherSeed, 999L);

        Map<String, byte[]> a = readJar(first);
        Map<String, byte[]> b = readJar(second);
        check(a.keySet().equals(b.keySet()),
                "the same seed produces the same entry names (" + a.size() + " entries)");

        List<String> differing = new ArrayList<String>();
        for (Map.Entry<String, byte[]> entry : a.entrySet()) {
            byte[] mirror = b.get(entry.getKey());
            if (mirror == null || !Arrays.equals(entry.getValue(), mirror)) {
                differing.add(entry.getKey() + "[" + entry.getValue().length + "/"
                        + (mirror == null ? -1 : mirror.length) + "]");
            }
        }
        check(differing.isEmpty(),
                "the same seed reproduces every entry byte for byte (differing="
                        + differing.size() + (differing.isEmpty() ? "" : ", e.g. "
                        + limit(differing, 6)) + ")");

        Map<String, byte[]> c = readJar(otherSeed);
        int changed = 0;
        for (Map.Entry<String, byte[]> entry : a.entrySet()) {
            byte[] other = c.get(entry.getKey());
            if (other == null || !Arrays.equals(entry.getValue(), other)) {
                changed++;
            }
        }
        check(changed > 0,
                "a different seed changes the output, so the seed really reaches the passes"
                        + " (" + changed + " entries changed)");
    }

    private static void protectInChildProcess(Path input, Path output, long seed) throws Exception {
        String javaHome = System.getProperty("java.home");
        Path java = Paths.get(javaHome, "bin", isWindows() ? "java.exe" : "java");
        if (!Files.isRegularFile(java)) {
            check(true, "no java launcher available; skipping the cross-process check");
            return;
        }
        String classpath = System.getProperty("java.class.path");
        List<String> command = new ArrayList<String>();
        command.add(java.toString());
        command.add("-cp");
        command.add(classpath);
        command.add("io.umbra.cli.Main");
        command.add("-i");
        command.add(input.toString());
        command.add("-o");
        command.add(output.toString());
        command.add("--seed");
        command.add(String.valueOf(seed));
        command.add("--fixed-time");
        command.add("--no-failure-log");
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        builder.directory(input.toAbsolutePath().getParent().getParent().toFile());
        Process process = builder.start();
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        InputStream stream = process.getInputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = stream.read(buffer)) >= 0) {
            captured.write(buffer, 0, read);
        }
        int code = process.waitFor();
        check(code == 0, "child JVM build exits 0 (exit=" + code + ", output tail="
                + tail(new String(captured.toByteArray(), StandardCharsets.UTF_8)) + ")");
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win");
    }

    private static String tail(String text) {
        String trimmed = text.trim();
        if (trimmed.length() <= 400) {
            return trimmed;
        }
        return trimmed.substring(trimmed.length() - 400);
    }

    private static void protect(Path input, Path output, long seed) throws Exception {
        UmbraConfig base = new UmbraConfig.Builder().seed(seed).build(false);
        UmbraConfig preset = Presets.apply(base, "balanced", false);
        UmbraConfig config = preset.toBuilder().input(input).output(output).build();
        new UmbraEngine(silentLog()).run(config, ProgressListener.NONE);
        check(Files.isRegularFile(output),
                "protection wrote " + output.getFileName() + " for seed " + seed);
    }

    private static PassContext context(long seed) throws Exception {
        UmbraConfig config = new UmbraConfig.Builder().seed(seed).build(false);
        return new PassContext(config, null, null, null, null, new MappingSet(), new Stats(),
                silentLog(), new Random(seed), ProgressListener.NONE);
    }

    private static Log silentLog() {
        return new Log(new Log.Sink() {
            @Override
            public void line(String level, String message) {
            }
        }, false);
    }

    private static Map<String, byte[]> readJar(Path path) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<String, byte[]>();
        JarFile jar = new JarFile(path.toFile());
        try {
            Enumeration<JarEntry> e = jar.entries();
            while (e.hasMoreElements()) {
                JarEntry entry = e.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                InputStream in = jar.getInputStream(entry);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                try {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                    }
                } finally {
                    in.close();
                }
                entries.put(entry.getName(), out.toByteArray());
            }
        } finally {
            jar.close();
        }
        return entries;
    }

    private static String limit(List<String> values, int max) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < values.size() && i < max; i++) {
            if (i > 0) {
                text.append(", ");
            }
            text.append(values.get(i));
        }
        if (values.size() > max) {
            text.append(", ...");
        }
        return text.toString();
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError("DeterminismTest: " + message);
        }
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        if (Files.isDirectory(path)) {
            Files.list(path).forEach(child -> {
                try {
                    deleteRecursively(child);
                } catch (IOException ignored) {
                    ignored.getClass();
                }
            });
        }
        Files.deleteIfExists(path);
    }
}

package io.umbra.core.jni;

import io.umbra.core.util.Log;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Locates a C toolchain (gcc/clang/cc), reads the JNI headers out of the running
 * JDK and compiles the generated translation unit into a shared library.
 */
public final class NativeCompiler {

    private static final long COMPILE_TIMEOUT_SECONDS = 180L;

    /** Result of one compilation attempt. */
    public static final class Result {
        private final boolean success;
        private final Path library;
        private final String command;
        private final String output;
        private final long millis;

        Result(boolean success, Path library, String command, String output, long millis) {
            this.success = success;
            this.library = library;
            this.command = command;
            this.output = output;
            this.millis = millis;
        }

        public boolean success() { return success; }
        public Path library() { return library; }
        /** Human readable command line (arguments quoted when necessary). */
        public String command() { return command; }
        /** Combined stdout/stderr of the compiler. */
        public String output() { return output; }
        public long millis() { return millis; }
    }

    private NativeCompiler() {
    }

    /**
     * Returns the compiler to use or {@code null} when none is available.
     *
     * <p>An explicitly configured compiler is never silently replaced by an
     * auto-detected one: a broken configuration must fail (and let the pass fall
     * back to Java) instead of using a different toolchain.</p>
     */
    public static String resolve(String configured, Log log) {
        if (configured != null && !configured.trim().isEmpty()) {
            String value = configured.trim();
            if (works(value)) {
                return value;
            }
            log.warn("native compiler not found or not executable: %s", value);
            return null;
        }
        List<String> candidates = new ArrayList<String>(Arrays.asList(
                "gcc", "cc", "clang", "g++", "clang++", "tcc"));
        if (File.separatorChar == '\\') {
            candidates.add("C:/Program Files/Zulu/zulu-8/bin/gcc.exe");
        }
        for (String candidate : candidates) {
            if (works(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean works(String compiler) {
        try {
            ProcessBuilder builder = new ProcessBuilder(compiler, "--version");
            builder.redirectErrorStream(true);
            File sink = File.createTempFile("umbra-cc-", ".txt");
            try {
                builder.redirectOutput(sink);
                Process process = builder.start();
                boolean finished = process.waitFor(20L, TimeUnit.SECONDS);
                if (!finished) {
                    process.destroyForcibly();
                    return false;
                }
                return process.exitValue() == 0;
            } finally {
                if (!sink.delete()) {
                    sink.deleteOnExit();
                }
            }
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** JNI header directories of the running JDK, most specific first. */
    public static List<String> jniIncludeDirectories() {
        Set<String> candidates = new LinkedHashSet<String>();
        List<String> homes = new ArrayList<String>();
        String javaHome = System.getProperty("java.home");
        if (javaHome != null) {
            homes.add(javaHome);
            File parent = new File(javaHome).getParentFile();
            if (parent != null) {
                homes.add(parent.getAbsolutePath());
            }
        }
        String envHome = System.getenv("JAVA_HOME");
        if (envHome != null && !envHome.trim().isEmpty()) {
            homes.add(envHome.trim());
        }
        homes.add("C:/Program Files/Zulu/zulu-8");
        for (String home : homes) {
            candidates.add(home + File.separator + "include");
            candidates.add(home + File.separator + "include" + File.separator + "win32");
        }
        List<String> result = new ArrayList<String>();
        Set<String> seen = new LinkedHashSet<String>();
        for (String candidate : candidates) {
            Path path = new File(candidate).toPath();
            if (Files.isDirectory(path)) {
                String absolute = path.toAbsolutePath().toString();
                if (seen.add(absolute)) {
                    result.add(absolute);
                }
            }
        }
        return result;
    }

    /** True when at least one include directory actually contains {@code jni.h}. */
    public static boolean hasJniHeaders() {
        for (String directory : jniIncludeDirectories()) {
            if (Files.isRegularFile(new File(directory, "jni.h").toPath())) {
                return true;
            }
        }
        return false;
    }

    /** Builds the compiler command line for the requested target. */
    public static List<String> command(String compiler, Path source, Path library, String target,
                                       String extraFlags) {
        List<String> command = new ArrayList<String>();
        command.add(compiler);
        String normalized = target == null ? "windows" : target.trim().toLowerCase(java.util.Locale.ROOT);
        if ("linux".equals(normalized)) {
            command.add("-shared");
            command.add("-fPIC");
        } else if ("macos".equals(normalized)) {
            command.add("-dynamiclib");
            command.add("-fPIC");
        } else {
            command.add("-shared");
            command.add("-static-libgcc");
            // Fixed image base + no timestamp make the produced PE image byte-for-byte
            // reproducible for identical input; the linker otherwise randomises the
            // preferred load address and stamps the current time.
            command.add("-Wl,--image-base,0x10000000");
            command.add("-Wl,--no-insert-timestamp");
        }
        command.add("-O2");
        command.add("-fwrapv");
        command.add("-fno-strict-aliasing");
        command.add("-o");
        command.add(library.toAbsolutePath().toString());
        command.add(source.toAbsolutePath().toString());
        for (String include : jniIncludeDirectories()) {
            command.add("-I" + include);
        }
        command.addAll(tokenize(extraFlags));
        return command;
    }

    /** Compiles {@code source} into {@code library}. */
    public static Result compile(String compiler, Path source, Path library, String target,
                                 String extraFlags, Log log) {
        List<String> command = command(compiler, source, library, target, extraFlags);
        long start = System.currentTimeMillis();
        Path logFile = null;
        try {
            logFile = Files.createTempFile("umbra-native-build", ".log");
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            builder.redirectOutput(logFile.toFile());
            Process process = builder.start();
            boolean finished = process.waitFor(COMPILE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            String output;
            if (!finished) {
                process.destroyForcibly();
            }
            output = new String(Files.readAllBytes(logFile), StandardCharsets.UTF_8);
            int exit = finished ? process.exitValue() : -1;
            boolean ok = finished && exit == 0 && Files.isRegularFile(library);
            return new Result(ok, library, render(command), output, System.currentTimeMillis() - start);
        } catch (IOException e) {
            return new Result(false, library, render(command), String.valueOf(e),
                    System.currentTimeMillis() - start);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(false, library, render(command), "interrupted",
                    System.currentTimeMillis() - start);
        } finally {
            if (logFile != null) {
                try {
                    Files.deleteIfExists(logFile);
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }

    /** Splits a flag string on whitespace, honouring double quotes. */
    public static List<String> tokenize(String flags) {
        List<String> tokens = new ArrayList<String>();
        if (flags == null) {
            return tokens;
        }
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < flags.length(); i++) {
            char c = flags.charAt(i);
            if (c == '"') {
                quoted = !quoted;
            } else if (!quoted && Character.isWhitespace(c)) {
                if (current.length() > 0) {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            tokens.add(current.toString());
        }
        return tokens;
    }

    private static String render(List<String> command) {
        StringBuilder out = new StringBuilder();
        for (String argument : command) {
            if (out.length() > 0) {
                out.append(' ');
            }
            if (argument.indexOf(' ') >= 0) {
                out.append('"').append(argument).append('"');
            } else {
                out.append(argument);
            }
        }
        return out.toString();
    }
}

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

    private static final long COMPILE_TIMEOUT_MAX_SECONDS = 1800L;

    private static final long LARGE_UNIT_BYTES = 2L * 1024L * 1024L;

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

        public String command() { return command; }

        public String output() { return output; }
        public long millis() { return millis; }
    }

    private NativeCompiler() {
    }

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

            File sink = File.createTempFile(randomToken(), ".txt");
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

    public static boolean hasJniHeaders() {
        for (String directory : jniIncludeDirectories()) {
            if (Files.isRegularFile(new File(directory, "jni.h").toPath())) {
                return true;
            }
        }
        return false;
    }

    public static List<String> command(String compiler, Path source, Path library, String target,
                                       String extraFlags) {
        return command(compiler, source, library, target, extraFlags, true);
    }

    public static List<String> command(String compiler, Path source, Path library, String target,
                                       String extraFlags, boolean reproducible) {
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

            command.add("-Wl,--image-base,0x10000000");
            if (reproducible) {
                command.add("-Wl,--no-insert-timestamp");
            }
        }
        command.add(optimizationLevel(source));
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

    static long timeoutSeconds(Path source) {
        long bytes = sourceSize(source);
        long scaled = COMPILE_TIMEOUT_SECONDS + (bytes / (1024L * 1024L)) * 4L;
        return Math.min(COMPILE_TIMEOUT_MAX_SECONDS, scaled);
    }

    static String optimizationLevel(Path source) {
        return sourceSize(source) >= LARGE_UNIT_BYTES ? "-O1" : "-O2";
    }

    private static long sourceSize(Path source) {
        try {
            return Files.size(source);
        } catch (IOException e) {

            return 0L;
        }
    }

    public static Result compile(String compiler, Path source, Path library, String target,
                                 String extraFlags, Log log) {
        return compile(compiler, source, library, target, extraFlags, log, true);
    }

    public static Result compile(String compiler, Path source, Path library, String target,
                                 String extraFlags, Log log, boolean reproducible) {
        List<String> command = command(compiler, source, library, target, extraFlags, reproducible);
        long timeoutSeconds = timeoutSeconds(source);
        long start = System.currentTimeMillis();
        Path logFile = null;
        try {
            logFile = Files.createTempFile(randomToken(), ".log");
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            builder.redirectOutput(logFile.toFile());
            Process process = builder.start();
            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            String output;
            if (!finished) {
                process.destroyForcibly();
            }
            output = new String(Files.readAllBytes(logFile), StandardCharsets.UTF_8);
            if (!finished) {

                output = "[timed out after " + timeoutSeconds + "s]\n" + output;
            }
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

                }
            }
        }
    }

    public static String randomToken() {
        return Long.toHexString(java.util.concurrent.ThreadLocalRandom.current().nextLong()
                & 0x7FFFFFFFFFFFFFFFL);
    }

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

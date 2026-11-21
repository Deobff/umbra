package io.umbra.core.util;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Failure context and reporting for a single Umbra run.
 *
 * <p>Umbra used to answer every failure with one line on {@code System.err}
 * ("Umbra failed: ...") and the raw exit code. The desktop console only reads
 * the child's stdout, so a failed run looked like "finished with exit 1" with no
 * reason at all, and an {@link Error} (out of memory, stack overflow) was not
 * even caught. This class keeps the context of the run (phase, pass,
 * progress, the tail of the log) so the CLI can print a reason that names the
 * failing stage and write the same detail to a file the user can reopen later.</p>
 *
 * <p>It is deliberately static: one CLI run per JVM, and the engine, the passes
 * and the CLI entry point all need to write into the same record. All fields are
 * volatile, the report writing never throws, and a failure inside the reporter
 * must never replace the failure it is describing.</p>
 */
public final class FailureReport {

    /** How many recent log lines are kept for the report. */
    private static final int LOG_TAIL = 60;

    /** How many stack frames are printed inline (the file keeps all of them). */
    private static final int INLINE_FRAMES = 12;

    private static volatile Log attachedLog;
    private static volatile String phase = "startup";
    private static volatile String passName;
    private static volatile String passClass;
    private static volatile int percent = -1;
    private static volatile String progressMessage;
    private static volatile long startedAt = System.currentTimeMillis();

    private static final Map<String, String> facts = new LinkedHashMap<String, String>();

    private FailureReport() {
    }

    // ------------------------------------------------------------------ context

    /** Clears the record before a run; called by the CLI and the engine. */
    public static void reset() {
        phase = "startup";
        passName = null;
        passClass = null;
        percent = -1;
        progressMessage = null;
        startedAt = System.currentTimeMillis();
        synchronized (facts) {
            facts.clear();
        }
    }

    /** Records the current stage: load, hierarchy, pass, write, post, verify, report. */
    public static void phase(String name) {
        phase = name;
    }

    /** Records the pass that is running right now. */
    public static void pass(String name) {
        passName = name == null || name.isEmpty() ? null : name;
        passClass = null;
    }

    /** Records the last progress tick so a hang or a crash points at a stage. */
    public static void progress(int value, String message) {
        percent = value;
        progressMessage = message;
    }

    /** Reads a fact back (used for the recorded command line). */
    public static String fact(String key) {
        if (key == null) {
            return "";
        }
        synchronized (facts) {
            String value = facts.get(key);
            return value == null ? "" : value;
        }
    }

    /** Keeps a named fact (input, output, seed, preset, ...) for the report. */
    public static void fact(String key, String value) {
        if (key == null) {
            return;
        }
        synchronized (facts) {
            facts.put(key, value == null ? "" : value);
        }
    }

    /** The log whose tail is attached to a failure report. */
    public static void attachLog(Log log) {
        attachedLog = log;
    }

    public static String phase() {
        return phase;
    }

    public static String passName() {
        return passName;
    }

    public static long startedAt() {
        return startedAt;
    }

    /** One line that says where the run was when it died. */
    public static String contextLine() {
        StringBuilder out = new StringBuilder();
        out.append("phase: ").append(phase);
        if (passName != null) {
            out.append(" / pass ").append(passName);
            if (passClass != null && !passClass.isEmpty()) {
                out.append(" (").append(passClass).append(')');
            }
        }
        if (percent >= 0) {
            out.append(" / progress ").append(percent).append('%');
            if (progressMessage != null && !progressMessage.isEmpty()) {
                out.append(" \"").append(progressMessage).append('"');
            }
        }
        return out.toString();
    }

    // -------------------------------------------------------------- exceptions

    /** The deepest cause, which is nearly always the interesting one. */
    public static Throwable rootCause(Throwable failure) {
        Throwable current = failure;
        int guard = 0;
        while (current != null && guard++ < 32) {
            Throwable next = current.getCause();
            if (next == null || next == current) {
                return current;
            }
            current = next;
        }
        return current == null ? failure : current;
    }

    /** "java.io.FileSystemException: The process cannot access the file" */
    public static String causeLine(Throwable failure) {
        Throwable root = rootCause(failure);
        String message = root.getMessage();
        String type = root.getClass().getName();
        if (message == null || message.trim().isEmpty()) {
            return type;
        }
        return type + ": " + collapse(message);
    }

    /** Human hint for the failure classes Umbra actually sees in the field. */
    public static String hint(Throwable failure) {
        Throwable root = rootCause(failure);
        String type = root.getClass().getName();
        String message = root.getMessage() == null ? "" : root.getMessage().toLowerCase(Locale.ROOT);
        Runtime runtime = Runtime.getRuntime();
        long maxMb = runtime.maxMemory() / (1024L * 1024L);
        if (failure instanceof OutOfMemoryError || type.endsWith("OutOfMemoryError")) {
            return "the JVM ran out of memory (max " + maxMb + " MB). Re-run with a larger heap, "
                    + "for example java -Xmx8g -jar umbra.jar ... (on a 64-bit JDK), or protect fewer "
                    + "classes at once / disable the heaviest passes (virtualization, class encryption)";
        }
        if (failure instanceof StackOverflowError || type.endsWith("StackOverflowError")) {
            return "the transform recursed too deep (max " + maxMb + " MB heap). Raise the thread stack "
                    + "with -Xss4m and re-run; if it persists, the failing pass needs a depth limit";
        }
        if (type.endsWith("ZipException") || message.contains("zip file is empty")
                || message.contains("invalid entry") || message.contains("error in opening zip file")) {
            return "an archive is not a readable JAR: it is truncated, corrupted or not a ZIP at all "
                    + "(check the -i input and the input libraries)";
        }
        if (message.contains("too many operations") || message.contains("method too large")
                || message.contains("exceeds the jvm's 64 kb") || message.contains("64 kb limit")) {
            return "a method grew past the JVM's 64 KB bytecode limit while it was being obfuscated. "
                    + "Umbra restores such a method's original body automatically; when even that does "
                    + "not fit, lower the body transforms for this archive "
                    + "(flowObfuscation.level=light, exception.level=1, flow.maxBlocks, "
                    + "methodVirtualization.enabled=false) and re-run";
        }
        if (message.contains("native key binding could not be established")) {
            return "the native key bridge is compiled at build time by a C toolchain (gcc/clang). "
                    + "Install one, make sure %TEMP% is writable and not blocked by the antivirus, and "
                    + "re-run; if the toolchain is not available on this machine, set "
                    + "--set classEncryption.nativeKey.fallback=true to accept the seed key explicitly, "
                    + "or --set classEncryption.nativeKey=false to disable the native binding";
        }
        if (message.contains("class encryption cannot seal")) {
            return "this is a layout limitation, not a crash: the input is a multi-release, module-info or "
                    + "nested archive that class encryption cannot seal. Either add "
                    + "--set classEncryption.allowSkip=true (ship it with class encryption OFF but renaming, "
                    + "flow and string encryption still applied), disable it with "
                    + "--set classEncryption.enabled=false, or use a preset without class encryption";
        }
        if (message.contains("being used by another process") || message.contains("另一个程序")
                || message.contains("cannot access the file") || message.contains("拒绝访问")
                || message.contains("access is denied")) {
            return "a file is locked by another process: close the running protected jar, the IDE, "
                    + "the decompiler or the antivirus scan holding -o, or write to a different path";
        }
        if (type.endsWith("NoSuchFileException") || type.endsWith("FileNotFoundException")) {
            return "a path does not exist: check -i / -o / --lib (relative paths resolve against the "
                    + "current working directory)";
        }
        if (message.contains("no space left") || message.contains("磁盘空间")) {
            return "the disk holding the output is full";
        }
        if (type.endsWith("AccessDeniedException")) {
            return "the output (or a temporary file next to it) cannot be written: close whatever holds "
                    + "it, or pick a writable -o directory";
        }
        if (type.endsWith("ConfigException")) {
            return "the configuration is rejected before any transform ran; fix the option named in the message";
        }
        if (type.endsWith("LicenseException")) {
            return "the enterprise license is missing or invalid (exit code 3)";
        }
        return "re-run the same command with -v; the failure report next to the output has the full stack, "
                + "the effective configuration and the tail of the run log";
    }

    // ------------------------------------------------------------------- render

    /**
     * Prints the compact failure block to {@code target}. Every line is prefixed
     * so a log scraper can find it; the message is intentionally short enough to
     * read in a console.
     */
    public static void render(PrintStream target, String summary, Throwable failure) {
        if (target == null) {
            return;
        }
        try {
            target.println("[ERROR] " + summary);
            target.println("[ERROR]   " + contextLine());
            if (failure != null) {
                target.println("[ERROR]   cause: " + causeLine(failure));
                String[] frames = shortStack(failure).split("\\r?\\n");
                for (String frame : frames) {
                    if (frame.trim().isEmpty()) {
                        continue;
                    }
                    target.println("[ERROR]   " + frame);
                }
            }
            target.println("[ERROR]   hint: " + hint(failure));
            target.flush();
        } catch (Throwable ignored) {
            
        }
    }

    /**
     * Writes the full failure report next to {@code target} (or into the current
     * directory when it is null) and returns the file, or null when even that
     * could not be done.
     */
    public static Path write(Path target, String variant, String summary, Throwable failure,
                             int exitCode, String version, String commandLine) {
        return write(target, variant, summary, failure, exitCode, version, commandLine, null);
    }

    /**
     * Same as the seven argument form, but appends caller supplied lines (for
     * example the class list of a failed verification) before the log tail.
     */
    public static Path write(Path target, String variant, String summary, Throwable failure,
                             int exitCode, String version, String commandLine,
                             List<String> extra) {
        try {
            Path directory = directoryFor(target);
            if (directory == null) {
                return null;
            }
            Files.createDirectories(directory);
            String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
            String name = baseName(target, variant) + ".failure-" + stamp + ".log";
            Path file = directory.resolve(name);
            StringBuilder out = new StringBuilder();
            out.append("Umbra failure report").append('\n');
            out.append("=====================").append('\n');
            out.append("version...   : ").append(version == null ? "?" : version).append('\n');
            out.append("time.......  : ").append(new Date().toString()).append('\n');
            out.append("exit code..  : ").append(exitCode).append('\n');
            out.append("elapsed....  : ").append(System.currentTimeMillis() - startedAt).append(" ms\n");
            out.append("summary....  : ").append(summary).append('\n');
            out.append("context....  : ").append(contextLine()).append('\n');
            if (failure != null) {
                out.append("cause......  : ").append(causeLine(failure)).append('\n');
            }
            out.append("command....  : ").append(commandLine == null ? "?" : commandLine).append('\n');
            out.append('\n').append("-- facts ").append(repeat('-', 60)).append('\n');
            synchronized (facts) {
                for (Map.Entry<String, String> entry : facts.entrySet()) {
                    out.append(pad(entry.getKey(), 20)).append(": ").append(entry.getValue()).append('\n');
                }
            }
            out.append('\n').append("-- environment ").append(repeat('-', 52)).append('\n');
            appendProperty(out, "java.version", System.getProperty("java.version"));
            appendProperty(out, "java.vm.name", System.getProperty("java.vm.name"));
            appendProperty(out, "java.vendor", System.getProperty("java.vendor"));
            appendProperty(out, "os.name", System.getProperty("os.name"));
            appendProperty(out, "os.arch", System.getProperty("os.arch"));
            appendProperty(out, "file.encoding", System.getProperty("file.encoding"));
            appendProperty(out, "sun.stdout.encoding", System.getProperty("sun.stdout.encoding"));
            appendProperty(out, "sun.stderr.encoding", System.getProperty("sun.stderr.encoding"));
            appendProperty(out, "user.dir", System.getProperty("user.dir"));
            appendProperty(out, "java.io.tmpdir", System.getProperty("java.io.tmpdir"));
            appendProperty(out, "java.class.path", System.getProperty("java.class.path"));
            Runtime runtime = Runtime.getRuntime();
            out.append(pad("memory", 20)).append(": max ")
                    .append(runtime.maxMemory() / (1024L * 1024L)).append(" MB, total ")
                    .append(runtime.totalMemory() / (1024L * 1024L)).append(" MB, free ")
                    .append(runtime.freeMemory() / (1024L * 1024L)).append(" MB")
                    .append('\n');
            if (failure != null) {
                out.append('\n').append("-- stack ").append(repeat('-', 56)).append('\n');
                out.append(fullStack(failure));
            }
            if (extra != null && !extra.isEmpty()) {
                out.append('\n').append("-- details ").append(repeat('-', 54)).append('\n');
                for (String line : extra) {
                    out.append(line).append('\n');
                }
            }
            out.append('\n').append("-- log tail ").append(repeat('-', 52)).append('\n');
            for (String line : logTail()) {
                out.append(line).append('\n');
            }
            Files.write(file, out.toString().getBytes(Charset.forName("UTF-8")));
            return file;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void appendProperty(StringBuilder out, String key, String value) {
        out.append(pad(key, 20)).append(": ").append(value == null ? "?" : value).append('\n');
    }

    private static String pad(String value, int width) {
        StringBuilder out = new StringBuilder(value == null ? "" : value);
        while (out.length() < width) {
            out.append(' ');
        }
        return out.toString();
    }

    private static String repeat(char value, int count) {
        StringBuilder out = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            out.append(value);
        }
        return out.toString();
    }

    /**
     * Directory the report lands in: next to the output archive when the run had
     * one, otherwise the working directory. The input directory is deliberately
     * never used - it is the user's project, and a failed run must not drop
     * files there.
     */
    private static Path directoryFor(Path target) {
        Path path = target;
        if (path == null) {
            String output = fact("output");
            if (output == null || output.isEmpty()) {
                return Paths.get(System.getProperty("user.dir", "."));
            }
            path = Paths.get(output);
        }
        Path absolute = path.toAbsolutePath();
        if (Files.isDirectory(absolute)) {
            return absolute;
        }
        Path parent = absolute.getParent();
        return parent == null ? absolute : parent;
    }

    private static String baseName(Path target, String variant) {
        String name = "umbra";
        Path path = target;
        if (path == null) {
            String output = fact("output");
            if (output != null && !output.isEmpty()) {
                path = Paths.get(output);
            }
        }
        if (path != null && path.getFileName() != null) {
            name = path.getFileName().toString();
            int dot = name.lastIndexOf('.');
            if (dot > 0) {
                name = name.substring(0, dot);
            }
        }
        if (variant != null && !variant.isEmpty()) {
            return name + "-" + variant;
        }
        return name;
    }

    /** The tail of the run log, newest last. */
    private static List<String> logTail() {
        Log log = attachedLog;
        if (log == null) {
            return new ArrayList<String>();
        }
        try {
            return log.tail(LOG_TAIL);
        } catch (Throwable ignored) {
            return new ArrayList<String>();
        }
    }

    // ------------------------------------------------------------------- stacks

    /** The first frames of the deepest cause chain, for the console block. */
    private static String shortStack(Throwable failure) {
        StringWriter buffer = new StringWriter();
        PrintWriter writer = new PrintWriter(buffer);
        Throwable current = failure;
        int chain = 0;
        while (current != null && chain++ < 4) {
            writer.println(current.getClass().getName()
                    + (current.getMessage() == null ? "" : ": " + collapse(current.getMessage())));
            StackTraceElement[] frames = current.getStackTrace();
            int limit = Math.min(frames.length, INLINE_FRAMES);
            for (int i = 0; i < limit; i++) {
                writer.println("  at " + frames[i]);
            }
            if (frames.length > limit) {
                writer.println("  ... " + (frames.length - limit) + " more");
            }
            Throwable next = current.getCause();
            if (next != null && next != current) {
                writer.println("Caused by:");
            }
            current = next;
        }
        writer.flush();
        return buffer.toString();
    }

    /** The complete stack, causes first class last, for the report file. */
    public static String fullStack(Throwable failure) {
        if (failure == null) {
            return "";
        }
        StringWriter buffer = new StringWriter();
        PrintWriter writer = new PrintWriter(buffer);
        failure.printStackTrace(writer);
        Throwable suppressed = failure;
        int guard = 0;
        while (suppressed != null && guard++ < 8) {
            Throwable[] entries = suppressed.getSuppressed();
            for (Throwable entry : entries) {
                writer.println("Suppressed: " + entry);
                entry.printStackTrace(writer);
            }
            suppressed = suppressed.getCause();
        }
        writer.flush();
        return buffer.toString();
    }

    private static String collapse(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\r', ' ').replace('\n', ' ');
    }
}

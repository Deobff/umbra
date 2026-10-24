package io.umbra.tool;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Dependency-free helper that runs the Umbra CLI as a child process.
 *
 * <p>This class is intentionally duplicated (identical source) in the Gradle
 * and Maven plugins: it only uses the JDK so neither plugin drags the Umbra
 * runtime, ASM or any other library onto the build classpath.</p>
 *
 * <p>The command is built as an argument vector and handed to
 * {@link ProcessBuilder}; no shell is involved, so paths and values with
 * spaces, quotes or shell metacharacters are passed through verbatim and
 * cannot be re-interpreted.</p>
 *
 * <p>Contract relied upon (stable since Umbra 2.0):</p>
 * <pre>
 * java -jar umbra.jar -i &lt;input.jar&gt; -o &lt;output.jar&gt; [-c &lt;config.yml&gt;]
 *      [--preset &lt;name&gt;] [--seed &lt;n&gt;] [--keep &lt;rule&gt;]...
 *      [--set k=v]... [--verify]
 * </pre>
 *
 * <p>Exit codes: 0 success, 1 configuration/transform failure, 2 JVM
 * verification failure (only with {@code --verify}), 3 license failure.</p>
 */
public final class CliRunner {

    /** Environment variable used as the default Umbra tool jar location. */
    public static final String ENV_TOOL_JAR = "UMBRA_JAR";

    /** Mapping file name the CLI writes next to the output jar. */
    public static final String DEFAULT_MAPPING_FILE = "umbra-mapping.txt";

    /** Receives one line of combined stdout/stderr output at a time. */
    public interface LineSink {
        void line(String line);
    }

    /** Outcome of one CLI invocation. */
    public static final class Result {
        private final int exitCode;
        private final List<String> tail;
        private final File logFile;

        private Result(int exitCode, List<String> tail, File logFile) {
            this.exitCode = exitCode;
            this.tail = tail;
            this.logFile = logFile;
        }

        /** Process exit code; 0 means success. */
        public int exitCode() {
            return exitCode;
        }

        /** Last lines of output, for error messages. */
        public List<String> tail() {
            return tail;
        }

        /** Log file the output was duplicated to, or {@code null}. */
        public File logFile() {
            return logFile;
        }

        public boolean isSuccess() {
            return exitCode == 0;
        }
    }

    private CliRunner() {
    }

    /** True on Windows, used only to pick {@code java.exe} vs {@code java}. */
    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).indexOf("win") >= 0;
    }

    /** Java executable of the JVM currently running the build. */
    public static File defaultJavaExecutable() {
        String home = System.getProperty("java.home");
        if (home == null || home.trim().isEmpty()) {
            return new File(isWindows() ? "java.exe" : "java");
        }
        return javaExecutable(new File(home));
    }

    /**
     * Resolves the Java launcher.
     *
     * @param javaHome explicit JDK/JRE home directory, or {@code null} to use
     *                 the JVM that runs the build
     */
    public static File resolveJava(File javaHome) {
        if (javaHome == null) {
            return defaultJavaExecutable();
        }
        File executable = javaExecutable(javaHome);
        if (!executable.isFile()) {
            throw new IllegalArgumentException(
                    "javaHome does not contain a Java launcher: " + executable.getAbsolutePath());
        }
        return executable;
    }

    private static File javaExecutable(File javaHome) {
        File bin = new File(javaHome, "bin");
        return new File(bin, isWindows() ? "java.exe" : "java");
    }

    /**
     * Default tool jar from the {@code UMBRA_JAR} environment variable, or
     * {@code null} when unset. Build scripts normally set the path explicitly.
     */
    public static File defaultToolJar() {
        String env = System.getenv(ENV_TOOL_JAR);
        if (env == null || env.trim().isEmpty()) {
            return null;
        }
        return new File(env.trim());
    }

    /**
     * Builds the CLI argument vector.
     *
     * @param javaExecutable Java launcher (see {@link #resolveJava(File)})
     * @param toolJar        path to {@code umbra.jar}
     * @param input          input jar, must exist
     * @param output         protected output jar; parent directories are created
     * @param config         optional YAML configuration
     * @param preset         optional preset name
     * @param seed           optional deterministic seed
     * @param keep           keep rules (may be {@code null})
     * @param options        advanced options; entries of the form
     *                       {@code key=value} become {@code --set key=value},
     *                       entries starting with {@code -} are passed through
     *                       verbatim (split on whitespace, no shell)
     * @param verify         add {@code --verify}
     */
    public static List<String> buildCommand(File javaExecutable, File toolJar, File input, File output,
                                            File config, String preset, Long seed, List<String> keep,
                                            List<String> options, boolean verify) {
        requireReadableFile(javaExecutable, "java executable");
        requireReadableFile(toolJar, "umbra tool jar (toolJar)");
        requireReadableFile(input, "input jar");
        if (output == null) {
            throw new IllegalArgumentException("output jar is not configured");
        }
        if (config != null) {
            requireReadableFile(config, "config file");
        }

        List<String> command = new ArrayList<String>();
        command.add(javaExecutable.getAbsolutePath());
        command.add("-jar");
        command.add(toolJar.getAbsoluteFile().getPath());
        command.add("-i");
        command.add(input.getAbsoluteFile().getPath());
        command.add("-o");
        command.add(output.getAbsoluteFile().getPath());
        if (config != null) {
            command.add("-c");
            command.add(config.getAbsoluteFile().getPath());
        }
        if (preset != null && !preset.trim().isEmpty()) {
            command.add("--preset");
            command.add(preset.trim());
        }
        if (seed != null) {
            command.add("--seed");
            command.add(Long.toString(seed.longValue()));
        }
        if (keep != null) {
            for (String rule : keep) {
                if (rule == null || rule.trim().isEmpty()) {
                    continue;
                }
                command.add("--keep");
                command.add(rule.trim());
            }
        }
        if (options != null) {
            for (String option : options) {
                appendOption(command, option);
            }
        }
        if (verify) {
            command.add("--verify");
        }
        return command;
    }

    /**
     * Translates one {@code options} DSL entry into CLI arguments.
     * {@code key=value} entries become {@code --set key=value}; entries
     * starting with {@code -} are free-form pass-through, which keeps the
     * plugin usable when the CLI grows new flags without a plugin release.
     */
    private static void appendOption(List<String> command, String raw) {
        if (raw == null) {
            return;
        }
        String option = raw.trim();
        if (option.isEmpty()) {
            return;
        }
        if (option.startsWith("-")) {
            for (String token : option.split("\\s+")) {
                if (!token.isEmpty()) {
                    command.add(token);
                }
            }
            return;
        }
        int split = option.indexOf('=');
        if (split <= 0) {
            throw new IllegalArgumentException(
                    "Umbra option entries must be key=value or start with '-': " + raw);
        }
        command.add("--set");
        command.add(option);
    }

    /**
     * Runs the CLI, streaming combined stdout/stderr to {@code sink} and
     * optionally teeing every line into {@code logFile} (UTF-8).
     * Never returns a fabricated success: the child's exit code is preserved.
     */
    public static Result run(List<String> command, LineSink sink, File logFile) throws IOException {
        String shown = describeCommand(command);
        if (sink != null) {
            sink.line("$ " + shown);
        }

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);

        Writer log = null;
        try {
            if (logFile != null) {
                File parent = logFile.getAbsoluteFile().getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                log = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(logFile), Charset.forName("UTF-8")));
                log.write("# " + shown + System.lineSeparator());
            }
            Process process = builder.start();
            List<String> tail = new ArrayList<String>();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), Charset.defaultCharset()));
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (sink != null) {
                        sink.line(line);
                    }
                    if (log != null) {
                        log.write(line);
                        log.write(System.lineSeparator());
                    }
                    tail.add(line);
                    while (tail.size() > 80) {
                        tail.remove(0);
                    }
                }
            } finally {
                reader.close();
            }
            int exitCode;
            try {
                exitCode = process.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting for the Umbra CLI", e);
            }
            if (log != null) {
                log.flush();
            }
            return new Result(exitCode, tail, logFile);
        } finally {
            if (log != null) {
                log.close();
            }
        }
    }

    /**
     * Human readable meaning of a non-zero CLI exit code. Mirrors the
     * documented Umbra contract; unknown codes are reported honestly instead
     * of being mapped to "success".
     */
    public static String describeExitCode(int code) {
        switch (code) {
            case 0:
                return "success";
            case 1:
                return "configuration or transform failure";
            case 2:
                return "JVM verification of the protected classes failed (--verify)";
            case 3:
                return "license missing, invalid or revoked (--require-license)";
            default:
                return "unexpected failure";
        }
    }

    /** Last lines of output joined for an exception message. */
    public static String summarise(List<String> tail) {
        if (tail == null || tail.isEmpty()) {
            return "(no output)";
        }
        StringBuilder text = new StringBuilder();
        int start = Math.max(0, tail.size() - 12);
        for (int i = start; i < tail.size(); i++) {
            if (text.length() > 0) {
                text.append(" | ");
            }
            text.append(tail.get(i));
        }
        return text.toString();
    }

    /** Quotes one argument for display only; execution never uses a shell. */
    public static String quote(String value) {
        if (value == null) {
            return "";
        }
        boolean quote = value.isEmpty()
                || value.indexOf(' ') >= 0
                || value.indexOf('\t') >= 0
                || value.indexOf('"') >= 0
                || value.indexOf('\'') >= 0;
        if (!quote) {
            return value;
        }
        return "\"" + value.replace("\"", "\\\"") + "\"";
    }

    /** Renders an argument vector for logging. */
    public static String describeCommand(List<String> command) {
        StringBuilder text = new StringBuilder();
        for (String argument : command) {
            if (text.length() > 0) {
                text.append(' ');
            }
            text.append(quote(argument));
        }
        return text.toString();
    }

    /** Creates the output jar's parent directory (the CLI also does this). */
    public static void prepareOutput(File output) {
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs() && !parent.isDirectory()) {
            throw new IllegalStateException("Could not create output directory: " + parent);
        }
    }

    /** Throws a clear message when a required file is missing. */
    public static void requireReadableFile(File file, String what) {
        if (file == null) {
            throw new IllegalArgumentException(what + " is not configured");
        }
        if (!file.isFile()) {
            throw new IllegalArgumentException(what + " does not exist or is not a file: "
                    + file.getAbsolutePath());
        }
    }

    /**
     * Strict post-run check: a zero exit code must have produced a non-empty
     * output jar, otherwise the build fails instead of shipping a stale jar.
     */
    public static void requireOutputJar(File output) {
        if (output == null || !output.isFile() || output.length() == 0L) {
            throw new IllegalStateException(
                    "Umbra exited successfully but did not write the output jar: " + output);
        }
    }

    /**
     * Honors a configured mapping path.
     *
     * <p>The Umbra CLI writes its mapping file next to the output jar
     * ({@code umbra-mapping.txt}); it has no flag for the mapping path. When a
     * plugin {@code mapping} location is configured, this moves the produced
     * file to that location so build systems can publish/retain it
     * deterministically. If the config sets a custom
     * {@code renamer.mappingFile}, the CLI writes there instead and this method
     * reports that no default-location mapping was found rather than
     * pretending success.</p>
     *
     * @return the final mapping file, or {@code null} when none was produced
     */
    public static File relocateMapping(File outputJar, File desiredMapping, LineSink sink) {
        if (desiredMapping == null) {
            return null;
        }
        File outputDir = outputJar.getAbsoluteFile().getParentFile();
        File produced = new File(outputDir, DEFAULT_MAPPING_FILE);
        if (sameFile(produced, desiredMapping)) {
            return desiredMapping;
        }
        if (!produced.isFile()) {
            if (sink != null) {
                sink.line("warning: mapping file requested at " + desiredMapping.getAbsolutePath()
                        + " but " + produced.getAbsolutePath() + " was not written"
                        + " (renaming disabled or a custom renamer.mappingFile is configured)");
            }
            return null;
        }
        try {
            File parent = desiredMapping.getAbsoluteFile().getParentFile();
            if (parent != null) {
                Files.createDirectories(parent.toPath());
            }
            Files.move(produced.toPath(), desiredMapping.toPath(), StandardCopyOption.REPLACE_EXISTING);
            if (sink != null) {
                sink.line("mapping: " + produced.getAbsolutePath() + " -> "
                        + desiredMapping.getAbsolutePath());
            }
            return desiredMapping;
        } catch (IOException e) {
            if (sink != null) {
                sink.line("warning: could not move mapping file " + produced.getAbsolutePath()
                        + " to " + desiredMapping.getAbsolutePath() + ": " + e.getMessage());
            }
            return null;
        }
    }

    private static boolean sameFile(File first, File second) {
        try {
            return first.getCanonicalFile().equals(second.getCanonicalFile());
        } catch (IOException e) {
            return first.getAbsoluteFile().equals(second.getAbsoluteFile());
        }
    }
}

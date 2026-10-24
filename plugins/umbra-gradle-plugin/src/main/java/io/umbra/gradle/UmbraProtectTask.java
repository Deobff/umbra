package io.umbra.gradle;

import io.umbra.tool.CliRunner;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;

import java.io.File;
import java.util.Collections;
import java.util.List;

/**
 * Runs the Umbra CLI on the project jar.
 *
 * <p>Depends on {@code jar}; the CLI is launched as a child process with an
 * argument vector (no shell), its output is streamed to the Gradle console,
 * and a non-zero exit code fails the build with the documented meaning of the
 * code. The task action only touches its own properties, so it is safe with
 * the Gradle configuration cache.</p>
 */
public abstract class UmbraProtectTask extends DefaultTask {

    /** Umbra tool jar. */
    @InputFile
    @PathSensitive(PathSensitivity.RELATIVE)
    @Optional
    public abstract RegularFileProperty getToolJar();

    /** Optional JDK/JRE home for the CLI. */
    @Input
    @Optional
    public abstract Property<String> getJavaHome();

    /** Optional YAML config file. */
    @InputFile
    @PathSensitive(PathSensitivity.RELATIVE)
    @Optional
    public abstract RegularFileProperty getConfigFile();

    /** Input jar. */
    @InputFile
    @PathSensitive(PathSensitivity.RELATIVE)
    @Optional
    public abstract RegularFileProperty getInputJar();

    /** Protected output jar. */
    @OutputFile
    @Optional
    public abstract RegularFileProperty getOutputJar();

    /** Optional preset name. */
    @Input
    @Optional
    public abstract Property<String> getPreset();

    /** Optional deterministic seed. */
    @Input
    @Optional
    public abstract Property<Long> getSeed();

    /** Whether {@code --verify} is passed. */
    @Input
    @Optional
    public abstract Property<Boolean> getVerify();

    /** Keep rules. */
    @Input
    @Optional
    public abstract ListProperty<String> getKeep();

    /** Advanced options / pass-through flags. */
    @Input
    @Optional
    public abstract ListProperty<String> getOptions();

    /** Optional mapping file to retain. */
    @OutputFile
    @Optional
    public abstract RegularFileProperty getMappingFile();

    /** Optional CLI log file. */
    @OutputFile
    @Optional
    public abstract RegularFileProperty getLogFile();

    /** Runs Umbra and throws {@link GradleException} on any failure. */
    @TaskAction
    public void protect() {
        File toolJar = fileOrNull(getToolJar());
        if (toolJar == null) {
            throw new GradleException("umbra.toolJar is not configured. Point it at dist/umbra.jar,"
                    + " e.g. umbra { toolJar = file(\"${rootDir}/dist/umbra.jar\") },"
                    + " or set the UMBRA_JAR environment variable.");
        }
        File input = fileOrNull(getInputJar());
        if (input == null) {
            throw new GradleException("umbra.input is not configured. Apply the java plugin so the"
                    + " jar task supplies it, or set umbra { input = file(\"app.jar\") }.");
        }
        File output = fileOrNull(getOutputJar());
        if (output == null) {
            throw new GradleException("umbra.output is not configured."
                    + " Set umbra { output = file(\"build/umbra/app-obf.jar\") }.");
        }
        File config = fileOrNull(getConfigFile());

        String javaHomeValue = getJavaHome().getOrNull();
        File javaHome = null;
        if (javaHomeValue != null && !javaHomeValue.trim().isEmpty()) {
            javaHome = new File(javaHomeValue.trim());
        }

        List<String> keep = getKeep().getOrElse(Collections.<String>emptyList());
        List<String> options = getOptions().getOrElse(Collections.<String>emptyList());
        final boolean verify = Boolean.TRUE.equals(getVerify().getOrNull());
        Long seed = getSeed().getOrNull();
        String preset = getPreset().getOrNull();

        File javaExecutable;
        List<String> command;
        try {
            javaExecutable = CliRunner.resolveJava(javaHome);
            command = CliRunner.buildCommand(javaExecutable, toolJar, input, output, config,
                    preset, seed, keep, options, verify);
            CliRunner.prepareOutput(output);
        } catch (IllegalArgumentException e) {
            throw new GradleException("Umbra configuration error: " + e.getMessage(), e);
        }

        final File logFile = fileOrNull(getLogFile());
        CliRunner.LineSink sink = new CliRunner.LineSink() {
            @Override
            public void line(String line) {
                getLogger().lifecycle("[umbra] {}", line);
            }
        };

        CliRunner.Result result;
        try {
            result = CliRunner.run(command, sink, logFile);
        } catch (java.io.IOException e) {
            throw new GradleException("Could not run the Umbra CLI: " + e.getMessage(), e);
        }

        if (!result.isSuccess()) {
            throw new GradleException("Umbra failed with exit code " + result.exitCode() + " ("
                    + CliRunner.describeExitCode(result.exitCode()) + ")."
                    + (logFile == null ? "" : " Full log: " + logFile.getAbsolutePath())
                    + " Last output: " + CliRunner.summarise(result.tail()));
        }

        boolean dryRun = command.contains("--dry-run");
        if (dryRun) {
            getLogger().lifecycle("[umbra] dry run finished; no output jar expected");
            return;
        }

        try {
            CliRunner.requireOutputJar(output);
        } catch (IllegalStateException e) {
            throw new GradleException(e.getMessage(), e);
        }
        getLogger().lifecycle("[umbra] protected jar: {} ({} bytes)",
                output.getAbsolutePath(), Long.valueOf(output.length()));

        File mapping = fileOrNull(getMappingFile());
        if (mapping != null) {
            File produced = CliRunner.relocateMapping(output, mapping, sink);
            if (produced != null) {
                getLogger().lifecycle("[umbra] mapping: {}", produced.getAbsolutePath());
            }
        }
        if (logFile != null) {
            getLogger().lifecycle("[umbra] log: {}", logFile.getAbsolutePath());
        }
    }

    private static File fileOrNull(RegularFileProperty property) {
        if (property == null || !property.isPresent()) {
            return null;
        }
        return property.get().getAsFile();
    }
}

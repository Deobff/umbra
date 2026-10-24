package io.umbra.maven;

import io.umbra.tool.CliRunner;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * Maven goal that protects the project jar with the Umbra CLI.
 *
 * <p>Bound to {@code package} by default; a project only needs:</p>
 *
 * <pre>
 * &lt;plugin&gt;
 *   &lt;groupId&gt;io.umbra&lt;/groupId&gt;
 *   &lt;artifactId&gt;umbra-maven-plugin&lt;/artifactId&gt;
 *   &lt;version&gt;3.0.0&lt;/version&gt;
 *   &lt;executions&gt;
 *     &lt;execution&gt;
 *       &lt;goals&gt;&lt;goal&gt;protect&lt;/goal&gt;&lt;/goals&gt;
 *       &lt;configuration&gt;
 *         &lt;toolJar&gt;${project.basedir}/dist/umbra.jar&lt;/toolJar&gt;
 *         &lt;preset&gt;balanced&lt;/preset&gt;
 *         &lt;verify&gt;true&lt;/verify&gt;
 *       &lt;/configuration&gt;
 *     &lt;/execution&gt;
 *   &lt;/executions&gt;
 * &lt;/plugin&gt;
 * </pre>
 *
 * <p>The CLI is launched as a child process with an argument vector (no
 * shell); its output is streamed to the Maven log, the child's exit code is
 * preserved and a non-zero code fails the build. The tool jar path comes from
 * the {@code toolJar} parameter or the {@code UMBRA_JAR} environment
 * variable.</p>
 */
@Mojo(name = "protect", defaultPhase = LifecyclePhase.PACKAGE, threadSafe = true,
        requiresDependencyResolution = ResolutionScope.RUNTIME)
public class UmbraProtectMojo extends AbstractMojo {

    /** Current project, used to derive default input/output paths. */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    /** Umbra tool jar; defaults to the {@code UMBRA_JAR} environment variable. */
    @Parameter(property = "umbra.toolJar")
    private File toolJar;

    /** Optional JDK/JRE home used to launch Umbra (defaults to the build JVM). */
    @Parameter(property = "umbra.javaHome")
    private String javaHome;

    /** Optional YAML configuration passed as {@code -c}. */
    @Parameter(property = "umbra.config")
    private File configFile;

    /** Input jar; defaults to the project artifact ({@code target/<finalName>.jar}). */
    @Parameter(property = "umbra.input")
    private File input;

    /** Protected output jar; defaults to {@code target/<finalName>-obf.jar}. */
    @Parameter(property = "umbra.output")
    private File output;

    /** Optional protection preset. */
    @Parameter(property = "umbra.preset")
    private String preset;

    /** Optional deterministic seed. */
    @Parameter(property = "umbra.seed")
    private Long seed;

    /** Adds {@code --verify}. */
    @Parameter(property = "umbra.verify", defaultValue = "false")
    private boolean verify;

    /** Keep rules passed as repeated {@code --keep}. */
    @Parameter
    private List<String> keep;

    /**
     * Advanced options: {@code key=value} entries become {@code --set};
     * entries starting with {@code -} are passed to the CLI verbatim.
     */
    @Parameter
    private List<String> options;

    /** Optional mapping file location (retained from the CLI's mapping output). */
    @Parameter(property = "umbra.mapping")
    private File mapping;

    /** Optional file that receives the combined CLI log. */
    @Parameter(property = "umbra.logFile")
    private File logFile;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        File resolvedToolJar = resolveToolJar();
        File resolvedInput = input != null ? input : defaultArtifactFile();
        File resolvedOutput = output != null ? output : defaultOutputFile();
        File resolvedJavaHome = null;
        if (javaHome != null && !javaHome.trim().isEmpty()) {
            resolvedJavaHome = new File(javaHome.trim());
        }

        List<String> resolvedKeep = keep == null ? Collections.<String>emptyList() : keep;
        List<String> resolvedOptions = options == null ? Collections.<String>emptyList() : options;

        final File effectiveLog = logFile;
        File javaExecutable;
        List<String> command;
        try {
            javaExecutable = CliRunner.resolveJava(resolvedJavaHome);
            command = CliRunner.buildCommand(javaExecutable, resolvedToolJar, resolvedInput,
                    resolvedOutput, configFile, preset, seed, resolvedKeep, resolvedOptions, verify);
            CliRunner.prepareOutput(resolvedOutput);
        } catch (IllegalArgumentException e) {
            throw new MojoExecutionException("Umbra configuration error: " + e.getMessage(), e);
        }

        CliRunner.LineSink sink = new CliRunner.LineSink() {
            @Override
            public void line(String line) {
                getLog().info(line);
            }
        };

        CliRunner.Result result;
        try {
            result = CliRunner.run(command, sink, effectiveLog);
        } catch (IOException e) {
            throw new MojoExecutionException("Could not run the Umbra CLI: " + e.getMessage(), e);
        }

        if (!result.isSuccess()) {
            throw new MojoFailureException("Umbra failed with exit code " + result.exitCode() + " ("
                    + CliRunner.describeExitCode(result.exitCode()) + ")."
                    + (effectiveLog == null ? "" : " Full log: " + effectiveLog.getAbsolutePath())
                    + " Last output: " + CliRunner.summarise(result.tail()));
        }

        if (command.contains("--dry-run")) {
            getLog().info("Umbra dry run finished; no output jar expected");
            return;
        }

        try {
            CliRunner.requireOutputJar(resolvedOutput);
        } catch (IllegalStateException e) {
            throw new MojoFailureException(e.getMessage());
        }
        getLog().info("Umbra protected jar: " + resolvedOutput.getAbsolutePath()
                + " (" + resolvedOutput.length() + " bytes)");

        if (mapping != null) {
            File produced = CliRunner.relocateMapping(resolvedOutput, mapping, sink);
            if (produced != null) {
                getLog().info("Umbra mapping: " + produced.getAbsolutePath());
            }
        }
        if (effectiveLog != null) {
            getLog().info("Umbra log: " + effectiveLog.getAbsolutePath());
        }
    }

    private File resolveToolJar() throws MojoExecutionException {
        if (toolJar != null) {
            return toolJar;
        }
        File fromEnvironment = CliRunner.defaultToolJar();
        if (fromEnvironment != null) {
            return fromEnvironment;
        }
        throw new MojoExecutionException("umbra.toolJar is not configured. Set"
                + " <toolJar>/path/to/umbra.jar</toolJar> or the UMBRA_JAR environment variable"
                + " (for example -Dumbra.toolJar=dist/umbra.jar).");
    }

    private File defaultArtifactFile() {
        return new File(project.getBuild().getDirectory(),
                project.getBuild().getFinalName() + ".jar");
    }

    private File defaultOutputFile() {
        return new File(project.getBuild().getDirectory(),
                project.getBuild().getFinalName() + "-obf.jar");
    }
}

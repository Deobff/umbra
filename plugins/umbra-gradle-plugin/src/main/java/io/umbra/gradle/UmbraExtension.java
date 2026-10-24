package io.umbra.gradle;

import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;

/**
 * Gradle DSL for Umbra.
 *
 * <pre>
 * plugins {
 *     id 'java'
 *     id 'io.umbra' version '3.0.0'
 * }
 *
 * umbra {
 *     toolJar = file("dist/umbra.jar")          // required (UMBRA_JAR env also works)
 *     preset  = "balanced"
 *     seed    = 23303
 *     verify  = true
 *     keep    = ["com.example.Main"]
 *     options = ["mba.enabled=true", "--flatten"]
 *     mapping = file("build/umbra/mapping.txt")
 *     logFile = file("build/umbra/protect.log")
 * }
 * </pre>
 *
 * <p>All properties are plain Gradle lazy properties, so the task works with
 * the configuration cache. {@code input} and {@code output} default from the
 * {@code jar} task; explicit values win.</p>
 */
public abstract class UmbraExtension {

    /** Path to {@code umbra.jar}; defaults to the {@code UMBRA_JAR} environment variable. */
    public abstract RegularFileProperty getToolJar();

    /** Optional JDK/JRE home used to launch Umbra (defaults to the build JVM). */
    public abstract Property<String> getJavaHome();

    /** Optional YAML configuration passed as {@code -c}. */
    public abstract RegularFileProperty getConfig();

    /** Input jar; defaults to the {@code jar} task's archive file. */
    public abstract RegularFileProperty getInput();

    /** Protected output jar; defaults to {@code build/umbra/&lt;name&gt;-obf.jar}. */
    public abstract RegularFileProperty getOutput();

    /** Optional protection preset ({@code light}, {@code balanced}, {@code maximum}, ...). */
    public abstract Property<String> getPreset();

    /** Optional deterministic seed. */
    public abstract Property<Long> getSeed();

    /** Adds {@code --verify}; defaults to {@code false}. */
    public abstract Property<Boolean> getVerify();

    /** Keep rules passed as repeated {@code --keep}. */
    public abstract ListProperty<String> getKeep();

    /**
     * Advanced options: {@code key=value} entries become {@code --set key=value};
     * entries starting with {@code -} are passed to the CLI verbatim.
     */
    public abstract ListProperty<String> getOptions();

    /** Optional mapping file location (retained from the CLI's mapping output). */
    public abstract RegularFileProperty getMapping();

    /** Optional file that receives the combined CLI log. */
    public abstract RegularFileProperty getLogFile();
}

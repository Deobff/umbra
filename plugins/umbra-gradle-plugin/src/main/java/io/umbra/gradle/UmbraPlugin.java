package io.umbra.gradle;

import io.umbra.tool.CliRunner;
import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.AppliedPlugin;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.api.tasks.bundling.Jar;

import java.io.File;

/**
 * Umbra Gradle plugin entry point.
 *
 * <p>Registers the {@code umbra} extension and the {@code umbraProtect} task.
 * When the {@code java} plugin is present the task depends on {@code jar} and
 * takes the jar archive as its default input, so a project only needs:</p>
 *
 * <pre>
 * plugins {
 *     id 'java'
 *     id 'io.umbra' version '3.0.0'
 * }
 *
 * umbra {
 *     toolJar = file("dist/umbra.jar")
 *     preset  = "balanced"
 *     verify  = true
 * }
 * </pre>
 *
 * <p>All wiring is lazy (Gradle providers); the task never reads the
 * {@link Project} at execution time, which keeps it compatible with the
 * configuration cache.</p>
 */
public class UmbraPlugin implements Plugin<Project> {

    /** Task name registered by the plugin. */
    public static final String TASK_NAME = "umbraProtect";

    /** Extension name registered by the plugin. */
    public static final String EXTENSION_NAME = "umbra";

    @Override
    public void apply(final Project project) {
        final UmbraExtension extension =
                project.getExtensions().create(EXTENSION_NAME, UmbraExtension.class);
        extension.getVerify().convention(Boolean.FALSE);

        // Default tool jar from the environment; an explicit DSL value wins.
        File envToolJar = CliRunner.defaultToolJar();
        if (envToolJar != null) {
            extension.getToolJar().fileValue(envToolJar);
        }

        final TaskProvider<UmbraProtectTask> protect =
                project.getTasks().register(TASK_NAME, UmbraProtectTask.class, new Action<UmbraProtectTask>() {
                    @Override
                    public void execute(UmbraProtectTask task) {
                        task.setGroup("build");
                        task.setDescription("Protects the project jar with Umbra");
                        task.getToolJar().convention(extension.getToolJar());
                        task.getJavaHome().convention(extension.getJavaHome());
                        task.getConfigFile().convention(extension.getConfig());
                        task.getInputJar().convention(extension.getInput());
                        task.getOutputJar().convention(extension.getOutput());
                        task.getPreset().convention(extension.getPreset());
                        task.getSeed().convention(extension.getSeed());
                        task.getVerify().convention(extension.getVerify());
                        task.getKeep().convention(extension.getKeep());
                        task.getOptions().convention(extension.getOptions());
                        task.getMappingFile().convention(extension.getMapping());
                        task.getLogFile().convention(extension.getLogFile());
                    }
                });

        project.getPluginManager().withPlugin("java", new Action<AppliedPlugin>() {
            @Override
            public void execute(AppliedPlugin ignored) {
                final TaskProvider<Jar> jar = project.getTasks().named("jar", Jar.class);
                extension.getInput().convention(jar.flatMap(archive -> archive.getArchiveFile()));
                extension.getOutput().convention(project.getLayout().getBuildDirectory()
                        .file("umbra/" + project.getName() + "-obf.jar"));
                protect.configure(new Action<UmbraProtectTask>() {
                    @Override
                    public void execute(UmbraProtectTask task) {
                        task.dependsOn(jar);
                    }
                });
            }
        });
    }
}

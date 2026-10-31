package io.umbra.guifx;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.PixelReader;
import javafx.scene.image.WritableImage;
import javafx.stage.Stage;

import javax.imageio.ImageIO;
import java.io.File;

/**
 * JavaFX front end for the Umbra engine.
 *
 * <p>The window is built by {@link ConsoleShell} from a {@link ConsoleModel}; this
 * class only owns the application lifecycle and the headless self-test hooks:</p>
 *
 * <ul>
 *   <li>{@code -Dumbra.fx.shot=<png>} writes a screenshot and exits (visual QA),</li>
 *   <li>{@code -Dumbra.fx.input/-Dumbra.fx.output/-Dumbra.fx.preset} prefill the
 *       targets,</li>
 *   <li>{@code -Dumbra.fx.autoprotect=1} starts a protection run immediately,</li>
 *   <li>{@code -Dumbra.fx.exitWhenDone=1} exits after that run finishes,</li>
 *   <li>{@code -Dumbra.fx.reduceMotion=true} (or {@code -Dumbra.fx.animations=false})
 *       turns every animation duration to zero while keeping the final state.</li>
 * </ul>
 */
public final class FxGui extends Application {

    /** Console version, shown in the title bar and in the About window. */
    static final String VERSION = "3.2.2";

    private static String jarArgument;

    public static void main(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if ("--jar".equals(args[i])) {
                jarArgument = args[i + 1];
            }
        }
        launch(args);
    }

    @Override
    public void start(Stage stage) {
        ConsoleModel model = new ConsoleModel();
        if (jarArgument != null && !jarArgument.isEmpty()) {
            model.jarPath = jarArgument;
        }
        stage.initStyle(javafx.stage.StageStyle.UNDECORATED);
        ConsoleShell shell = new ConsoleShell(stage, model);
        shell.setOnAbout(new Runnable() {
            @Override
            public void run() {
                AboutDialog.show(stage, model.jarPath);
            }
        });
        Parent root = shell.build();

        Scene scene = new Scene(root, 1180, 780);
        scene.setFill(Tokens.CANVAS);
        java.net.URL sheet = FxGui.class.getResource("umbra-fx.css");
        if (sheet != null) {
            scene.getStylesheets().add(sheet.toExternalForm());
        } else {
            System.out.println("stylesheet umbra-fx.css is missing from the jar");
        }

        stage.setScene(scene);
        stage.setTitle("Umbra " + VERSION);
        stage.setMinWidth(1000);
        stage.setMinHeight(640);
        stage.show();
        // A screenshot must be a deterministic still frame, so the entrance motion
        // is skipped when one is requested; a live launch keeps it.
        boolean stillFrame = System.getProperty("umbra.fx.shot") != null;
        if (!stillFrame) {
            Motion.entrance(root);
        }
        // Rebuild the option rows once the window has a real width: the first pass
        // measures the scroll content at its preferred width, and a slider skin that
        // laid its track out at that width never shrinks it again.
        javafx.application.Platform.runLater(new Runnable() {
            @Override
            public void run() {
                shell.settleLayout();
            }
        });

        shell.prefill(System.getProperty("umbra.fx.input"),
                System.getProperty("umbra.fx.output"),
                System.getProperty("umbra.fx.preset"));
        shell.log("engine jar: " + new File(model.jarPath).getAbsolutePath());
        shell.log("pick a group on the left, then press Protect");
        if (System.getProperty("umbra.fx.exitWhenDone") != null) {
            shell.setOnDone(new Runnable() {
                @Override
                public void run() {
                    Platform.exit();
                }
            });
        }
        String shot = System.getProperty("umbra.fx.shot");
        if (shot != null) {
            // Give the scene one layout pass plus the row entrance (180 ms) before
            // snapshotting, otherwise the capture can catch an empty frame.
            javafx.animation.PauseTransition settle =
                    new javafx.animation.PauseTransition(javafx.util.Duration.millis(320));
            settle.setOnFinished(event -> writeShot(scene, shot));
            settle.play();
        }
        if (System.getProperty("umbra.fx.autoprotect") != null) {
            Platform.runLater(new Runnable() {
                @Override
                public void run() {
                    shell.protect();
                }
            });
        }
        // QA hook: render the About window into a PNG without opening a modal stage.
        String aboutShot = System.getProperty("umbra.fx.about-shot");
        if (aboutShot != null) {
            javafx.animation.PauseTransition settle =
                    new javafx.animation.PauseTransition(javafx.util.Duration.millis(200));
            settle.setOnFinished(event -> {
                javafx.scene.Parent about = AboutDialog.build(model.jarPath);
                Scene aboutScene = new Scene(about);
                aboutScene.setFill(Tokens.PANEL);
                java.net.URL aboutSheet = FxGui.class.getResource("umbra-fx.css");
                if (aboutSheet != null) {
                    aboutScene.getStylesheets().add(aboutSheet.toExternalForm());
                }
                writeShot(aboutScene, aboutShot);
            });
            settle.play();
        }
        if (System.getProperty("umbra.fx.selfcheck") != null) {
            javafx.animation.PauseTransition settle =
                    new javafx.animation.PauseTransition(javafx.util.Duration.millis(320));
            settle.setOnFinished(event -> {
                java.util.List<String> failures = shell.selfCheck();
                for (String failure : failures) {
                    System.out.println("selfcheck: FAIL " + failure);
                }
                System.out.println("selfcheck: " + (failures.isEmpty() ? "PASS" : "FAILED")
                        + " (" + failures.size() + " failures)");
                Platform.exit();
                if (!failures.isEmpty()) {
                    System.exit(1);
                }
            });
            settle.play();
        }
        // QA hook: the geometry of every slider row, measured after the scene has
        // settled. The pixel probe on the screenshot cross-checks these rectangles.
        String band = System.getProperty("umbra.fx.dump-band");
        if (band != null) {
            javafx.animation.PauseTransition settle =
                    new javafx.animation.PauseTransition(javafx.util.Duration.millis(320));
            settle.setOnFinished(event -> {
                StringBuilder text = new StringBuilder();
                for (String line : shell.nodesInBand(430, 470)) {
                    text.append(line).append(System.lineSeparator());
                }
                try {
                    java.nio.file.Files.write(java.nio.file.Paths.get(band),
                            text.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    System.out.println("band written: " + band);
                } catch (Exception failure) {
                    System.out.println("band write failed: " + failure);
                }
                Platform.exit();
            });
            settle.play();
        }
        // QA hook: the geometry of every slider row, measured after the scene has
        // settled. The pixel probe on the screenshot cross-checks these rectangles.
        String geometry = System.getProperty("umbra.fx.dump-geometry");
        if (geometry != null) {
            javafx.animation.PauseTransition settle =
                    new javafx.animation.PauseTransition(javafx.util.Duration.millis(320));
            settle.setOnFinished(event -> {
                StringBuilder text = new StringBuilder();
                for (String line : shell.sliderGeometry()) {
                    text.append(line).append(System.lineSeparator());
                }
                try {
                    java.nio.file.Files.write(java.nio.file.Paths.get(geometry),
                            text.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    System.out.println("geometry written: " + geometry);
                } catch (Exception failure) {
                    System.out.println("geometry write failed: " + failure);
                }
                Platform.exit();
            });
            settle.play();
        }
        // QA hook: the previewed command is the contract between the UI and the
        // engine, so tests can assert on it without a screenshot.
        String dumpCommand = System.getProperty("umbra.fx.dump-command");
        if (dumpCommand != null) {
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get(dumpCommand),
                        shell.commandPreview().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                System.out.println("command written: " + dumpCommand);
            } catch (Exception failure) {
                System.out.println("command dump failed: " + failure);
            }
        }
        // QA hook: render every group and report value/representation mismatches.
        String audit = System.getProperty("umbra.fx.audit-options");
        if (audit != null) {
            javafx.animation.PauseTransition settle =
                    new javafx.animation.PauseTransition(javafx.util.Duration.millis(200));
            settle.setOnFinished(event -> {
                java.util.List<String> problems = new java.util.ArrayList<String>();
                problems.addAll(shell.auditOptions());
                String geometryDump = System.getProperty("umbra.fx.dump-geometry");
                if (geometryDump != null) {
                    // Scene-space rectangles prove where the slider and its readout
                    // actually ended up; a screenshot alone cannot be asserted on.
                    StringBuilder geo = new StringBuilder();
                    for (String line : shell.sliderGeometry()) {
                        geo.append(line).append(System.lineSeparator());
                    }
                    try {
                        java.nio.file.Files.write(java.nio.file.Paths.get(geometryDump),
                                geo.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        System.out.println("geometry written: " + geometryDump);
                    } catch (Exception failure) {
                        System.out.println("geometry write failed: " + failure);
                    }
                }
                StringBuilder text = new StringBuilder();
                int notes = 0;
                int issues = 0;
                for (String problem : problems) {
                    text.append(problem).append(System.lineSeparator());
                    if (problem.startsWith("note: ")) {
                        notes++;
                    } else {
                        issues++;
                    }
                }
                text.append("audit: ").append(issues == 0 ? "CLEAN" : issues + " issue(s)")
                        .append(", ").append(notes).append(" note(s)")
                        .append(System.lineSeparator());
                try {
                    java.nio.file.Files.write(java.nio.file.Paths.get(audit),
                            text.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                } catch (Exception failure) {
                    System.out.println("audit write failed: " + failure);
                }
                System.out.print(text);
                Platform.exit();
            });
            settle.play();
        }
    }

    /** Snapshots the scene to a PNG and exits; used by the visual QA loop. */
    private static void writeShot(Scene scene, String path) {
        try {
            WritableImage image = scene.snapshot(null);
            int width = (int) image.getWidth();
            int height = (int) image.getHeight();
            java.awt.image.BufferedImage buffered = new java.awt.image.BufferedImage(
                    width, height, java.awt.image.BufferedImage.TYPE_INT_RGB);
            PixelReader reader = image.getPixelReader();
            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    buffered.setRGB(x, y, reader.getArgb(x, y));
                }
            }
            ImageIO.write(buffered, "png", new File(path));
            System.out.println("shot written: " + new File(path).getAbsolutePath());
        } catch (Exception failure) {
            System.out.println("shot failed: " + failure);
        }
        Platform.exit();
    }
}

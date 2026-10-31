package io.umbra.guifx;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;

/**
 * About window: what Umbra is and what it does.
 *
 * <p>This is an introduction, not a diagnostics panel. It states the product in
 * one paragraph, lists the protection layers it actually implements, and keeps a
 * single muted line at the bottom with the version and the JVM — the two facts a
 * bug report needs, without turning the window into a log dump.</p>
 */
final class AboutDialog {

    /** Protection layers, phrased the way the engine's own reports name them. */
    private static final String[][] FEATURES = {
            {"renaming", "classes, members and packages, flat or per project"},
            {"string and integer encryption", "per-site engines with a one-time state"},
            {"control-flow obfuscation", "opaque predicates, block guards, block scheduling"},
            {"method virtualization", "VM2 with a sealed Cantrip second dialect"},
            {"class encryption", "payload archive with an in-memory loader"},
            {"native guard", "anti-debug, anti-dump, code CRC and page checks"},
            {"anti-analysis", "anti-LLM decoys, decompiler noise, integrity checks"},
    };

    private AboutDialog() {
    }

    /** Opens the dialog modally over {@code owner}. */
    static void show(Window owner, String engineJar) {
        Stage stage = new Stage(StageStyle.UNDECORATED);
        stage.initModality(Modality.WINDOW_MODAL);
        if (owner != null) {
            stage.initOwner(owner);
        }
        Scene scene = new Scene(build(engineJar));
        scene.setFill(Tokens.PANEL);
        java.net.URL sheet = FxGui.class.getResource("umbra-fx.css");
        if (sheet != null) {
            scene.getStylesheets().add(sheet.toExternalForm());
        }
        scene.setOnKeyPressed(event -> {
            if (event.getCode() == javafx.scene.input.KeyCode.ESCAPE) {
                stage.close();
            }
        });
        stage.setScene(scene);
        stage.setTitle("About Umbra");
        stage.setResizable(false);
        stage.showAndWait();
    }

    /**
     * Builds the dialog content. Split out from {@link #show} so the headless QA
     * hook can render it into a screenshot without opening a modal window.
     */
    static javafx.scene.Parent build(String engineJar) {
        Label mark = new Label("U");
        mark.getStyleClass().add("ux-brand-mark");
        Label title = new Label("UMBRA");
        title.getStyleClass().add("ux-about-title");
        Label version = new Label("version " + FxGui.VERSION);
        version.getStyleClass().add("ux-version");
        VBox head = new VBox(2, title, version);
        HBox brand = new HBox(12, mark, head);
        brand.setAlignment(Pos.CENTER_LEFT);

        Label intro = new Label("Umbra is a Java bytecode protection suite. It rewrites"
                + " compiled classes so that decompilers, debuggers and memory dumpers"
                + " have far less to work with, while the protected program keeps"
                + " running unchanged.");
        intro.getStyleClass().add("ux-about-body");
        intro.setWrapText(true);
        intro.setMaxWidth(520);

        Label sectionTitle = new Label("PROTECTION LAYERS");
        sectionTitle.getStyleClass().add("ux-caption");

        VBox features = new VBox(6);
        for (String[] feature : FEATURES) {
            features.getChildren().add(feature(feature[0], feature[1]));
        }
        features.getStyleClass().add("ux-about-facts");

        Label footer = new Label("Java 8 + ASM only  ·  command line, YAML, Gradle/Maven"
                + " plugins and this console share one engine  ·  "
                + System.getProperty("java.version", "?") + " on "
                + System.getProperty("os.name", "?") + " "
                + System.getProperty("os.arch", "?"));
        footer.getStyleClass().add("ux-about-foot");
        footer.setWrapText(true);
        footer.setMaxWidth(520);

        Button close = new FusionButton("Close");
        close.getStyleClass().add("ux-primary");
        close.setOnAction(event -> {
            javafx.stage.Window window = close.getScene() == null
                    ? null : close.getScene().getWindow();
            if (window != null) {
                window.hide();
            }
        });
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox actions = new HBox(10, spacer, close);
        actions.setAlignment(Pos.CENTER_RIGHT);

        VBox root = new VBox(14, brand, intro, sectionTitle, features, footer, actions);
        root.getStyleClass().add("ux-about");
        root.setPadding(new Insets(22, 24, 20, 24));
        root.setMinWidth(560);
        root.setMaxWidth(600);
        return root;
    }

    /** One capability row: accent bullet, layer name, then what it covers. */
    private static HBox feature(String name, String detail) {
        Label bullet = new Label("·");
        bullet.getStyleClass().add("ux-about-bullet");
        Label layer = new Label(name);
        layer.getStyleClass().add("ux-about-layer");
        layer.setMinWidth(186);
        Label text = new Label(detail);
        text.getStyleClass().add("ux-about-value");
        text.setWrapText(true);
        HBox.setHgrow(text, Priority.ALWAYS);
        HBox row = new HBox(8, bullet, layer, text);
        row.setAlignment(Pos.TOP_LEFT);
        return row;
    }
}

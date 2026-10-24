package io.umbra.gui;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Tiny plain-properties preferences store under {@code ~/.umbra/gui.properties}.
 *
 * <p>Only the last-used directories, seed and preset are remembered; the file
 * is intentionally human-readable and written atomically. Failures are ignored
 * (a read-only home must never break the GUI).</p>
 */
public final class GuiPrefs {

    private static final String DIRECTORY = ".umbra";
    private static final String FILE = "gui.properties";

    private final Path file;
    private final Properties values = new Properties();
    private String lastInputDir = "";
    private String lastOutputDir = "";
    private String lastConfigDir = "";
    private long seed = 23303L;
    private String preset = GuiPresets.DEFAULT;

    private GuiPrefs(Path file) {
        this.file = file;
    }

    /** Loads preferences, falling back to defaults on any error. */
    public static GuiPrefs load() {
        Path home;
        try {
            home = Paths.get(System.getProperty("user.home", "."));
        } catch (RuntimeException e) {
            home = Paths.get(".");
        }
        GuiPrefs prefs = new GuiPrefs(home.resolve(DIRECTORY).resolve(FILE));
        if (Files.isRegularFile(prefs.file)) {
            try (InputStream in = Files.newInputStream(prefs.file)) {
                prefs.values.load(in);
            } catch (Exception ignored) {
                // A corrupt preferences file only loses memory, never data.
            }
        }
        prefs.lastInputDir = prefs.values.getProperty("lastInputDir", "");
        prefs.lastOutputDir = prefs.values.getProperty("lastOutputDir", "");
        prefs.lastConfigDir = prefs.values.getProperty("lastConfigDir", "");
        try {
            prefs.seed = Long.parseLong(prefs.values.getProperty("seed", "23303"));
        } catch (NumberFormatException ignored) {
            prefs.seed = 23303L;
        }
        prefs.preset = prefs.values.getProperty("preset", GuiPresets.DEFAULT);
        return prefs;
    }

    public Path file() {
        return file;
    }

    public String lastInputDir() {
        return lastInputDir;
    }

    public void setLastInputDir(String directory) {
        if (directory != null && !directory.trim().isEmpty()) {
            lastInputDir = directory.trim();
        }
    }

    public String lastOutputDir() {
        return lastOutputDir;
    }

    public void setLastOutputDir(String directory) {
        if (directory != null && !directory.trim().isEmpty()) {
            lastOutputDir = directory.trim();
        }
    }

    public String lastConfigDir() {
        return lastConfigDir;
    }

    public void setLastConfigDir(String directory) {
        if (directory != null && !directory.trim().isEmpty()) {
            lastConfigDir = directory.trim();
        }
    }

    public long seed() {
        return seed;
    }

    public void setSeed(long seed) {
        this.seed = seed;
    }

    public String preset() {
        return preset;
    }

    public void setPreset(String preset) {
        if (preset != null && !preset.trim().isEmpty()) {
            this.preset = preset.trim();
        }
    }

    /** Records the directory of a file (null-safe, no-op for empty paths). */
    public void rememberInput(Path input) {
        if (input != null && input.toAbsolutePath().getParent() != null) {
            setLastInputDir(input.toAbsolutePath().getParent().toString());
        }
    }

    public void rememberOutput(Path output) {
        if (output != null && output.toAbsolutePath().getParent() != null) {
            setLastOutputDir(output.toAbsolutePath().getParent().toString());
        }
    }

    public void rememberConfig(Path config) {
        if (config != null && config.toAbsolutePath().getParent() != null) {
            setLastConfigDir(config.toAbsolutePath().getParent().toString());
        }
    }

    /** Best-effort save; never throws. */
    public void save() {
        values.setProperty("lastInputDir", lastInputDir);
        values.setProperty("lastOutputDir", lastOutputDir);
        values.setProperty("lastConfigDir", lastConfigDir);
        values.setProperty("seed", String.valueOf(seed));
        values.setProperty("preset", preset);
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path temporary = file.resolveSibling(FILE + ".tmp");
            try (OutputStream out = Files.newOutputStream(temporary)) {
                values.store(out, "Umbra desktop GUI preferences");
            }
            try {
                Files.move(temporary, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception moveFailed) {
                Files.deleteIfExists(temporary);
                try (OutputStream out = Files.newOutputStream(file)) {
                    values.store(out, "Umbra desktop GUI preferences");
                }
            }
        } catch (IOException ignored) {
            // Preferences are a convenience; a read-only home is not an error.
        }
    }
}

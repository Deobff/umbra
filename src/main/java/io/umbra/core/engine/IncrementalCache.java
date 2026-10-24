package io.umbra.core.engine;

import io.umbra.core.config.UmbraConfig;
import io.umbra.core.model.ClassPool;
import io.umbra.core.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Class-level incremental cache.
 *
 * <p>A metadata file records input class hashes and their output names. When
 * the same input class is unchanged, its previous output bytes are reused
 * verbatim, provided the seed and mapping are stable. This is intentionally
 * class-granular: a changed class can still affect unchanged callers, so
 * releases should run a full build when signatures change.</p>
 */
public final class IncrementalCache {

    private static final String HEADER_PREFIX = "# umbra-incremental v1 seed=";

    private IncrementalCache() {
    }

    /** Loads a reuse plan, or {@code null} when incremental reuse is not possible. */
    public static Plan load(UmbraConfig config, Map<String, String> inputHashes, Log log) throws IOException {
        UmbraConfig.IncrementalOptions options = config.incremental();
        if (!options.enabled()) {
            return null;
        }
        if (options.previousOutput().trim().isEmpty()) {
            log.info("incremental: no previous output configured; recording metadata only");
            return null;
        }
        if (config.mapping().inputFile().trim().isEmpty()) {
            log.warn("incremental: mapping.inputFile is required for safe reuse; disabling reuse");
            return null;
        }
        Path previous = resolve(config, options.previousOutput());
        Path metadata = resolve(config, options.metadataFile());
        if (!Files.exists(previous) || !Files.exists(metadata)) {
            log.warn("incremental: previous output or metadata missing; performing a full run");
            return null;
        }

        Map<String, Entry> entries = new LinkedHashMap<String, Entry>();
        boolean seedMatches = false;
        for (String line : Files.readAllLines(metadata, StandardCharsets.UTF_8)) {
            if (line.startsWith(HEADER_PREFIX)) {
                String seedText = line.substring(HEADER_PREFIX.length()).trim();
                try {
                    seedMatches = Long.parseLong(seedText) == config.seed();
                } catch (NumberFormatException ignored) {
                    seedMatches = false;
                }
                continue;
            }
            if (line.trim().isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split("\t");
            if (parts.length != 3) {
                continue;
            }
            entries.put(parts[1], new Entry(parts[0], parts[2], null));
        }
        if (!seedMatches) {
            log.warn("incremental: seed differs from the previous build; disabling reuse");
            return null;
        }

        try (ZipFile zip = new ZipFile(previous.toFile())) {
            for (Map.Entry<String, Entry> e : entries.entrySet()) {
                if (!inputHashes.containsKey(e.getKey())) {
                    continue;
                }
                Entry entry = e.getValue();
                if (!entry.hash.equals(inputHashes.get(e.getKey()))) {
                    continue;
                }
                ZipEntry classEntry = zip.getEntry(entry.outputName + ".class");
                if (classEntry == null) {
                    continue;
                }
                try (InputStream in = zip.getInputStream(classEntry)) {
                    entry.bytes = readAll(in);
                }
            }
        }
        int reusable = 0;
        for (Entry entry : entries.values()) {
            if (entry.bytes != null) {
                reusable++;
            }
        }
        log.info("incremental: %d of %d unchanged classes are reusable", reusable, inputHashes.size());
        return new Plan(entries);
    }

    /** Writes metadata for the next incremental run. */
    public static void write(UmbraConfig config, Map<String, String> inputHashes,
                             MappingSet mappings, Log log) throws IOException {
        if (!config.incremental().enabled()) {
            return;
        }
        Path metadata = resolve(config, config.incremental().metadataFile());
        StringBuilder out = new StringBuilder();
        out.append(HEADER_PREFIX).append(config.seed()).append('\n');
        for (Map.Entry<String, String> e : inputHashes.entrySet()) {
            String output = mappings.mappedClass(e.getKey());
            out.append(e.getValue()).append('\t').append(e.getKey()).append('\t').append(output).append('\n');
        }
        Path parent = metadata.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(metadata, out.toString().getBytes(StandardCharsets.UTF_8));
        log.info("incremental: metadata written to %s", metadata);
    }

    /** SHA-256 hex digest of class bytes. */
    public static String hash(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] value = digest.digest(bytes);
            StringBuilder out = new StringBuilder(value.length * 2);
            for (byte b : value) {
                out.append(String.format("%02x", b & 0xff));
            }
            return out.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static Path resolve(UmbraConfig config, String value) {
        Path path = Paths.get(value.trim());
        if (path.isAbsolute()) {
            return path;
        }
        Path parent = config.output().toAbsolutePath().getParent();
        return parent == null ? path : parent.resolve(path);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    /** Reuse plan for one run. */
    public static final class Plan {
        private final Map<String, Entry> entries;

        Plan(Map<String, Entry> entries) {
            this.entries = entries;
        }

        /** Applies reusable bytes to the pool, tracking statistics. */
        public void apply(ClassPool pool, MappingSet mappings, Stats stats) {
            int reused = 0;
            for (Map.Entry<String, Entry> e : entries.entrySet()) {
                Entry entry = e.getValue();
                if (entry.bytes == null) {
                    continue;
                }
                if (!pool.entryPrefix(e.getKey()).isEmpty()) {
                    continue;
                }
                String current = mappings.mappedClass(e.getKey());
                if (!current.equals(entry.outputName)) {
                    continue;
                }
                pool.putRawOutput(current, entry.bytes);
                reused++;
            }
            stats.add("incremental.reused", reused);
            stats.add("incremental.candidates", entries.size());
        }
    }

    private static final class Entry {
        final String hash;
        final String outputName;
        byte[] bytes;

        Entry(String hash, String outputName, byte[] bytes) {
            this.hash = hash;
            this.outputName = outputName;
            this.bytes = bytes;
        }
    }
}

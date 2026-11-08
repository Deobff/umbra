package io.umbra.core.pass.impl;

import io.umbra.core.api.OutputPostProcessor;
import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.jni.KeyRootCode;
import io.umbra.core.runtime.crypto.UmbraCrypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * V27: anchors the loader's bytes in the native bridge.
 *
 * <p>The Java-side self checks live in the class they protect, so a patched
 * loader can simply delete them. This pass runs after every other pass and
 * after the archive exists: it hashes the <em>final</em> loader class and pins
 * that digest inside the compiled bridge, where the loader cannot reach it.
 * The bridge then answers {@code verifyLoader(byte[])} in constant time.</p>
 *
 * <p>Seed builds have no bridge; they log a warning because they cannot detect
 * a patched loader.</p>
 */
public final class NativeLoaderDigestPass implements Pass {

    private static final byte[] MAGIC_LOADER = {'U', 'M', 'B', 'R', 'A', 'D', 'G', '1'};
    private static final byte[] MAGIC_BRIDGE = {'U', 'M', 'B', 'R', 'A', 'D', 'G', '2'};
    private static final int DIGEST_SIZE = 32;

    @Override
    public String name() {
        return "native-loader-digest";
    }

    @Override
    public int order() {
        return 260;
    }

    @Override
    public boolean enabled(PassContext context) {
        return true;
    }

    @Override
    public void run(PassContext context) {
        final String loaderName = context.classes().getMeta("native.loader");
        final String bridgeResource = context.classes().getMeta("native.bridge.resource");
        final byte[] root = context.secret(PassContext.NATIVE_KEY_ROOT);
        final String digestKeyHex = context.classes().getMeta("native.digestKey");
        if (loaderName == null || loaderName.isEmpty() || bridgeResource == null
                || bridgeResource.isEmpty() || digestKeyHex == null) {
            context.log().warn("native-loader-digest: no bridge in this build; a patched loader "
                    + "cannot be detected natively (seed tier)");
            context.stats().add("native.loaderDigest", 0);
            return;
        }
        final String fallbackEntry = loaderName.replace('.', '/') + ".class";
        final String bridgeEntry = loaderName.replace('.', '/') + ".class";
        context.postProcessors().add(new OutputPostProcessor() {
            @Override
            public String name() {
                return "native-loader-digest";
            }

            @Override
            public void process(Path output, PassContext run) throws Exception {
                Map<String, byte[]> entries = read(output);

                String publishedBridge = run.stats().text("classEncryption.bridgeEntry");
                if (publishedBridge == null || publishedBridge.isEmpty()) {
                    publishedBridge = run.stats().text("classEncryption.native.bridgeEntry");
                }
                String publishedBridgeSha = run.stats().text("classEncryption.bridgeSha256");
                String publishedEntry = run.stats().text("classEncryption.loaderEntry");
                String publishedSha = run.stats().text("classEncryption.loaderSha256");
                String loaderEntry = publishedEntry == null || publishedEntry.isEmpty()
                        ? fallbackEntry
                        : publishedEntry;
                run.log().info("native-loader-digest: target=%s publishedSha=%s", loaderEntry,
                        publishedSha == null ? "(none)" : publishedSha);
                byte[] loaderBytes = entries.get(loaderEntry);
                if (loaderBytes == null) {
                    throw new IllegalStateException(
                            "native-loader-digest: loader entry missing from the archive: "
                                    + loaderEntry);
                }
                byte[] bridge = entries.get(bridgeResource);
                if (bridge == null) {
                    throw new IllegalStateException(
                            "native-loader-digest: bridge resource missing: " + bridgeResource);
                }

                byte[] loaderShaPinned = publishedSha != null && publishedSha.length() == 64
                        ? hexToBytes(publishedSha)
                        : sha256Bytes(loaderBytes);
                String entrySha = sha256Hex(loaderBytes);
                run.log().info("native-loader-digest: entry sha256=%s len=%d", entrySha,
                        Integer.valueOf(loaderBytes.length));
                if (publishedSha != null && !publishedSha.isEmpty()
                        && !publishedSha.equalsIgnoreCase(entrySha)) {
                    throw new IllegalStateException(
                            "native-loader-digest: loader entry changed after class-encryption");
                }
                byte[] digest = loaderShaPinned;
                if (digest == null || digest.length != DIGEST_SIZE) {
                    throw new IllegalStateException("native-loader-digest: digest failed");
                }

                String resolvedBridgeEntry = publishedBridge == null || publishedBridge.isEmpty()
                        ? bridgeEntry
                        : publishedBridge;
                byte[] bridgeBytes = entries.get(resolvedBridgeEntry);
                if (bridgeBytes == null) {
                    throw new IllegalStateException(
                            "native-loader-digest: bridge class missing: " + resolvedBridgeEntry);
                }

                run.log().info("native-loader-digest: bridgeEntry=%s bridgeSha=%s",
                        resolvedBridgeEntry, publishedBridgeSha == null ? "(none)" : publishedBridgeSha);
                byte[] bridgeDigest = publishedBridgeSha != null
                        && publishedBridgeSha.length() == 64
                        ? hexToBytes(publishedBridgeSha)
                        : sha256Bytes(bridgeBytes);
                byte[] patched = bridge.clone();
                patchSlot(patched, MAGIC_LOADER, digest, "loader");
                patchSlot(patched, MAGIC_BRIDGE, bridgeDigest, "bridge");
                entries.put(bridgeResource, patched);
                write(output, entries);
                run.stats().add("native.loaderDigest", 1);
                run.log().info("native-loader-digest: pinned %s inside %s (digest=%s)",
                        loaderEntry, bridgeResource, hex(digest));
            }
        });
    }

    private static byte[] sha256Bytes(byte[] data) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(data);
        } catch (java.security.NoSuchAlgorithmException missing) {
            throw new IllegalStateException("native-loader-digest: sha256 unavailable", missing);
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(data);
            return hex(hash);
        } catch (java.security.NoSuchAlgorithmException missing) {
            throw new IllegalStateException("native-loader-digest: sha256 unavailable", missing);
        }
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() != 64) {
            throw new IllegalStateException("native-loader-digest: bad digest key");
        }
        byte[] bytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(Character.forDigit((value >> 4) & 0xF, 16));
            text.append(Character.forDigit(value & 0xF, 16));
        }
        return text.toString();
    }

    private static void patchSlot(byte[] data, byte[] magic, byte[] digest, String label) {
        int at = findMagic(data, magic);
        if (at < 0) {
            throw new IllegalStateException(
                    "native-loader-digest: missing " + label + " digest slot");
        }
        int from = at + magic.length;
        System.arraycopy(digest, 0, data, from, DIGEST_SIZE);
        for (int i = 0; i < 8; i++) {
            if (data[from + i] != digest[i]) {
                throw new IllegalStateException(
                        "native-loader-digest: " + label + " slot did not take the digest");
            }
        }
    }

    private static int findMagic(byte[] data, byte[] magic) {
        int found = -1;
        outer:
        for (int i = 0; i + magic.length + DIGEST_SIZE <= data.length; i++) {
            for (int j = 0; j < magic.length; j++) {
                if (data[i + j] != magic[j]) {
                    continue outer;
                }
            }
            if (found >= 0) {
                return -1;
            }
            found = i;
            i += magic.length - 1;
        }
        return found;
    }

    private static Map<String, byte[]> read(Path archive) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<String, byte[]>();
        zipComment = null;
        java.util.zip.ZipFile file = new java.util.zip.ZipFile(archive.toFile());
        try {
            zipComment = file.getComment();
            java.util.Enumeration<? extends ZipEntry> list = file.entries();
            byte[] buffer = new byte[8192];
            while (list.hasMoreElements()) {
                ZipEntry entry = list.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                InputStream in = file.getInputStream(entry);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int read;
                while ((read = in.read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                }
                in.close();
                entries.put(entry.getName(), out.toByteArray());
            }
        } finally {
            file.close();
        }
        return entries;
    }

    private static String zipComment;

    private static void write(Path archive, Map<String, byte[]> entries) throws IOException {
        Path sibling = archive.resolveSibling(archive.getFileName() + ".digest-tmp");
        List<String> order = new ArrayList<String>(entries.keySet());
        String manifest = "META-INF/MANIFEST.MF";
        if (order.remove(manifest)) {
            order.add(0, manifest);
        }
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(sibling))) {
            if (zipComment != null) {
                zip.setComment(zipComment);
            }
            for (String entryName : order) {
                ZipEntry entry = new ZipEntry(entryName);
                zip.putNextEntry(entry);
                zip.write(entries.get(entryName));
                zip.closeEntry();
            }
        }
        if (zipComment != null) {
            java.util.zip.ZipFile check = new java.util.zip.ZipFile(sibling.toFile());
            try {
                if (check.getComment() == null) {
                    throw new IllegalStateException(
                            "native-loader-digest: archive comment was lost while rewriting");
                }
            } finally {
                check.close();
            }
        }
        Files.move(sibling, archive, StandardCopyOption.REPLACE_EXISTING);
    }
}

package io.umbra.core.pass.impl;

import io.umbra.core.api.OutputPostProcessor;
import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.model.ClassPool;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.crypto.CryptoSupport;
import io.umbra.core.runtime.crypto.GuardSupport;
import io.umbra.core.runtime.crypto.UmbraIntegrityGuard;
import io.umbra.core.runtime.crypto.UmbraWatchdog;
import io.umbra.core.util.Cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Startup integrity / anti-tamper guard for archives that are not encrypted.
 *
 * <p>Injects the {@code UmbraIntegrityGuard} runtime template, calls
 * {@code check()} from every program entry point and registers an archive
 * post-processor that, after the writer produced the final JAR, appends a
 * sealed manifest of per-entry SHA-256 digests plus an aggregate digest. The
 * guard rebuilds the digest map at startup and compares it:</p>
 *
 * <ul>
 *   <li>{@code integrity.level=1} - aggregate (manifest) digest.</li>
 *   <li>{@code integrity.level=2} - aggregate + every class entry digest.</li>
 *   <li>{@code integrity.level=3} - every entry digest + periodic re-check.</li>
 *   <li>{@code integrity.action} = {@code exit|throw|corrupt}.</li>
 *   <li>{@code integrity.antiDump} refuses debug/dump agents and duplicate
 *       archive entries.</li>
 * </ul>
 *
 * <p>When {@code classEncryption.enabled=true} this pass delegates to the
 * encrypted-archive loader, which folds the digest checks into its sealed
 * payload index (running both would double-encrypt and invalidate the archive
 * digests).</p>
 */
public final class IntegrityPass implements Pass {

    @Override
    public String name() {
        return "integrity";
    }

    @Override
    public int order() {
        return 117;
    }

    @Override
    public boolean enabled(PassContext context) {
        boolean enabled = context.config().optionBool("integrity.enabled", false);
        if (!enabled) {
            return false;
        }
        io.umbra.core.compat.JarLayout layout =
                io.umbra.core.compat.LayoutRegistry.layout(context.classes());
        if ((!layout.isFlat() || layout.moduleInfo())
                && !context.config().optionBool("layout.forceEntryProtection", false)) {
            context.log().warn("integrity: skipped on %s layout (archive-digest sealing is a flat-JAR "
                    + "protection; the nested container and its libs are not covered by the seal); "
                    + "use a flat JAR for startup integrity", layout.kindId());
            context.stats().add("layout.guard.skipped", 1);
            context.stats().add("integrity.skipped.layout", 1);
            context.stats().text("layout.guard.integrity", "skipped:" + layout.kindId());
            return false;
        }
        return true;
    }

    @Override
    public void run(PassContext context) {
        UmbraConfig config = context.config();
        if (config.optionBool("classEncryption.enabled", false)) {
            context.log().info("integrity: delegated to the encrypted-archive loader "
                    + "(classEncryption.integrity=%s)", Boolean.valueOf(
                    config.optionBool("classEncryption.integrity", true)));
            return;
        }
        int level = level(config);
        String action = action(config);
        boolean antiDump = config.optionBool("integrity.antiDump", true);

        Random random = new Random(config.seed() ^ 0x4974656772697479L);
        byte[][] parts = new byte[4][];
        for (int i = 0; i < parts.length; i++) {
            parts[i] = Cipher.randomBytes(random, 8);
        }
        byte[] salt = Cipher.randomBytes(random, 16);
        byte[] material = new byte[0];
        for (int i = 0; i < parts.length; i++) {
            material = Cipher.concat(material, parts[i]);
        }
        byte[] master = Cipher.hmacSha256(material, salt);
        Cipher.wipe(material);

        // Reuse the unified runtime guard so an instrumented process is refused
        // before the archive digests are trusted. When the anti-debug pass runs it
        // already injected the same (seed-derived) guard class, so this call only
        // asks for its name; otherwise the guard is injected here at level 2.
        String runtimeGuard = "";
        if (antiDump) {
            int guardLevel = AntiDebugPass.resolveLevel(config);
            String guardAction = AntiDebugPass.resolveAction(config);
            if (guardLevel <= 0) {
                guardLevel = 2;
                guardAction = action;
            }
            if ("log".equals(guardAction)) {
                guardAction = "throw"; // the integrity layer cannot continue after a logged signal
            }
            Map<String, String> guardReplacements = new LinkedHashMap<String, String>();
            guardReplacements.put("@@LEVEL@@", String.valueOf(guardLevel));
            guardReplacements.put("@@THREAD@@", "false");
            guardReplacements.put("@@JVMTI@@", String.valueOf(config.optionBool("antiDebug.jvmti", true)));
            guardReplacements.put("@@ATTACH@@", String.valueOf(config.optionBool("antiDebug.attach", true)));
            guardReplacements.put("@@ATTACHWATCH@@",
                    String.valueOf(config.optionBool("antiDebug.attachWatch", true)));
            guardReplacements.put("@@PORTPROBE@@",
                    String.valueOf(config.optionBool("antiDebug.portProbe", false)));
            guardReplacements.put("@@ENV@@", String.valueOf(config.optionBool("antiDebug.env", true)));
            guardReplacements.put("@@TIMING@@", String.valueOf(config.optionBool("antiDebug.timing", true)));
            guardReplacements.put("@@ACTION@@", guardAction);
            guardReplacements.put("@@WATCHDOG@@", "");
            guardReplacements.put("@@LOGTOKEN@@", AntiDebugPass.logToken(config));
            guardReplacements.put("@@WATCHMS@@", String.valueOf(
                    Math.max(1000L, config.optionLong("antiDebug.watchdogMs", 4000L))));
            runtimeGuard = GuardSupport.ensureRuntimeGuard(context.classes(), config.seed(),
                    guardReplacements).replace('/', '.');
        }

        String digestEntry = randomEntryName(context, random);
        String crypto = CryptoSupport.ensureCrypto(context.classes(), config.seed());
        String guard = CryptoSupport.randomName(context.classes(), config.seed(),
                "integrity-guard", "umbra/runtime/G");
        String watchdog = "";
        if (level >= 3) {
            watchdog = TemplateInjector.inject(context.classes(), UmbraWatchdog.class,
                    "umbra/runtime/W", config.seed()).replace('/', '.');
        }
        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put("@@DIGEST@@", digestEntry);
        replacements.put("@@P0@@", Cipher.base64(parts[0]));
        replacements.put("@@P1@@", Cipher.base64(parts[1]));
        replacements.put("@@P2@@", Cipher.base64(parts[2]));
        replacements.put("@@P3@@", Cipher.base64(parts[3]));
        replacements.put("@@SALT@@", Cipher.base64(salt));
        replacements.put("@@ACTION@@", action);
        replacements.put("@@LEVEL@@", String.valueOf(level));
        replacements.put("@@ANTIDUMP@@", String.valueOf(antiDump));
        replacements.put("@@WATCHDOG@@", watchdog);
        replacements.put("@@RUNTIMEGUARD@@", runtimeGuard);
        CryptoSupport.injectWithCrypto(context.classes(), UmbraIntegrityGuard.class, guard, crypto,
                replacements);

        String[] entry = GuardSupport.parseEntryPoint(config.option("classEncryption.entry", ""));
        int instrumented = entry == null
                ? GuardSupport.instrumentMains(context.classes(), guard)
                : GuardSupport.instrumentEntryPoints(context.classes(), guard, entry[0], entry[1]);
        if (instrumented == 0) {
            context.log().warn("integrity: no program entry point found; guard not referenced, "
                    + "no archive manifest written");
            return;
        }
        context.postProcessors().add(new ManifestPostProcessor(guard, digestEntry, master,
                level, action, antiDump));
        context.stats().add("integrity.level", level);
        context.stats().add("integrity.guard", 1);
        if (!runtimeGuard.isEmpty()) {
            context.stats().add("integrity.runtimeGuard", 1);
        }
        context.log().info("integrity: level %d guard %s called from %d entry point(s) (action=%s, "
                        + "antiDump=%s, runtimeGuard=%s)",
                level, guard, instrumented, action, Boolean.valueOf(antiDump),
                runtimeGuard.isEmpty() ? "-" : runtimeGuard);
    }

    private static int level(UmbraConfig config) {
        int level = config.optionInt("integrity.level", 1);
        if (level < 1) {
            return 1;
        }
        return Math.min(level, 3);
    }

    private static String action(UmbraConfig config) {
        String value = config.option("integrity.action", "throw").trim().toLowerCase(Locale.ROOT);
        if ("exit".equals(value) || "throw".equals(value) || "corrupt".equals(value)) {
            return value;
        }
        return "throw";
    }

    private static String randomEntryName(PassContext context, Random random) {
        ClassPool pool = context.classes();
        for (int attempt = 0; attempt < 1000; attempt++) {
            StringBuilder name = new StringBuilder("META-INF/");
            String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            for (int i = 0; i < 16; i++) {
                name.append(alphabet.charAt(random.nextInt(alphabet.length())));
            }
            String candidate = name.toString();
            if (pool.resource(candidate) == null && pool.getClass(candidate) == null) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate an integrity manifest entry name");
    }

    /**
     * Post-processor that appends the sealed integrity manifest. Excludes the
     * guard class and the manifest itself (a file cannot contain its own hash).
     */
    private static final class ManifestPostProcessor implements OutputPostProcessor {
        private final String guard;
        private final String digestEntry;
        private final byte[] master;
        private final int level;
        private final String action;
        private final boolean antiDump;

        ManifestPostProcessor(String guard, String digestEntry, byte[] master, int level,
                              String action, boolean antiDump) {
            this.guard = guard;
            this.digestEntry = digestEntry;
            this.master = master;
            this.level = level;
            this.action = action;
            this.antiDump = antiDump;
        }

        @Override
        public String name() {
            return "integrity-manifest";
        }

        @Override
        public void process(Path output, PassContext context) throws Exception {
            Map<String, Integer> entryMethods = new LinkedHashMap<String, Integer>();
            Map<String, byte[]> entries = readEntries(output, entryMethods);
            String guardEntry = findEntry(entries, guard + ".class");
            if (guardEntry == null) {
                throw new IOException("integrity guard class entry is missing");
            }
            List<String> names = new ArrayList<String>(entries.keySet());
            Collections.sort(names);
            ByteArrayOutputStream aggregateBody = new ByteArrayOutputStream();
            byte[][] digests = new byte[names.size()][];
            for (int i = 0; i < names.size(); i++) {
                String name = names.get(i);
                byte[] digest = Cipher.sha256(entries.get(name));
                digests[i] = digest;
                if (name.equals(guardEntry) || name.equals(digestEntry)) {
                    continue;
                }
                byte[] nameBytes = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                writeInt(aggregateBody, nameBytes.length);
                aggregateBody.write(nameBytes);
                aggregateBody.write(digest);
            }
            byte[] aggregate = Cipher.sha256(aggregateBody.toByteArray());

            ByteArrayOutputStream manifest = new ByteArrayOutputStream();
            writeInt(manifest, 0x554D4932);
            manifest.write(1);
            manifest.write(level);
            int count = 0;
            for (int i = 0; i < names.size(); i++) {
                if (!names.get(i).equals(guardEntry)) {
                    count++;
                }
            }
            writeInt(manifest, count);
            for (int i = 0; i < names.size(); i++) {
                String name = names.get(i);
                if (name.equals(guardEntry)) {
                    continue;
                }
                byte[] nameBytes = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                writeInt(manifest, nameBytes.length);
                manifest.write(nameBytes);
                manifest.write(digests[i]);
            }
            manifest.write(aggregate);

            Random random = new Random(context.config().seed() ^ 0x1D1E5L);
            byte[] nonce = Cipher.randomBytes(random, Cipher.NONCE_BYTES);
            byte[] sealed = Cipher.seal(manifest.toByteArray(), master, nonce, Cipher.Algorithm.CHACHA20);
            entries.put(digestEntry, sealed);
            rewrite(output, entries, entryMethods);

            context.stats().add("integrity.entries", count);
            context.stats().add("integrity.manifestBytes", sealed.length);
            context.log().info("integrity: manifest with %d entry digests written (%s, level %d, antiDump=%s)",
                    count, digestEntry, level, Boolean.valueOf(antiDump));
        }
    }

    // ------------------------------------------------------------------
    // JAR helpers
    // ------------------------------------------------------------------

    /** Finds a class entry by exact name or by a layout prefix (BOOT-INF/classes/...). */
    private static String findEntry(Map<String, byte[]> entries, String classNameEntry) {
        if (entries.containsKey(classNameEntry)) {
            return classNameEntry;
        }
        String suffix = "/" + classNameEntry;
        for (String name : entries.keySet()) {
            if (name.endsWith(suffix)) {
                return name;
            }
        }
        return null;
    }

    private static Map<String, byte[]> readEntries(Path jar, Map<String, Integer> methods)
            throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<String, byte[]>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            java.util.Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                methods.put(entry.getName(), Integer.valueOf(entry.getMethod()));
                InputStream in = zip.getInputStream(entry);
                try {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = in.read(buffer)) >= 0) {
                        out.write(buffer, 0, read);
                    }
                    entries.put(entry.getName(), out.toByteArray());
                } finally {
                    in.close();
                }
            }
        }
        return entries;
    }

    static void rewrite(Path jar, Map<String, byte[]> entries, Map<String, Integer> methods)
            throws IOException {
        Path parent = jar.toAbsolutePath().getParent();
        Path temp = parent.resolve(jar.getFileName().toString() + ".umbra-tmp");
        try {
            try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(temp))) {
                for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                    ZipEntry zipEntry = new ZipEntry(entry.getKey());
                    zipEntry.setTime(315532800000L);
                    Integer method = methods.get(entry.getKey());
                    if (method != null && method.intValue() == ZipEntry.STORED) {
                        // Preserve STORED entries (nested Spring Boot/WAR libs):
                        // recompressing them breaks the container loader.
                        zipEntry.setMethod(ZipEntry.STORED);
                        zipEntry.setSize(entry.getValue().length);
                        zipEntry.setCompressedSize(entry.getValue().length);
                        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
                        crc.update(entry.getValue());
                        zipEntry.setCrc(crc.getValue());
                    }
                    out.putNextEntry(zipEntry);
                    out.write(entry.getValue());
                    out.closeEntry();
                }
            }
            try {
                Files.move(temp, jar, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException notAtomic) {
                Files.move(temp, jar, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }
}

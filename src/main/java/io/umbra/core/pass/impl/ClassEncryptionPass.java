package io.umbra.core.pass.impl;

import io.umbra.core.api.OutputPostProcessor;
import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.model.ClassPool;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.crypto.CryptoSupport;
import io.umbra.core.runtime.crypto.GuardSupport;
import io.umbra.core.runtime.crypto.UmbraClassLoader;
import io.umbra.core.runtime.crypto.UmbraResourceConnection;
import io.umbra.core.runtime.crypto.UmbraResourceHandler;
import io.umbra.core.runtime.crypto.UmbraWatchdog;
import io.umbra.core.util.Cipher;
import io.umbra.core.util.Jars;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Whole-archive encryption with a plaintext bootstrap loader.
 *
 * <p>Runs as an archive post-processor: after the engine wrote the JAR, every
 * class entry <em>and</em> every resource entry is sealed with
 * ChaCha20/AES-256-CTR + HMAC-SHA-256 and moved to a random, extension-less
 * entry name; a sealed index carries the class map and the resource map
 * (logical name, payload entry, plaintext size and SHA-256 digest). The only
 * plaintext class files left are the injected loader and its infrastructure
 * helpers (crypto, URL handler, URL connection); the loader becomes
 * {@code Main-Class}.</p>
 *
 * <p>At runtime {@code UmbraClassLoader} decrypts classes on demand
 * ({@code defineClass}/{@code definePackage}, correct
 * {@code CodeSource}/{@code ProtectionDomain}) and serves decrypted resources
 * through a custom {@code URLStreamHandler}, so {@code getResource},
 * {@code getResourceAsStream}, {@code getResources} and URL-based loaders all
 * keep working without ever writing plaintext to disk. It then invokes the
 * original entry point. {@code getResource} returns URLs whose
 * {@code openStream()} decrypts the payload lazily.</p>
 *
 * <p>Options: {@code classEncryption.enabled}, {@code .algorithm},
 * {@code .integrity} (+ {@code integrity.level}/{@code integrity.action}),
 * {@code .antiDump}, {@code .loaderClass}, {@code .entry},
 * {@code .resources} (encrypt non-class entries, default true),
 * {@code .resourceIntegrity} (digest-check resources at levels 2/3),
 * {@code .minResourceSize} (keep smaller entries plaintext for compatibility)
 * and {@code .manifestMinimal} (strip the manifest down to
 * {@code Manifest-Version} + {@code Main-Class}; otherwise only
 * remote/agent/class-path attributes are stripped).</p>
 *
 * <p>The rewrite is atomic: a sibling temp file is moved over the original
 * archive.</p>
 */
public final class ClassEncryptionPass implements Pass {

    private static final long FIXED_TIME = 315532800000L; // 1980-01-01

    /** Internal names of compile-time templates remapped at injection time. */
    private static final String LOADER_TEMPLATE = "io/umbra/core/runtime/crypto/UmbraClassLoader";
    private static final String HANDLER_TEMPLATE = "io/umbra/core/runtime/crypto/UmbraResourceHandler";
    private static final String CONNECTION_TEMPLATE = "io/umbra/core/runtime/crypto/UmbraResourceConnection";

    private static final int MAGIC = 0x554D4232;
    private static final int INDEX_VERSION = 2;
    private static final int FLAG_INTEGRITY = 1;
    private static final int FLAG_ANTIDUMP = 2;
    private static final int FLAG_RESOURCE_INTEGRITY = 4;
    private static final int ALG_SHIFT = 3;

    @Override
    public String name() {
        return "class-encryption";
    }

    @Override
    public int order() {
        return 200;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("classEncryption.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        UmbraConfig config = context.config();
        ClassPool pool = context.classes();

        String[] entry = resolveEntryPoint(context);
        if (entry == null) {
            context.log().warn("class-encryption: no entry point found (no Main-Class, no main(String[]) "
                    + "and classEncryption.entry is not set); archive left unencrypted");
            return;
        }
        String entryClass = entry[0];
        String entryMethod = entry[1];

        Cipher.Algorithm algorithm = Cipher.Algorithm.parse(
                config.option("classEncryption.algorithm", "chacha20"), Cipher.Algorithm.CHACHA20);
        if (algorithm == Cipher.Algorithm.XOR) {
            algorithm = Cipher.Algorithm.CHACHA20;
        }
        boolean integrity = config.optionBool("classEncryption.integrity", true);
        int level = integrity ? integrityLevel(config) : 0;
        boolean antiDump = config.optionBool("classEncryption.antiDump", true);
        String action = integrityAction(config);
        boolean encryptResources = config.optionBool("classEncryption.resources", true);
        boolean resourceIntegrity = config.optionBool("classEncryption.resourceIntegrity", true);
        boolean manifestMinimal = config.optionBool("classEncryption.manifestMinimal", true);
        int minResourceSize = Math.max(0, config.optionInt("classEncryption.minResourceSize", 0));

        Random random = new Random(config.seed() ^ 0x434C415353454E43L);
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

        String configuredLoader = config.option("classEncryption.loaderClass", "").trim().replace('.', '/');
        String loaderName;
        if (configuredLoader.isEmpty()) {
            loaderName = CryptoSupport.randomName(pool, config.seed(), "class-loader", "umbra/runtime/L");
        } else {
            loaderName = configuredLoader;
            if (pool.getClass(loaderName) != null) {
                context.log().warn("class-encryption: classEncryption.loaderClass=%s already exists in the "
                        + "input; archive left unencrypted", loaderName);
                return;
            }
        }
        String cryptoName = CryptoSupport.ensureCrypto(pool, config.seed());
        String connectionName = uniqueTemplateName(pool, config.seed(), "resource-connection",
                "umbra/runtime/K", loaderName);
        String handlerName = uniqueTemplateName(pool, config.seed(), "resource-handler",
                "umbra/runtime/H", loaderName, connectionName);
        String watchdog = "";
        if (level >= 3) {
            watchdog = TemplateInjector.inject(pool, UmbraWatchdog.class, "umbra/runtime/W",
                    config.seed()).replace('/', '.');
        }
        // The encrypted loader refuses to decrypt/define classes while the unified
        // runtime guard reports a signal. The anti-debug pass (order 115) already
        // injected the shared seed-derived guard class; this call retrieves the same
        // name, so the loader and the entry-point guards consult one detector.
        String runtimeGuard = "";
        int guardLevel = AntiDebugPass.resolveLevel(config);
        if (guardLevel > 0) {
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
            guardReplacements.put("@@ACTION@@", AntiDebugPass.resolveAction(config));
            guardReplacements.put("@@WATCHDOG@@", "");
            guardReplacements.put("@@WATCHMS@@", String.valueOf(
                    Math.max(1000L, config.optionLong("antiDebug.watchdogMs", 4000L))));
            runtimeGuard = GuardSupport.ensureRuntimeGuard(pool, config.seed(), guardReplacements)
                    .replace('/', '.');
        }
        String indexEntry = randomResourceName(random);
        for (int attempt = 0; attempt < 1000 && (pool.resource(indexEntry) != null
                || pool.getClass(indexEntry) != null); attempt++) {
            indexEntry = randomResourceName(random);
        }

        Map<String, String> loaderRemap = new LinkedHashMap<String, String>();
        loaderRemap.put(LOADER_TEMPLATE, loaderName);
        CryptoSupport.injectWithCrypto(pool, UmbraResourceConnection.class, connectionName, null, null,
                loaderRemap);

        Map<String, String> handlerRemap = new LinkedHashMap<String, String>(loaderRemap);
        handlerRemap.put(CONNECTION_TEMPLATE, connectionName);
        CryptoSupport.injectWithCrypto(pool, UmbraResourceHandler.class, handlerName, null, null,
                handlerRemap);

        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put("@@INDEX@@", indexEntry);
        replacements.put("@@P0@@", Cipher.base64(parts[0]));
        replacements.put("@@P1@@", Cipher.base64(parts[1]));
        replacements.put("@@P2@@", Cipher.base64(parts[2]));
        replacements.put("@@P3@@", Cipher.base64(parts[3]));
        replacements.put("@@SALT@@", Cipher.base64(salt));
        replacements.put("@@ACTION@@", action);
        replacements.put("@@WATCHDOG@@", watchdog);
        replacements.put("@@GUARD@@", runtimeGuard);
        Map<String, String> loaderExtra = new LinkedHashMap<String, String>();
        loaderExtra.put(HANDLER_TEMPLATE, handlerName);
        CryptoSupport.injectWithCrypto(pool, UmbraClassLoader.class, loaderName, cryptoName, replacements,
                loaderExtra);
        pool.setMainClass(loaderName);

        ArchivePostProcessor processor = new ArchivePostProcessor(loaderName, cryptoName, connectionName,
                handlerName, indexEntry, master, algorithm, integrity, level, antiDump, encryptResources,
                resourceIntegrity, manifestMinimal, minResourceSize, entryClass, entryMethod,
                new Random(config.seed() ^ 0x5EA1ED1L));
        context.postProcessors().add(processor);
        context.stats().add("classEncryption.algorithmCode", algorithm == Cipher.Algorithm.AES_CTR ? 2 : 1);
        if (!runtimeGuard.isEmpty()) {
            context.stats().add("classEncryption.runtimeGuard", 1);
        }
        context.log().info("class-encryption: registered archive post-processor (loader=%s, alg=%s, "
                        + "integrity=%s/%d, antiDump=%s, resources=%s, resourceIntegrity=%s, "
                        + "minResourceSize=%d, manifestMinimal=%s, entry=%s#%s, runtimeGuard=%s)",
                loaderName, algorithm.id(), Boolean.valueOf(integrity), level, Boolean.valueOf(antiDump),
                Boolean.valueOf(encryptResources), Boolean.valueOf(resourceIntegrity), minResourceSize,
                Boolean.valueOf(manifestMinimal), entryClass, entryMethod,
                runtimeGuard.isEmpty() ? "-" : runtimeGuard);
        // The engine's --verify step only sees the plaintext loader and its
        // infrastructure helpers; encrypted payloads are linked and digest
        // checked by the loader at runtime, so verification cannot fail on them.
        context.log().info("class-encryption: note: --verify links only the plaintext loader/helpers; "
                + "encrypted classes and resources are verified by the loader at runtime");
    }

    /**
     * Allocates a template name that is deterministic for the seed and cannot
     * collide with the loader itself or with other injected helpers.
     */
    private static String uniqueTemplateName(ClassPool pool, long seed, String salt, String prefix,
                                             String... reserved) {
        for (int attempt = 0; attempt < 10000; attempt++) {
            String candidate = CryptoSupport.randomName(pool, seed + attempt, salt, prefix);
            boolean conflict = false;
            for (int i = 0; i < reserved.length; i++) {
                if (candidate.equals(reserved[i])) {
                    conflict = true;
                    break;
                }
            }
            if (!conflict) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate an injected helper name");
    }

    // ------------------------------------------------------------------
    // Entry point detection
    // ------------------------------------------------------------------

    private static String[] resolveEntryPoint(PassContext context) {
        UmbraConfig config = context.config();
        ClassPool pool = context.classes();
        String[] explicit = GuardSupport.parseEntryPoint(config.option("classEncryption.entry", ""));
        if (explicit != null) {
            ClassNode node = pool.getClass(explicit[0]);
            if (node == null) {
                context.log().warn("class-encryption: explicit entry class %s is not in the input",
                        explicit[0]);
                return null;
            }
            if (findMainMethod(node, explicit[1]) == null) {
                context.log().warn("class-encryption: explicit entry method %s#%s(String[]) does not exist",
                        explicit[0], explicit[1]);
                return null;
            }
            return new String[] { explicit[0], explicit[1] };
        }
        String mainClass = pool.mainClass();
        if (mainClass != null) {
            mainClass = context.mappings().mappedClass(mainClass);
            ClassNode node = pool.getClass(mainClass);
            if (node != null && findMainMethod(node, "main") != null) {
                return new String[] { mainClass, "main" };
            }
        }
        List<String> names = new ArrayList<String>(pool.classes().keySet());
        for (int i = 0; i < names.size(); i++) {
            ClassNode node = pool.getClass(names.get(i));
            if (node == null || pool.isGenerated(node.name)) {
                continue;
            }
            if (findMainMethod(node, "main") != null) {
                return new String[] { node.name, "main" };
            }
        }
        return null;
    }

    private static MethodNode findMainMethod(ClassNode node, String name) {
        for (MethodNode method : node.methods) {
            if (!name.equals(method.name) || !"([Ljava/lang/String;)V".equals(method.desc)) {
                continue;
            }
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                continue;
            }
            return method;
        }
        return null;
    }

    private static int integrityLevel(UmbraConfig config) {
        int level = config.optionInt("integrity.level", 1);
        if (level < 1) {
            return 1;
        }
        return Math.min(level, 3);
    }

    private static String integrityAction(UmbraConfig config) {
        // Documented default is throw (OPTIONS.md integrity.action); 3.0 code
        // used exit here, which made a tampered archive shut down silently.
        String value = config.option("integrity.action", "throw").trim().toLowerCase(Locale.ROOT);
        if ("exit".equals(value) || "throw".equals(value) || "corrupt".equals(value)) {
            return value;
        }
        return "throw";
    }

    private static String randomResourceName(Random random) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 18; i++) {
            builder.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return builder.toString();
    }

    private static String randomPayloadName(Random random, Set<String> used) {
        for (int attempt = 0; attempt < 10000; attempt++) {
            String candidate = randomResourceName(random);
            if (used.add(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate an encrypted payload entry name");
    }

    // ------------------------------------------------------------------
    // Post-processor
    // ------------------------------------------------------------------

    /** Rewrites the finished archive: encrypts classes + resources, injects loader/index. */
    private static final class ArchivePostProcessor implements OutputPostProcessor {
        private final String loaderName;
        private final String cryptoName;
        private final String connectionName;
        private final String handlerName;
        private final String indexEntry;
        private final byte[] master;
        private final Cipher.Algorithm algorithm;
        private final boolean integrity;
        private final int level;
        private final boolean antiDump;
        private final boolean encryptResources;
        private final boolean resourceIntegrity;
        private final boolean manifestMinimal;
        private final int minResourceSize;
        private final String entryClass;
        private final String entryMethod;
        private final Random random;

        ArchivePostProcessor(String loaderName, String cryptoName, String connectionName, String handlerName,
                             String indexEntry, byte[] master, Cipher.Algorithm algorithm, boolean integrity,
                             int level, boolean antiDump, boolean encryptResources, boolean resourceIntegrity,
                             boolean manifestMinimal, int minResourceSize, String entryClass,
                             String entryMethod, Random random) {
            this.loaderName = loaderName;
            this.cryptoName = cryptoName;
            this.connectionName = connectionName;
            this.handlerName = handlerName;
            this.indexEntry = indexEntry;
            this.master = master;
            this.algorithm = algorithm;
            this.integrity = integrity;
            this.level = level;
            this.antiDump = antiDump;
            this.encryptResources = encryptResources;
            this.resourceIntegrity = resourceIntegrity;
            this.manifestMinimal = manifestMinimal;
            this.minResourceSize = minResourceSize;
            this.entryClass = entryClass;
            this.entryMethod = entryMethod;
            this.random = random;
        }

        @Override
        public String name() {
            return "class-encryption";
        }

        @Override
        public void process(Path output, PassContext context) throws Exception {
            Map<String, Integer> entryMethods = new LinkedHashMap<String, Integer>();
            Map<String, byte[]> entries = readEntries(output, entryMethods);
            String loaderEntry = loaderName + ".class";
            byte[] loaderBytes = entries.remove(loaderEntry);
            if (loaderBytes == null) {
                throw new IOException("class-encryption: injected loader entry is missing");
            }
            Set<String> infrastructureEntries = new LinkedHashSet<String>();
            infrastructureEntries.add(loaderEntry);
            infrastructureEntries.add(cryptoName + ".class");
            infrastructureEntries.add(connectionName + ".class");
            infrastructureEntries.add(handlerName + ".class");

            byte[] oldManifest = entries.get("META-INF/MANIFEST.MF");
            Map<String, String> attributes = buildManifest(oldManifest);
            Set<String> plaintextClasses = new LinkedHashSet<String>();
            plaintextClasses.add(loaderName.replace('/', '.'));
            plaintextClasses.add(cryptoName.replace('/', '.'));
            plaintextClasses.add(connectionName.replace('/', '.'));
            plaintextClasses.add(handlerName.replace('/', '.'));
            plaintextClasses.add("module-info");

            Map<String, byte[]> rewritten = new LinkedHashMap<String, byte[]>();
            rewritten.put("META-INF/MANIFEST.MF", Jars.writeManifest(attributes));
            rewritten.put(loaderEntry, loaderBytes);
            for (String infrastructure : infrastructureEntries) {
                if (infrastructure.equals(loaderEntry)) {
                    continue;
                }
                byte[] bytes = entries.get(infrastructure);
                if (bytes == null) {
                    throw new IOException("class-encryption: injected helper entry is missing: "
                            + infrastructure);
                }
                rewritten.put(infrastructure, bytes);
            }

            Set<String> usedNames = new LinkedHashSet<String>();
            for (String existing : entries.keySet()) {
                usedNames.add(existing);
            }
            usedNames.add("META-INF/MANIFEST.MF");
            usedNames.addAll(infrastructureEntries);
            usedNames.add(indexEntry);

            List<String> classNames = new ArrayList<String>();
            List<String> classPayloads = new ArrayList<String>();
            List<byte[]> classDigests = new ArrayList<byte[]>();
            List<String> resourceNames = new ArrayList<String>();
            List<String> resourcePayloads = new ArrayList<String>();
            List<byte[]> resourceDigests = new ArrayList<byte[]>();
            List<Integer> resourceSizes = new ArrayList<Integer>();
            long resourceBytes = 0L;
            int plaintextResources = 0;

            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String name = entry.getKey();
                byte[] bytes = entry.getValue();
                if (name.equals("META-INF/MANIFEST.MF") || name.equals("META-INF/INDEX.LIST")) {
                    continue;
                }
                if (isSignatureFile(name)) {
                    continue;
                }
                if (name.startsWith("META-INF/versions/") && name.endsWith(".class")) {
                    context.log().debug("class-encryption: dropping versioned class entry %s", name);
                    continue;
                }
                if (infrastructureEntries.contains(name)) {
                    continue; // already written plaintext above
                }
                if (!name.endsWith(".class")) {
                    if (encryptResources && bytes.length >= minResourceSize) {
                        String payloadName = randomPayloadName(random, usedNames);
                        rewritten.put(payloadName, sealResource(name, bytes));
                        resourceNames.add(name);
                        resourcePayloads.add(payloadName);
                        resourceDigests.add(Cipher.sha256(bytes));
                        resourceSizes.add(Integer.valueOf(bytes.length));
                        resourceBytes += bytes.length;
                    } else {
                        // Below the threshold (or resource encryption off):
                        // keep it readable; the loader serves it through the
                        // plaintext path of findResource.
                        rewritten.put(name, bytes);
                        plaintextResources++;
                    }
                    continue;
                }
                if (name.equals("module-info.class") || name.endsWith("/module-info.class")) {
                    rewritten.put(name, bytes);
                    continue;
                }
                String binaryName;
                try {
                    binaryName = new ClassReader(bytes).getClassName().replace('/', '.');
                } catch (RuntimeException malformed) {
                    context.log().debug("class-encryption: unparseable class entry %s kept as an opaque "
                            + "resource", name);
                    rewritten.put(randomPayloadName(random, usedNames), bytes);
                    continue;
                }
                String payloadName = randomPayloadName(random, usedNames);
                byte[] key = Cipher.hmacSha256(master, Cipher.utf8("c:" + binaryName));
                byte[] nonce = Cipher.randomBytes(random, Cipher.NONCE_BYTES);
                byte[] sealed = Cipher.seal(bytes, key, nonce, algorithm);
                Cipher.wipe(key);
                rewritten.put(payloadName, sealed);
                classNames.add(binaryName);
                classPayloads.add(payloadName);
                classDigests.add(Cipher.sha256(bytes));
            }

            ByteArrayOutputStream index = new ByteArrayOutputStream();
            writeInt(index, MAGIC);
            index.write(INDEX_VERSION);
            int flags = (integrity ? FLAG_INTEGRITY : 0) | (antiDump ? FLAG_ANTIDUMP : 0)
                    | (resourceIntegrity ? FLAG_RESOURCE_INTEGRITY : 0)
                    | ((algorithm == Cipher.Algorithm.AES_CTR ? 2 : 1) << ALG_SHIFT);
            index.write(flags);
            index.write(level);
            writeInt(index, plaintextClasses.size());
            for (String plaintext : plaintextClasses) {
                writeString(index, plaintext);
            }
            writeString(index, entryClass.replace('/', '.'));
            writeString(index, entryMethod);
            index.write(Cipher.sha256(loaderBytes));
            writeInt(index, classNames.size());
            for (int i = 0; i < classNames.size(); i++) {
                writeString(index, classNames.get(i));
                writeString(index, classPayloads.get(i));
                index.write(classDigests.get(i));
            }
            writeInt(index, resourceNames.size());
            for (int i = 0; i < resourceNames.size(); i++) {
                writeString(index, resourceNames.get(i));
                writeString(index, resourcePayloads.get(i));
                index.write(resourceDigests.get(i));
                writeInt(index, resourceSizes.get(i).intValue());
            }
            byte[] nonce = Cipher.randomBytes(random, Cipher.NONCE_BYTES);
            byte[] sealedIndex = Cipher.seal(index.toByteArray(), master, nonce, Cipher.Algorithm.CHACHA20);
            rewritten.put(indexEntry, sealedIndex);

            rewrite(output, rewritten, entryMethods);
            context.stats().add("classEncryption.classes", classNames.size());
            context.stats().add("classEncryption.payloadEntries",
                    classPayloads.size() + resourcePayloads.size());
            context.stats().add("classEncryption.resources", resourceNames.size());
            context.stats().add("classEncryption.resourceEntries", resourcePayloads.size());
            context.stats().add("classEncryption.resourceBytes", resourceBytes);
            context.stats().add("classEncryption.resourcesPlaintext", plaintextResources);
            context.stats().add("classEncryption.indexBytes", sealedIndex.length);
            context.log().info("class-encryption: encrypted %d classes and %d resources (%d bytes), "
                            + "%d plaintext resources kept, loader=%s, index=%s",
                    classNames.size(), resourceNames.size(), resourceBytes, plaintextResources,
                    loaderName, indexEntry);
        }

        private Map<String, String> buildManifest(byte[] oldManifest) {
            Map<String, String> attributes = new LinkedHashMap<String, String>();
            if (oldManifest != null && !manifestMinimal) {
                attributes.putAll(Jars.parseManifest(oldManifest));
            }
            if (!attributes.containsKey("Manifest-Version")) {
                attributes.put("Manifest-Version", "1.0");
            }
            attributes.put("Main-Class", loaderName.replace('/', '.'));
            attributes.remove("Premain-Class");
            attributes.remove("Agent-Class");
            attributes.remove("Launcher-Agent-Class");
            attributes.remove("Codebase");
            attributes.remove("Class-Path");
            attributes.remove("Signature-Version");
            attributes.remove("Magic");
            attributes.remove("Created-By");
            attributes.remove("Implementation-Title");
            attributes.remove("Implementation-Version");
            return attributes;
        }

        private byte[] sealResource(String logicalName, byte[] bytes) {
            byte[] key = Cipher.hmacSha256(master, Cipher.utf8("r:" + logicalName));
            byte[] nonce = Cipher.randomBytes(random, Cipher.NONCE_BYTES);
            try {
                return Cipher.seal(bytes, key, nonce, algorithm);
            } finally {
                Cipher.wipe(key);
            }
        }

        private static boolean isSignatureFile(String name) {
            if (!name.startsWith("META-INF/")) {
                return false;
            }
            String upper = name.toUpperCase(Locale.ROOT);
            return upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA")
                    || upper.endsWith(".EC") || upper.endsWith(".SIG");
        }
    }

    // ------------------------------------------------------------------
    // I/O helpers
    // ------------------------------------------------------------------

    static Map<String, byte[]> readEntries(Path jar, Map<String, Integer> methods)
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
                    zipEntry.setTime(FIXED_TIME);
                    Integer method = methods.get(entry.getKey());
                    if (method != null && method.intValue() == ZipEntry.STORED) {
                        // Preserve STORED entries; recompressing a nested library
                        // breaks container loaders (Spring Boot/WAR).
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

    private static void writeString(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeInt(out, bytes.length);
        out.write(bytes, 0, bytes.length);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }
}

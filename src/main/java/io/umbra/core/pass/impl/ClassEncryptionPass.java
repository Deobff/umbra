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
import java.security.SecureRandom;
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
import io.umbra.core.util.RuntimeNames;

/**
 * Whole-archive encryption with a plaintext bootstrap loader.
 *
 * <p>Runs as an archive post-processor: after the engine wrote the JAR, every
 * class entry <em>and</em> every resource entry is sealed with
 * ChaCha20/AES-256-CTR + HMAC-SHA-256 and moved to a random, extension-less
 * entry name; a sealed index carries the class map and the resource map
 * (logical name, payload entry, keyed digest, plaintext size). The only
 * plaintext class files left are the injected loader and its infrastructure
 * helpers (crypto, URL handler, URL connection); the loader becomes
 * {@code Main-Class}.</p>
 *
 * <p><b>Index version 3 / sample-bound keys.</b> The archive master key is not a
 * build constant: a fresh 32-byte {@code siteSeed} is embedded in the loader and
 * the master is derived as
 * {@code HMAC-SHA256(siteSeed, "umbra.master.v3" || zipComment || LE32(entryCount))}.
 * The ZIP comment and the entry count only exist after the archive is written, so
 * the key is bound to the concrete built sample; two builds of the same input
 * produce different masters, and editing the comment or adding/removing an entry
 * makes every payload unreadable. Each payload key mixes the entry's own nonce
 * into the KDF: {@code HMAC(master, UTF8("c:"+name) || nonce)}. Index integrity
 * metadata is keyed ({@code HMAC(master, "d:c:"+name || plaintext)}) so a
 * decrypted payload cannot be verified locally without the master key.
 * {@code classEncryption.masterBinding=seed} is a documented diagnostic fallback
 * (no comment/entry-count binding); the default is {@code sample}.</p>
 *
 * <p>Runtime integrity levels are clamped to at least 2 for encrypted archives
 * (per-class keyed digest on every decrypt/define); the level-2/3 watchdog samples
 * a random slice of payloads per tick and does a full pass periodically, keeping a
 * heartbeat that the decrypt path checks so a suspended watchdog is detectable.</p>
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
    /**
     * Index format version. 4 adds the constant-pool flag; a loader built before
     * that change rejects the archive with "Unsupported encrypted archive
     * version" instead of misreading the flag.
     */
    private static final int INDEX_VERSION = 4;
    private static final int FLAG_INTEGRITY = 1;
    private static final int FLAG_ANTIDUMP = 2;
    private static final int FLAG_RESOURCE_INTEGRITY = 4;
    /** Mirrored by {@code UmbraClassLoader}: encrypted {@code CONSTANT_Utf8} data. */
    private static final int FLAG_CONSTANT_POOL = 32;
    private static final int ALG_SHIFT = 3;


    private static final int BINDING_SAMPLE = 0;
    private static final int BINDING_SEED = 1;

    /** Assumed maximum entry count for the master-key binding. */
    private static final int MAX_ENTRIES = 1_000_000;

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

        // Eclipse runnable jars resolve classes through JarRsrcLoader, which builds
        // a URLClassLoader over the archive; sealed payloads are not class files,
        // so that loader cannot work with them.
        ClassPool.Resource archiveManifest = pool.resource("META-INF/MANIFEST.MF");
        if (archiveManifest != null && io.umbra.core.util.Jars
                .parseManifest(archiveManifest.bytes()).get("Rsrc-Main-Class") != null) {
            context.log().info("class-encryption: Eclipse runnable jar, archive left unencrypted");
            return;
        }

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
        // Encrypted archives always get per-class keyed digests: level 1 is not an
        // acceptable default for a swapped payload (analysis finding P1-6).
        int level = integrity ? Math.max(2, integrityLevel(config)) : 0;
        boolean antiDump = config.optionBool("classEncryption.antiDump", true);
        String action = integrityAction(config);
        boolean encryptResources = config.optionBool("classEncryption.resources", true);
        boolean resourceIntegrity = config.optionBool("classEncryption.resourceIntegrity", true);
        boolean manifestMinimal = config.optionBool("classEncryption.manifestMinimal", true);
        int minResourceSize = Math.max(0, config.optionInt("classEncryption.minResourceSize", 0));
        long watchdogMs = Math.max(1000L, config.optionLong("classEncryption.watchdogMs", 4000L));
        String bindingName = config.option("classEncryption.masterBinding", "sample").trim()
                .toLowerCase(Locale.ROOT);
        int binding = "seed".equals(bindingName) ? BINDING_SEED : BINDING_SAMPLE;

        Random random = new Random(config.seed() ^ 0x434C415353454E43L);
        // Per-build randomness (not derived from the obfuscator seed): two builds of
        // the same input must produce a different master key and different payloads.
        SecureRandom secure = new SecureRandom();
        byte[] siteSeed = new byte[32];
        secure.nextBytes(siteSeed);
        byte[] commentBytes = null;
        if (binding == BINDING_SAMPLE) {
            commentBytes = new byte[16];
            secure.nextBytes(commentBytes);
        }
        String logToken = randomToken(secure, 8);

        String configuredLoader = config.option("classEncryption.loaderClass", "").trim().replace('.', '/');
        String loaderName;
        if (configuredLoader.isEmpty()) {
            loaderName = CryptoSupport.randomName(pool, config.seed(), "class-loader", RuntimeNames.path("L"));
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
                RuntimeNames.path("K"), loaderName);
        String handlerName = uniqueTemplateName(pool, config.seed(), "resource-handler",
                RuntimeNames.path("H"), loaderName, connectionName);
        String watchdog = "";
        if (level >= 2) {
            watchdog = TemplateInjector.inject(pool, UmbraWatchdog.class, RuntimeNames.path("W"),
                    config.seed()).replace('/', '.');
        }
        // The encrypted loader refuses to decrypt/define classes while the unified
        // runtime guard reports a signal. The anti-debug pass (order 115) already
        // injected the shared seed-derived guard class; this call retrieves the same
        // name, so the loader and the entry-point guards consult one detector.
        String runtimeGuard = "";
        int guardLevel = AntiDebugPass.resolveLevel(config);
        String guardToken = logToken;
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
            guardReplacements.put("@@LOGTOKEN@@", guardToken);
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
        replacements.put("@@SEED@@", Cipher.base64(siteSeed));
        replacements.put("@@ACTION@@", action);
        replacements.put("@@LOGTOKEN@@", logToken);
        replacements.put("@@WATCHDOG@@", watchdog);
        replacements.put("@@GUARD@@", runtimeGuard);
        replacements.put("@@WATCHMS@@", String.valueOf(watchdogMs));
        Map<String, String> loaderExtra = new LinkedHashMap<String, String>();
        loaderExtra.put(HANDLER_TEMPLATE, handlerName);
        CryptoSupport.injectWithCrypto(pool, UmbraClassLoader.class, loaderName, cryptoName, replacements,
                loaderExtra);
        pool.setMainClass(loaderName);

        ArchivePostProcessor processor = new ArchivePostProcessor(loaderName, cryptoName, connectionName,
                handlerName, indexEntry, siteSeed, commentBytes, binding, algorithm, integrity, level,
                antiDump, encryptResources, resourceIntegrity, manifestMinimal, minResourceSize,
                entryClass, entryMethod, watchdogMs, new Random(config.seed() ^ 0x5EA1ED1L));
        context.postProcessors().add(processor);
        context.stats().add("classEncryption.algorithmCode", algorithm == Cipher.Algorithm.AES_CTR ? 2 : 1);
        context.stats().add("classEncryption.indexVersion", INDEX_VERSION);
        context.stats().add("classEncryption.integrityLevel", level);
        context.stats().add("classEncryption.watchdogMs", watchdogMs);
        context.stats().add("classEncryption.masterBinding",
                binding == BINDING_SAMPLE ? 1 : 0);
        if (!runtimeGuard.isEmpty()) {
            context.stats().add("classEncryption.runtimeGuard", 1);
        }
        context.log().info("class-encryption: registered archive post-processor (loader=%s, alg=%s, "
                        + "integrity=%s/%d, antiDump=%s, resources=%s, resourceIntegrity=%s, "
                        + "minResourceSize=%d, manifestMinimal=%s, entry=%s#%s, runtimeGuard=%s, "
                        + "masterBinding=%s, index=v%d)",
                loaderName, algorithm.id(), Boolean.valueOf(integrity), level, Boolean.valueOf(antiDump),
                Boolean.valueOf(encryptResources), Boolean.valueOf(resourceIntegrity), minResourceSize,
                Boolean.valueOf(manifestMinimal), entryClass, entryMethod,
                runtimeGuard.isEmpty() ? "-" : runtimeGuard,
                binding == BINDING_SAMPLE ? "sample" : "seed", INDEX_VERSION);
        // The engine's --verify step only sees the plaintext loader and its
        // infrastructure helpers; encrypted payloads are linked and digest
        // checked by the loader at runtime, so verification cannot fail on them.
        context.log().info("class-encryption: note: --verify links only the plaintext loader/helpers; "
                + "encrypted classes and resources are verified by the loader at runtime");
    }

    private static String randomToken(SecureRandom secure, int length) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(alphabet.charAt(secure.nextInt(alphabet.length())));
        }
        return builder.toString();
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
        int level = config.optionInt("integrity.level", 2);
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
        private final byte[] siteSeed;
        private final byte[] commentBytes;
        private final int binding;
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
        private final long watchdogMs;
        private final Random random;

        ArchivePostProcessor(String loaderName, String cryptoName, String connectionName, String handlerName,
                             String indexEntry, byte[] siteSeed, byte[] commentBytes, int binding,
                             Cipher.Algorithm algorithm, boolean integrity, int level, boolean antiDump,
                             boolean encryptResources, boolean resourceIntegrity, boolean manifestMinimal,
                             int minResourceSize, String entryClass, String entryMethod, long watchdogMs,
                             Random random) {
            this.loaderName = loaderName;
            this.cryptoName = cryptoName;
            this.connectionName = connectionName;
            this.handlerName = handlerName;
            this.indexEntry = indexEntry;
            this.siteSeed = siteSeed;
            this.commentBytes = commentBytes;
            this.binding = binding;
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
            this.watchdogMs = watchdogMs;
            this.random = random;
        }

        @Override
        public String name() {
            return "class-encryption";
        }

        @Override
        public void process(Path output, PassContext context) throws Exception {
            boolean constantPool = context.config().optionBool("classEncryption.constantPool", true);
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

            // Planning pass: decide payload names and classify entries without
            // encrypting yet. The final entry count is part of the master-key
            // binding, so it must be known before any payload is sealed.
            List<PayloadPlan> plans = new ArrayList<PayloadPlan>();
            boolean moduleInfoPresent = false;
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
                    continue;
                }
                if (!name.endsWith(".class")) {
                    if (encryptResources && bytes.length >= minResourceSize) {
                        plans.add(PayloadPlan.resource(name, randomPayloadName(random, usedNames), bytes));
                    } else {
                        plans.add(PayloadPlan.plaintext(name, bytes));
                    }
                    continue;
                }
                if (name.equals("module-info.class") || name.endsWith("/module-info.class")) {
                    moduleInfoPresent = true;
                    plans.add(PayloadPlan.plaintext(name, bytes));
                    continue;
                }
                String binaryName;
                try {
                    binaryName = new ClassReader(bytes).getClassName().replace('/', '.');
                } catch (RuntimeException malformed) {
                    context.log().debug("class-encryption: unparseable class entry %s kept as an opaque "
                            + "resource", name);
                    plans.add(PayloadPlan.plaintext(randomPayloadName(random, usedNames), bytes));
                    continue;
                }
                plans.add(PayloadPlan.classPayload(binaryName, randomPayloadName(random, usedNames), bytes));
            }
            int entryCount = rewritten.size() + plans.size() + 1; // + sealed index
            if (entryCount > MAX_ENTRIES) {
                throw new IOException("class-encryption: archive has too many entries: " + entryCount);
            }
            byte[] master = binding == BINDING_SAMPLE
                    ? Cipher.hmacSha256(siteSeed, Cipher.concat(Cipher.utf8("umbra.master.v3"),
                    commentBytes == null ? new byte[0] : commentBytes, Cipher.le32(entryCount)))
                    : Cipher.hmacSha256(siteSeed, Cipher.utf8("umbra.master.v3.seed"));

            Set<String> plaintextClasses = new LinkedHashSet<String>();
            plaintextClasses.add(loaderName.replace('/', '.'));
            plaintextClasses.add(cryptoName.replace('/', '.'));
            plaintextClasses.add(connectionName.replace('/', '.'));
            plaintextClasses.add(handlerName.replace('/', '.'));
            if (moduleInfoPresent) {
                plaintextClasses.add("module-info");
            }

            List<String> classNames = new ArrayList<String>();
            List<String> classPayloads = new ArrayList<String>();
            List<byte[]> classDigests = new ArrayList<byte[]>();
            List<String> resourceNames = new ArrayList<String>();
            List<String> resourcePayloads = new ArrayList<String>();
            List<byte[]> resourceDigests = new ArrayList<byte[]>();
            List<Integer> resourceSizes = new ArrayList<Integer>();
            long resourceBytes = 0L;
            int plaintextResources = 0;

            for (int i = 0; i < plans.size(); i++) {
                PayloadPlan plan = plans.get(i);
                if (plan.kind == PayloadPlan.PLAINTEXT) {
                    rewritten.put(plan.entry, plan.bytes);
                    if (!plan.entry.endsWith(".class")) {
                        plaintextResources++;
                    }
                    continue;
                }
                byte[] nonce = Cipher.randomBytes(random, Cipher.NONCE_BYTES);
                String label = (plan.kind == PayloadPlan.CLASS ? "c:" : "r:") + plan.logical;
                byte[] key = Cipher.hmacSha256(master, Cipher.concat(Cipher.utf8(label), nonce));
                byte[] payload = plan.bytes;
                try {
                    if (plan.kind == PayloadPlan.CLASS && constantPool) {
                        // Same routine the injected loader runs before defineClass, so
                        // build-time and run-time cannot drift apart.
                        payload = new byte[plan.bytes.length];
                        System.arraycopy(plan.bytes, 0, payload, 0, plan.bytes.length);
                        if (!UmbraClassLoader.cryptConstantPool(payload, key)) {
                            throw new IllegalStateException(
                                    "class-encryption: cannot encrypt the constant pool of "
                                            + plan.logical);
                        }
                    }
                    rewritten.put(plan.entry, Cipher.seal(payload, key, nonce, algorithm));
                } finally {
                    Cipher.wipe(key);
                }
                if (plan.kind == PayloadPlan.CLASS) {
                    classNames.add(plan.logical);
                    classPayloads.add(plan.entry);
                    // The digest covers exactly the bytes the loader unseals (constant
                    // pool still encrypted), so verification needs no define-path patch.
                    classDigests.add(Cipher.hmacSha256(master,
                            Cipher.concat(Cipher.utf8("d:c:" + plan.logical), payload)));
                } else {
                    resourceNames.add(plan.logical);
                    resourcePayloads.add(plan.entry);
                    resourceDigests.add(Cipher.hmacSha256(master,
                            Cipher.concat(Cipher.utf8("d:r:" + plan.logical), plan.bytes)));
                    resourceSizes.add(Integer.valueOf(plan.bytes.length));
                    resourceBytes += plan.bytes.length;
                }
            }

            ByteArrayOutputStream index = new ByteArrayOutputStream();
            writeInt(index, MAGIC);
            index.write(INDEX_VERSION);
            int flags = (integrity ? FLAG_INTEGRITY : 0) | (antiDump ? FLAG_ANTIDUMP : 0)
                    | (resourceIntegrity ? FLAG_RESOURCE_INTEGRITY : 0)
                    | (constantPool ? FLAG_CONSTANT_POOL : 0)
                    | ((algorithm == Cipher.Algorithm.AES_CTR ? 2 : 1) << ALG_SHIFT);
            index.write(flags);
            index.write(level);
            index.write(binding);
            writeInt(index, plaintextClasses.size());
            for (String plaintext : plaintextClasses) {
                writeString(index, plaintext);
            }
            writeString(index, entryClass.replace('/', '.'));
            writeString(index, entryMethod);
            index.write(Cipher.hmacSha256(master,
                    Cipher.concat(Cipher.utf8("d:loader"), loaderBytes)));
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

            String comment = commentBytes == null ? null : Cipher.base64(commentBytes);
            rewrite(output, rewritten, entryMethods, comment);
            Cipher.wipe(master);

            try {
                assertRewritten(output, rewritten, comment, entryCount, infrastructureEntries,
                        classPayloads, resourcePayloads, moduleInfoPresent);
            } catch (IOException invalid) {
                throw invalid;
            }
            context.stats().add("classEncryption.classes", classNames.size());
            context.stats().add("classEncryption.payloadEntries",
                    classPayloads.size() + resourcePayloads.size());
            context.stats().add("classEncryption.resources", resourceNames.size());
            context.stats().add("classEncryption.resourceEntries", resourcePayloads.size());
            context.stats().add("classEncryption.resourceBytes", resourceBytes);
            context.stats().add("classEncryption.resourcesPlaintext", plaintextResources);
            context.stats().add("classEncryption.indexBytes", sealedIndex.length);
            context.stats().add("classEncryption.entries", entryCount);
            context.stats().add("classEncryption.seedBound", binding == BINDING_SAMPLE ? 1 : 0);
            context.log().info("class-encryption: encrypted %d classes and %d resources (%d bytes), "
                            + "%d plaintext resources kept, loader=%s, index=%s, entries=%d, "
                            + "masterBinding=%s, level=%d",
                    classNames.size(), resourceNames.size(), resourceBytes, plaintextResources,
                    loaderName, indexEntry, entryCount,
                    binding == BINDING_SAMPLE ? "sample(zip-comment+entry-count)" : "seed(diagnostic)",
                    level);
        }

        /**
         * Build-time assertions (analysis checklist P2-1/P2-2): no unreplaced
         * {@code @@} placeholder in the plaintext runtime entries or entry names,
         * the index names every payload that was written, the plaintext class list
         * matches reality (module-info only when present), and the master binding
         * inputs are consistent.
         */
        private void assertRewritten(Path output, Map<String, byte[]> rewritten, String comment,
                                     int entryCount, Set<String> infrastructureEntries,
                                     List<String> classPayloads, List<String> resourcePayloads,
                                     boolean moduleInfoPresent) throws IOException {
            if (binding == BINDING_SAMPLE && (comment == null || comment.isEmpty())) {
                throw new IOException("class-encryption: sample binding requires a ZIP comment");
            }
            if (binding == BINDING_SEED && comment != null) {
                throw new IOException("class-encryption: seed binding must not write a ZIP comment");
            }
            for (String name : rewritten.keySet()) {
                if (name.indexOf("@@") >= 0) {
                    throw new IOException("class-encryption: unreplaced placeholder in entry name: " + name);
                }
            }
            try (ZipFile zip = new ZipFile(output.toFile())) {
                int actualEntries = 0;
                Set<String> names = new LinkedHashSet<String>();
                java.util.Enumeration<? extends ZipEntry> enumeration = zip.entries();
                while (enumeration.hasMoreElements()) {
                    ZipEntry entry = enumeration.nextElement();
                    if (entry.isDirectory()) {
                        continue;
                    }
                    actualEntries++;
                    names.add(entry.getName());
                }
                if (actualEntries != entryCount) {
                    throw new IOException("class-encryption: entry count changed during write (expected "
                            + entryCount + ", actual " + actualEntries + "); master key would not match");
                }
                String writtenComment = zip.getComment();
                if (binding == BINDING_SAMPLE) {
                    if (writtenComment == null || !writtenComment.equals(comment)) {
                        throw new IOException("class-encryption: ZIP comment was not written; "
                                + "sample-bound master key would not match");
                    }
                } else if (writtenComment != null && !writtenComment.isEmpty()) {
                    throw new IOException("class-encryption: unexpected ZIP comment for seed binding");
                }
                for (String payload : classPayloads) {
                    if (!names.contains(payload)) {
                        throw new IOException("class-encryption: class payload entry missing: " + payload);
                    }
                }
                for (String payload : resourcePayloads) {
                    if (!names.contains(payload)) {
                        throw new IOException("class-encryption: resource payload entry missing: " + payload);
                    }
                }
                if (!names.contains(indexEntry)) {
                    throw new IOException("class-encryption: sealed index entry missing");
                }
                for (String infrastructure : infrastructureEntries) {
                    if (!names.contains(infrastructure)) {
                        throw new IOException("class-encryption: plaintext helper missing: " + infrastructure);
                    }
                }
                // Class entries that stay plaintext must be exactly the injected
                // infrastructure plus an optional module-info.
                for (String name : names) {
                    if (!name.endsWith(".class")) {
                        continue;
                    }
                    boolean expected = infrastructureEntries.contains(name)
                            || (moduleInfoPresent && name.endsWith("module-info.class"));
                    if (!expected) {
                        throw new IOException("class-encryption: unexpected plaintext class entry: " + name);
                    }
                }
                // No unreplaced template placeholder may survive in a plaintext
                // class; encrypted payload bytes are random and are not scanned.
                for (String name : names) {
                    if (!name.endsWith(".class") || !infrastructureEntries.contains(name)) {
                        continue;
                    }
                    byte[] bytes = readZipEntry(zip, name);
                    if (containsPlaceholder(bytes)) {
                        throw new IOException("class-encryption: unreplaced placeholder in plaintext class: "
                                + name);
                    }
                }
            }
        }

        private static boolean containsPlaceholder(byte[] bytes) {
            for (int i = 0; i + 1 < bytes.length; i++) {
                if (bytes[i] == '@' && bytes[i + 1] == '@') {
                    return true;
                }
            }
            return false;
        }

        private static byte[] readZipEntry(ZipFile zip, String name) throws IOException {
            ZipEntry entry = zip.getEntry(name);
            if (entry == null) {
                return null;
            }
            InputStream in = zip.getInputStream(entry);
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    out.write(buffer, 0, read);
                }
                return out.toByteArray();
            } finally {
                in.close();
            }
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

        private static boolean isSignatureFile(String name) {
            if (!name.startsWith("META-INF/")) {
                return false;
            }
            String upper = name.toUpperCase(Locale.ROOT);
            return upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA")
                    || upper.endsWith(".EC") || upper.endsWith(".SIG");
        }
    }

    /** One planned output entry: encrypted class/resource payload or plaintext copy. */
    private static final class PayloadPlan {
        static final int CLASS = 1;
        static final int RESOURCE = 2;
        static final int PLAINTEXT = 3;

        final int kind;
        final String logical;
        final String entry;
        final byte[] bytes;

        private PayloadPlan(int kind, String logical, String entry, byte[] bytes) {
            this.kind = kind;
            this.logical = logical;
            this.entry = entry;
            this.bytes = bytes;
        }

        static PayloadPlan classPayload(String binaryName, String entry, byte[] bytes) {
            return new PayloadPlan(CLASS, binaryName, entry, bytes);
        }

        static PayloadPlan resource(String logicalName, String entry, byte[] bytes) {
            return new PayloadPlan(RESOURCE, logicalName, entry, bytes);
        }

        static PayloadPlan plaintext(String entry, byte[] bytes) {
            return new PayloadPlan(PLAINTEXT, null, entry, bytes);
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
        rewrite(jar, entries, methods, null);
    }

    static void rewrite(Path jar, Map<String, byte[]> entries, Map<String, Integer> methods,
                        String comment) throws IOException {
        Path parent = jar.toAbsolutePath().getParent();
        Path temp = parent.resolve(jar.getFileName().toString() + ".umbra-tmp");
        try {
            try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(temp))) {
                if (comment != null) {
                    out.setComment(comment);
                }
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

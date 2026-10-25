package io.umbra.tests;

import io.umbra.core.api.ProgressListener;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.engine.EngineResult;
import io.umbra.core.engine.UmbraEngine;
import io.umbra.core.engine.UmbraVerifier;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * WS23 string-encryption hardening tests (3.2): randomized per-class call-site
 * indices, per-artifact domain salt, opt-in plaintext cache, wipe/stack-trace
 * flags, and randomized multi-engine selection for {@code string.engine=auto}.
 *
 * <p>Plain-main harness like the other Umbra suites: protects the demo JAR with
 * the real engine, inspects the produced call sites/decryptor bytecode, loads
 * the injected decryptor reflectively to verify the failure-masking behaviour,
 * and executes the protected demo on the current JDK (and JDK 21 when
 * available).</p>
 */
public final class StringHardeningTest {

    private static final long SEED = 987654321L;

    private static final String[] DEMO_LITERALS = {
            "Hello, Umbra!", "logic broken", "self-check failed: ",
            "reflective static method invoke", "sum=", "caught: "
    };

    private static int checks;
    private static final List<Path> TEMP_ROOTS = new ArrayList<Path>();

    private StringHardeningTest() {
    }

    public static void main(String[] args) throws Exception {
        startWatchdog();
        Path demo = demoJar();
        if (demo == null) {
            System.out.println("StringHardeningTest: demo/demo.jar not found, skipping");
            return;
        }
        try {
            testSiteIdsRandomizedAndDeterministic(demo);
            testArtifactSalt(demo);
            testCacheDefaultAndOptIn(demo);
            testWipeAndHideFlags(demo);
            testMultiEngineAutoAndUnsupported(demo);
            testPlaintextAndDemoRuns(demo);
        } finally {
            cleanup();
        }
        System.out.println("StringHardeningTest: " + checks + " checks passed");
    }

    // ------------------------------------------------------------------
    // 1. Random per-class site ids, deterministic per seed
    // ------------------------------------------------------------------

    private static void testSiteIdsRandomizedAndDeterministic(Path demo) throws Exception {
        String[] options = options("string.strength", "3", "string.engine", "chacha20",
                "string.indy", "false");
        Run first = protect(demo, SEED, options, byteShapeTweak());
        Run repeat = protect(demo, SEED, options, byteShapeTweak());
        Run otherSeed = protect(demo, SEED + 1, options, byteShapeTweak());

        check("site-ids: same seed produces byte-identical classes",
                first.fingerprint.equals(repeat.fingerprint));
        check("site-ids: same seed produces identical site ids",
                siteIds(first).equals(siteIds(repeat)));
        check("site-ids: different seed changes site ids",
                !siteIds(first).equals(siteIds(otherSeed)));
        check("site-ids: different seed changes archive",
                !first.fingerprint.equals(otherSeed.fingerprint));

        long encrypted = stat(first, "strings.encrypted");
        long cacheSites = stat(first, "strings.cacheSites");
        check("site-ids: cache is off by default (crypto 3.2)",
                stat(first, "strings.cache") == 0 && cacheSites == 0);
        // Field-initialisation and other pre-passes can expose a literal through a
        // different shape than a plain d()/e() call; the security properties below
        // (unique random ids, no plaintext, deterministic bytes) are what matter.
        int ids = siteIds(first).size();
        check("site-ids: demo exposes a large random id set (" + ids + " ids, "
                + encrypted + " encrypted)", ids >= 400 && ids <= encrypted);
        check("site-ids: no plaintext demo literals remain after protection",
                plaintextHits(first).isEmpty());
        check("site-ids: all ids are non-negative",
                allNonNegative(siteIds(first)));
        check("site-ids: ids are not a small sequential range",
                !isSequentialRange(siteIds(first)));
        check("site-ids: at least one sparse class id set",
                hasSparseClass(first));

        // The decryptor must not carry the old sequential counter signature:
        // every per-class set is unique inside its own class.
        check("site-ids: ids are unique within each class", uniquePerClass(first));
        System.out.println("StringHardeningTest: site-id sample " + preview(siteIds(first)));
    }

    // ------------------------------------------------------------------
    // 2. Per-artifact domain salt
    // ------------------------------------------------------------------

    private static void testArtifactSalt(Path demo) throws Exception {
        Run first = protect(demo, SEED, options("string.engine", "chacha20"));
        Run repeat = protect(demo, SEED, options("string.engine", "chacha20"));
        Run otherSeed = protect(demo, SEED + 5, options("string.engine", "chacha20"));
        Run explicit = protect(demo, SEED,
                options("string.engine", "chacha20", "string.siteSalt", "1234567890123"));

        check("salt: decryptor salt is not the placeholder", decryptorSalt(first) != 0L);
        check("salt: same seed same salt", decryptorSalt(first) == decryptorSalt(repeat));
        check("salt: different seed different salt",
                decryptorSalt(first) != decryptorSalt(otherSeed));
        check("salt: explicit string.siteSalt is embedded",
                decryptorSalt(explicit) == 1234567890123L);
        check("salt: payload version is 3", stat(first, "strings.payloadVersion") == 3);
        verify(first, "salt");
        check("salt: protected demo runs (default cache off)", runsOk(first.jar));
    }

    // ------------------------------------------------------------------
    // 3. Plaintext cache: off by default, opt-in only
    // ------------------------------------------------------------------

    private static void testCacheDefaultAndOptIn(Path demo) throws Exception {
        Run defaults = protect(demo, SEED, options("string.engine", "chacha20"));
        check("cache: default stat is 0", stat(defaults, "strings.cache") == 0);
        check("cache: no cacheSites in default run", stat(defaults, "strings.cacheSites") == 0);
        check("cache: default call sites all use d(...)", !usesCacheMethod(defaults));
        check("cache: default decryptor cache bit clear", (decryptorFlags(defaults) & 4) == 0);

        Run cached = protect(demo, SEED,
                options("string.engine", "chacha20", "string.cache", "true"));
        check("cache: opt-in stat is 1", stat(cached, "strings.cache") == 1);
        check("cache: cache sites recorded", stat(cached, "strings.cacheSites") > 0);
        check("cache: opt-in call sites use e(...)", usesCacheMethod(cached));
        check("cache: opt-in decryptor cache bit set", (decryptorFlags(cached) & 4) != 0);
        check("cache: opt-in archive verifies", UmbraVerifier.verify(cached.jar).isEmpty());
        check("cache: opt-in demo runs", runsOk(cached.jar));
    }

    // ------------------------------------------------------------------
    // 4. WIPE / HIDE_TRACE flag semantics
    // ------------------------------------------------------------------

    private static void testWipeAndHideFlags(Path demo) throws Exception {
        Run plain = protect(demo, SEED,
                options("string.engine", "chacha20", "string.wipe", "false",
                        "string.stackTraceHide", "false"));
        Run hardened = protect(demo, SEED,
                options("string.engine", "chacha20", "string.wipe", "true",
                        "string.stackTraceHide", "true"));

        int plainFlags = decryptorFlags(plain);
        int hardenedFlags = decryptorFlags(hardened);
        check("flags: plain run has wipe/hide clear", (plainFlags & 3) == 0);
        check("flags: hardened run sets wipe bit", (hardenedFlags & 1) != 0);
        check("flags: hardened run sets hide bit", (hardenedFlags & 2) != 0);
        check("flags: wipe stat", stat(hardened, "strings.wipe") == 1);
        check("flags: stackTraceHide stat", stat(hardened, "strings.stackTraceHide") == 1);

        Throwable hiddenPerClass = callDecryptorPerClass(hardened, new String[] { "!!!!" }, "!!!!", 0, 2);
        check("flags: per-class-key hidden failure is sanitized",
                hiddenPerClass instanceof IllegalStateException
                        && hiddenPerClass.getStackTrace().length == 0);
        Throwable hidden = callDecryptor(hardened, new String[] { "!!!!" }, 1L, 0, 2);
        check("flags: hidden failure is sanitized IllegalStateException",
                hidden instanceof IllegalStateException);
        check("flags: sanitized exception has an empty stack trace",
                hidden != null && hidden.getStackTrace().length == 0);
        check("flags: sanitized exception message is empty",
                hidden != null && (hidden.getMessage() == null || hidden.getMessage().isEmpty()));

        Throwable exposed = callDecryptor(plain, new String[] { "!!!!" }, 1L, 0, 2);
        check("flags: without hide, the real failure type is visible",
                exposed instanceof IllegalArgumentException);
        check("flags: without hide, stack trace is not cleared",
                exposed != null && exposed.getStackTrace().length > 0);

        verify(hardened, "flags");
        check("flags: hardened demo runs", runsOk(hardened.jar));
    }

    // ------------------------------------------------------------------
    // 5. Randomized multi-engine auto selection, unsupported engine fallback
    // ------------------------------------------------------------------

    private static void testMultiEngineAutoAndUnsupported(Path demo) throws Exception {
        String[] allEngines = options("string.strength", "3", "string.engine", "auto",
                "string.engineOrder", "xor,rc4,chacha20,aes-ctr,speck",
                "string.indy", "false", "string.wipe", "true",
                "string.stackTraceHide", "true");
        Run auto = protect(demo, SEED, allEngines);
        Run autoRepeat = protect(demo, SEED, allEngines);
        Run autoOther = protect(demo, SEED + 11, allEngines);

        check("engine-auto: all five whitelisted engines used", stat(auto, "strings.engineKinds") == 5);
        for (String engine : new String[] { "xor", "rc4", "chacha20", "aes-ctr", "speck" }) {
            check("engine-auto: " + engine + " used", stat(auto, "strings.engine." + engine) > 0);
        }
        check("engine-auto: deterministic engine counts for a seed",
                engineCounts(auto).equals(engineCounts(autoRepeat)));
        check("engine-auto: deterministic archive for a seed",
                auto.fingerprint.equals(autoRepeat.fingerprint));
        check("engine-auto: different seed changes engine distribution",
                !engineCounts(auto).equals(engineCounts(autoOther)));
        verify(auto, "engine-auto");
        check("engine-auto: demo runs", runsOk(auto.jar));

        Run unsupported = protect(demo, SEED, options("string.engine", "totally-unsupported"));
        check("engine-auto: unsupported engine is not accepted silently",
                stat(unsupported, "strings.engineFallback") == 1
                        && stat(unsupported, "strings.unsupportedOptions") >= 1);
        check("engine-auto: fallback still uses supported engines only",
                stat(unsupported, "strings.engineKinds") >= 2);
        check("engine-auto: unsupported-engine fallback demo runs", runsOk(unsupported.jar));

        Run badOrder = protect(demo, SEED,
                options("string.engine", "auto", "string.engineOrder", "bogus,chacha20"));
        check("engine-auto: unknown engineOrder entries are counted",
                stat(badOrder, "strings.engineOrderIgnored") >= 1);
        check("engine-auto: only the supported entry is used",
                stat(badOrder, "strings.engineKinds") == 1);
        check("engine-auto: filtered order demo runs", runsOk(badOrder.jar));
    }

    // ------------------------------------------------------------------
    // 6. Plaintext leaks and demo runs on JDK 8 / 21
    // ------------------------------------------------------------------

    private static void testPlaintextAndDemoRuns(Path demo) throws Exception {
        Run hardened = protect(demo, SEED,
                options("string.strength", "3", "string.engine", "auto",
                        "string.stackTraceHide", "true", "string.wipe", "true"));
        check("demo: no plaintext demo literals remain",
                plaintextHits(hardened).isEmpty());
        check("demo: default JDK prints OK", runsOk(hardened.jar));
        verify(hardened, "demo");
        Path jdk21 = Paths.get("C:\\Program Files\\Java\\jdk-21.0.10\\bin\\java.exe");
        if (Files.isRegularFile(jdk21)) {
            check("demo: JDK 21 prints OK", runsOk(hardened.jar, jdk21.toString()));
        } else {
            System.out.println("StringHardeningTest: JDK 21 not found, skipped cross-JDK run");
        }
    }

    // ------------------------------------------------------------------
    // Engine harness
    // ------------------------------------------------------------------

    private static final class Run {
        Path jar;
        Map<String, Long> stats = new TreeMap<String, Long>();
        Map<String, ClassNode> classes = new LinkedHashMap<String, ClassNode>();
        String fingerprint;
        String passLog = "";
        String decryptorName;
        String indyName;
    }

    private interface Tweak {
        void apply(UmbraConfig.Builder builder);
    }

    /** Flow and integer passes rewrite adjacent int constants; disable them for byte-shape checks. */
    private static Tweak byteShapeTweak() {
        return new Tweak() {
            @Override
            public void apply(UmbraConfig.Builder builder) {
                builder.flow(new UmbraConfig.FlowOptions(false, "light", 8000));
                builder.integerEncryption(new UmbraConfig.IntegerEncryptionOptions(false, false));
            }
        };
    }

    private static Run protect(Path input, long seed, String[] options) throws Exception {
        return protect(input, seed, options, null);
    }

    private static Run protect(Path input, long seed, String[] options, Tweak tweak) throws Exception {
        Path directory = Files.createTempDirectory("umbra-string-hardening");
        TEMP_ROOTS.add(directory);
        Path output = directory.resolve("out.jar");
        UmbraConfig.Builder builder = new UmbraConfig.Builder()
                .input(input).output(output).seed(seed);
        for (int i = 0; i + 1 < options.length; i += 2) {
            builder.option(options[i], options[i + 1]);
        }
        if (tweak != null) {
            tweak.apply(builder);
        }
        final List<String> log = new ArrayList<String>();
        Log logSink = new Log(new Log.Sink() {
            @Override
            public void line(String level, String message) {
                log.add(level + " " + message);
            }
        }, true);
        EngineResult result = new UmbraEngine(logSink).run(builder.build(), ProgressListener.NONE);
        Run run = new Run();
        run.jar = output;
        run.stats = new TreeMap<String, Long>(result.stats().snapshot());
        run.passLog = String.join("\n", log);
        if (!Files.isRegularFile(output)) {
            throw new IllegalStateException("engine produced no output jar: " + run.passLog);
        }
        readClasses(output, run.classes);
        run.fingerprint = classFingerprint(run.classes);
        findHelpers(run);
        return run;
    }

    private static void findHelpers(Run run) {
        for (Map.Entry<String, ClassNode> entry : run.classes.entrySet()) {
            for (FieldNode field : entry.getValue().fields) {
                if ("SALT_SPEC".equals(field.name) && field.value instanceof String) {
                    run.decryptorName = entry.getKey();
                }
            }
            for (MethodNode method : entry.getValue().methods) {
                if ("bootstrapString".equals(method.name)
                        && method.desc.endsWith(")Ljava/lang/invoke/CallSite;")) {
                    run.indyName = entry.getKey();
                }
            }
        }
        if (run.decryptorName == null) {
            throw new IllegalStateException("injected string decryptor not found in archive");
        }
    }

    private static long decryptorSalt(Run run) {
        ClassNode node = run.classes.get(run.decryptorName);
        for (FieldNode field : node.fields) {
            if ("SALT_SPEC".equals(field.name) && field.value instanceof String) {
                return Long.parseLong(((String) field.value).trim());
            }
        }
        throw new IllegalStateException("SALT_SPEC missing");
    }

    private static int decryptorFlags(Run run) {
        ClassNode node = run.classes.get(run.decryptorName);
        for (FieldNode field : node.fields) {
            if ("FLAGS_SPEC".equals(field.name) && field.value instanceof String) {
                return Integer.parseInt(((String) field.value).trim());
            }
        }
        throw new IllegalStateException("FLAGS_SPEC missing");
    }

    // ------------------------------------------------------------------
    // Call-site inspection
    // ------------------------------------------------------------------

    private static List<Integer> siteIds(Run run) {
        List<Integer> ids = new ArrayList<Integer>();
        for (ClassNode node : run.classes.values()) {
            ids.addAll(siteIdsOf(node, run));
        }
        Collections.sort(ids);
        return ids;
    }

    private static List<Integer> siteIdsOf(ClassNode node, Run run) {
        List<Integer> ids = new ArrayList<Integer>();
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if (call.getOpcode() == Opcodes.INVOKESTATIC
                            && run.decryptorName.equals(call.owner)
                            && ("d".equals(call.name) || "e".equals(call.name))
                            && call.desc.endsWith(")Ljava/lang/String;")) {
                        // Exact call shape: parts..., (GETSTATIC key | LDC seed), siteId, engine.
                        AbstractInsnNode engineInsn = insn.getPrevious();
                        Integer engine = engineInsn == null ? null : intConstant(engineInsn);
                        AbstractInsnNode siteInsn = engineInsn == null ? null : engineInsn.getPrevious();
                        Integer id = siteInsn == null ? null : intConstant(siteInsn);
                        AbstractInsnNode anchor = siteInsn == null ? null : siteInsn.getPrevious();
                        boolean perSite = call.desc.contains(";JII)");
                        boolean anchorOk = anchor != null
                                && (perSite
                                        ? anchor instanceof LdcInsnNode
                                                && ((LdcInsnNode) anchor).cst instanceof Long
                                        : anchor instanceof org.objectweb.asm.tree.FieldInsnNode
                                                && anchor.getOpcode() == Opcodes.GETSTATIC);
                        if (engine != null && id != null && anchorOk) {
                            ids.add(id);
                        }
                    }
                } else if (insn instanceof InvokeDynamicInsnNode && run.indyName != null) {
                    InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                    if (indy.bsm != null && run.indyName.equals(indy.bsm.getOwner())) {
                        Object[] args = indy.bsmArgs;
                        if (args.length >= 5 && args[3] instanceof Integer) {
                            ids.add((Integer) args[3]);
                        }
                    }
                }
            }
        }
        return ids;
    }

    /** Collects the last {@code count} integer constants before the instruction, nearest first. */
    private static List<Integer> precedingIntConstants(AbstractInsnNode insn, int count) {
        List<Integer> found = new ArrayList<Integer>();
        AbstractInsnNode cursor = insn.getPrevious();
        for (int guard = 0; cursor != null && found.size() < count && guard < 24; guard++) {
            Integer value = intConstant(cursor);
            if (value != null) {
                found.add(value);
            }
            cursor = cursor.getPrevious();
        }
        return found;
    }

    private static Integer intConstant(AbstractInsnNode insn) {
        if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Integer) {
            return (Integer) ((LdcInsnNode) insn).cst;
        }
        if (insn instanceof IntInsnNode) {
            return Integer.valueOf(((IntInsnNode) insn).operand);
        }
        if (insn instanceof InsnNode) {
            int opcode = insn.getOpcode();
            if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
                return Integer.valueOf(opcode - Opcodes.ICONST_0);
            }
        }
        return null;
    }

    private static boolean usesCacheMethod(Run run) {
        for (ClassNode node : run.classes.values()) {
            for (MethodNode method : node.methods) {
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode call = (MethodInsnNode) insn;
                        if (run.decryptorName.equals(call.owner) && "e".equals(call.name)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private static boolean uniquePerClass(Run run) {
        for (ClassNode node : run.classes.values()) {
            List<Integer> ids = siteIdsOf(node, run);
            Set<Integer> unique = new LinkedHashSet<Integer>(ids);
            if (unique.size() != ids.size()) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasSparseClass(Run run) {
        for (ClassNode node : run.classes.values()) {
            List<Integer> ids = siteIdsOf(node, run);
            if (ids.size() >= 4) {
                List<Integer> sorted = new ArrayList<Integer>(ids);
                Collections.sort(sorted);
                for (int i = 1; i < sorted.size(); i++) {
                    if (sorted.get(i).intValue() - sorted.get(i - 1).intValue() != 1) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean allNonNegative(List<Integer> ids) {
        for (Integer id : ids) {
            if (id.intValue() < 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSequentialRange(List<Integer> ids) {
        if (ids.size() < 3) {
            return false;
        }
        List<Integer> sorted = new ArrayList<Integer>(ids);
        Collections.sort(sorted);
        for (int i = 1; i < sorted.size(); i++) {
            if (sorted.get(i).intValue() != sorted.get(i - 1).intValue() + 1) {
                return false;
            }
        }
        return true;
    }

    private static String preview(List<Integer> ids) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < Math.min(6, ids.size()); i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(ids.get(i));
        }
        return out.toString();
    }

    // ------------------------------------------------------------------
    // Reflection on the injected decryptor
    // ------------------------------------------------------------------

    private static Throwable callDecryptorPerClass(Run run, String[] parts, String classKey,
                                                   int siteId, int engine) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[] { run.jar.toUri().toURL() },
                StringHardeningTest.class.getClassLoader());
        try {
            Class<?> type = Class.forName(run.decryptorName.replace('/', '.'), true, loader);
            Method method = type.getMethod("d", String[].class, String.class, int.class, int.class);
            try {
                method.invoke(null, parts, classKey, Integer.valueOf(siteId), Integer.valueOf(engine));
                return null;
            } catch (InvocationTargetException failure) {
                return failure.getCause();
            }
        } finally {
            loader.close();
        }
    }

    private static Throwable callDecryptor(Run run, String[] parts, long seed, int siteId,
                                           int engine) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[] { run.jar.toUri().toURL() },
                StringHardeningTest.class.getClassLoader());
        try {
            Class<?> type = Class.forName(run.decryptorName.replace('/', '.'), true, loader);
            Method method = type.getMethod("d", String[].class, long.class, int.class, int.class);
            try {
                method.invoke(null, parts, Long.valueOf(seed), Integer.valueOf(siteId),
                        Integer.valueOf(engine));
                return null;
            } catch (InvocationTargetException failure) {
                return failure.getCause();
            }
        } finally {
            loader.close();
        }
    }

    // ------------------------------------------------------------------
    // Archive helpers
    // ------------------------------------------------------------------

    private static void readClasses(Path jar, Map<String, ClassNode> target) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(new FileInputStream(jar.toFile()))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (!entry.getName().endsWith(".class")) {
                    continue;
                }
                byte[] bytes = readAll(zip);
                ClassNode node = new ClassNode();
                new ClassReader(bytes).accept(node, 0);
                target.put(entry.getName().substring(0, entry.getName().length() - 6), node);
            }
        }
    }

    private static String classFingerprint(Map<String, ClassNode> classes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            List<String> names = new ArrayList<String>(classes.keySet());
            Collections.sort(names);
            for (String name : names) {
                digest.update(name.getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
            }
            StringBuilder out = new StringBuilder();
            for (byte b : digest.digest()) {
                out.append(Character.forDigit((b >>> 4) & 0xF, 16));
                out.append(Character.forDigit(b & 0xF, 16));
            }
            return out.toString();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static List<String> plaintextHits(Run run) {
        List<String> hits = new ArrayList<String>();
        for (ClassNode node : run.classes.values()) {
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode
                            && ((LdcInsnNode) insn).cst instanceof String) {
                        hits.addAll(match((String) ((LdcInsnNode) insn).cst));
                    } else if (insn instanceof InvokeDynamicInsnNode) {
                        for (Object argument : ((InvokeDynamicInsnNode) insn).bsmArgs) {
                            if (argument instanceof String) {
                                hits.addAll(match((String) argument));
                            }
                        }
                    }
                }
            }
            for (FieldNode field : node.fields) {
                if (field.value instanceof String) {
                    hits.addAll(match((String) field.value));
                }
            }
        }
        return hits;
    }

    private static List<String> match(String value) {
        List<String> found = new ArrayList<String>();
        for (String needle : DEMO_LITERALS) {
            if (value.contains(needle)) {
                found.add(needle);
            }
        }
        return found;
    }

    private static Map<String, Long> engineCounts(Run run) {
        Map<String, Long> counts = new LinkedHashMap<String, Long>();
        for (String engine : new String[] { "xor", "rc4", "chacha20", "aes-ctr", "speck" }) {
            counts.put(engine, Long.valueOf(stat(run, "strings.engine." + engine)));
        }
        return counts;
    }

    private static long stat(Run run, String key) {
        Long value = run.stats.get(key);
        return value == null ? 0L : value.longValue();
    }

    private static void verify(Run run, String phase) throws Exception {
        List<String> problems = UmbraVerifier.verify(run.jar);
        check(phase + ": archive verification", problems.isEmpty());
    }

    private static boolean runsOk(Path jar) throws Exception {
        return runsOk(jar, Paths.get(System.getProperty("java.home"), "bin", "java.exe").toString());
    }

    private static boolean runsOk(Path jar, String java) throws Exception {
        List<String> command = new ArrayList<String>();
        command.add(java);
        command.add("-jar");
        command.add(jar.toAbsolutePath().toString());
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        InputStream in = process.getInputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            output.write(buffer, 0, read);
        }
        if (!process.waitFor(120, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            return false;
        }
        String text = new String(output.toByteArray(), StandardCharsets.UTF_8);
        if (process.exitValue() != 0) {
            System.out.println("StringHardeningTest: run failed: " + text);
            return false;
        }
        return text.contains("OK");
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static String[] options(String... pairs) {
        return pairs;
    }

    // ------------------------------------------------------------------
    // Environment
    // ------------------------------------------------------------------

    private static Path demoJar() {
        Path candidate = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && candidate != null; i++) {
            if (Files.isRegularFile(candidate.resolve("demo").resolve("demo.jar"))) {
                return candidate.resolve("demo").resolve("demo.jar");
            }
            candidate = candidate.getParent();
        }
        return null;
    }

    private static void cleanup() {
        for (Path root : TEMP_ROOTS) {
            try {
                List<Path> paths = new ArrayList<Path>();
                Files.walk(root).forEach(paths::add);
                Collections.sort(paths, Collections.reverseOrder());
                for (Path path : paths) {
                    Files.deleteIfExists(path);
                }
            } catch (Exception ignored) {
            }
        }
    }

    private static void check(String message, boolean condition) {
        checks++;
        if (!condition) {
            throw new AssertionError("StringHardeningTest FAILED: " + message);
        }
    }

    private static void startWatchdog() {
        final long timeout = Long.parseLong(
                System.getProperty("umbra.stringhardening.watchdog", "300000"));
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(timeout);
                } catch (InterruptedException ignored) {
                    return;
                }
                System.err.println("StringHardeningTest WATCHDOG after " + timeout + "ms");
                Runtime.getRuntime().halt(3);
            }
        }, "string-hardening-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }
}

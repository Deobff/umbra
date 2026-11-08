package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.jni.CGenerator;
import io.umbra.core.jni.KeyRootCode;
import io.umbra.core.jni.NativeCompiler;
import io.umbra.core.jni.guard.GuardCodeGenerator;
import io.umbra.core.jni.guard.GuardFeatures;
import io.umbra.core.jni.guard.GuardOptions;
import io.umbra.core.jni.guard.PeImage;
import io.umbra.core.model.ClassPool;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.UmbraGuard;
import io.umbra.core.runtime.UmbraGuardLauncher;
import io.umbra.core.runtime.UmbraNativeGuard;
import io.umbra.core.runtime.UmbraNativeLoader;
import io.umbra.core.runtime.crypto.GuardSupport;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import io.umbra.core.util.RuntimeNames;

/**
 * Native anti-tamper / anti-Frida guard pass.
 *
 * <p>Builds (when a C toolchain and JNI headers are available) and injects a
 * small native guard library plus a self-contained Java guard template. The
 * guard covers debugger/JDWP/Frida/instrumentation detection, native library
 * self-integrity (file digest + code prologue hashes for its check/token
 * functions), a keyed {@code token()} challenge and native-method backfill
 * detection (methods Umbra turned native must still be native at runtime).</p>
 *
 * <p>Guard checks run from program entry points ({@code main}), from a
 * synthesized {@code <clinit>} hook of the main class and of every class owning
 * native methods, from a configurable watchdog thread, and - when
 * {@code NativeCodePass} shipped a native library - from every translated native
 * method via the exported {@code umbra_guard_tick} hook that reads the
 * {@code umbra.guard.path} system property.</p>
 *
 * <p>Detection policy: {@code antiDebug.action} = {@code throw} (default),
 * {@code exit}, {@code corrupt} or {@code log}. Without a toolchain the pass
 * degrades to the pure-Java checks (JDWP/agent options, Frida environment
 * markers, {@code /proc} checks on Linux).</p>
 */
public final class NativeGuardPass implements Pass {

    private static final long ZIP_TIME = 315532800000L;
    private static final int NATIVE_CHECK_PROLOGUE = 16;

    private static final String NATIVE_KEY_OPTION = "classEncryption.nativeKey";

    private static final String NATIVE_GATE_OPTION = "antiDebug.nativeGate";

    public static final String GATE_SECRET = "native.gateSecret";

    @Override
    public String name() {
        return "native-guard";
    }

    @Override
    public int order() {
        return 104;
    }

    @Override
    public boolean enabled(PassContext context) {
        boolean requested = context.config().optionInt("antiDebug.level", 0) > 0
                || context.config().antiDebug()
                || context.config().optionBool("antiDebug.enabled", false);
        boolean enabled = requested
                && context.config().optionBool("antiDebug.nativeGuard", true)
                && !context.classes().classes().isEmpty();
        if (!enabled) {
            return false;
        }
        io.umbra.core.compat.JarLayout layout =
                io.umbra.core.compat.LayoutRegistry.layout(context.classes());
        if ((!layout.isFlat() || layout.moduleInfo())
                && !context.config().optionBool("layout.forceEntryProtection", false)) {
            context.log().warn("native-guard: skipped on %s layout (the guard entry-point launcher is a "
                    + "root-JAR construct and cannot run before a nested container loader); "
                    + "use a flat JAR for native anti-tamper", layout.kindId());
            context.stats().add("layout.guard.skipped", 1);
            context.stats().add("nativeGuard.skipped.layout", 1);
            context.stats().text("layout.guard.nativeGuard", "skipped:" + layout.kindId());
            return false;
        }
        return true;
    }

    @Override
    public void run(PassContext context) {
        UmbraConfig config = context.config();
        String action = resolveAction(config);
        long watchdogMs = Math.max(0L, config.optionLong("antiDebug.watchdogMs", 4000L));
        GuardFeatures features = resolveFeatures(config, watchdogMs);
        boolean frida = features.frida;

        List<String> nativeMethods = collectNativeMethods(context.classes());
        Random random = new Random(config.seed() ^ 0x47554152444CL);
        NameGenerator names = new NameGenerator(random, "");
        String guardName = uniqueName(context.classes(), names, RuntimeNames.path("G"));
        String watchdogName = uniqueName(context.classes(), names, RuntimeNames.path("W"));

        String resourceName = "";
        byte[] library = null;
        String fileHashHex = "0";
        String prologueCheckHex = "";
        String prologueTokenHex = "";
        String source = "";
        int buildSamples = 0;
        String compiler = NativeCompiler.resolve(config.option("native.compiler", ""), context.log());
        long secret = new Random(config.seed() ^ 0x4755415244554CL).nextLong();
        long sampleSeed = new Random(config.seed() ^ 0x53414D504C45534CL).nextLong();

        String otpClass = null;
        if (config.optionBool("otp.enabled", false) && config.optionBool("otp.native", true)
                && config.flow().enabled()) {
            otpClass = context.runtime().ensureOtp(context.classes(), config.seed());
            context.stats().add("otp.native", otpClass == null ? 0 : 1);
        }
        if (compiler != null && NativeCompiler.hasJniHeaders()) {
            GuardBuild build = buildGuard(context, compiler, guardName, secret, features,
                    sampleSeed, otpClass);
            if (build != null) {
                library = build.library;
                source = build.source;
                features = build.features;
                buildSamples = build.codeSamples;
                resourceName = names.random(10) + "/" + names.random(14) + ".bin";
                assertGuardHygiene(context, library, resourceName);
                fileHashHex = GuardOptions.hex(GuardOptions.fnv1a64(library), 16);
                byte[][] prologues = PeImage.functionPrologues(library,
                        GuardCodeGenerator.functionTableMagic(secret), 4, NATIVE_CHECK_PROLOGUE);
                if (prologues.length == 4) {
                    prologueCheckHex = GuardOptions.bytesToHex(prologues[1]);
                    prologueTokenHex = GuardOptions.bytesToHex(prologues[3]);
                }
            }
        } else {
            context.log().warn("native-guard: no C toolchain/JNI headers; "
                    + "using the Java fallback guard");
        }

        String keyBridge = installNativeKey(context, compiler, secret, names);
        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put("@@RESOURCE@@", resourceName);
        replacements.put("@@KEYBRIDGE@@", keyBridge);
        replacements.put("@@NATIVE@@", String.valueOf(library != null));
        replacements.put("@@FRIDA@@", String.valueOf(frida));
        replacements.put("@@ACTION@@", action);
        replacements.put("@@SECRET@@", GuardOptions.hex(secret, 16));
        replacements.put("@@FILEHASH@@", fileHashHex);
        replacements.put("@@PCHECK@@", prologueCheckHex);
        replacements.put("@@PTOKEN@@", prologueTokenHex);
        replacements.put("@@WATCHDOG@@", String.valueOf(watchdogMs));
        replacements.put("@@METHODS@@", joinMethods(nativeMethods));

        try {
            injectGuardTemplates(context.classes(), guardName, watchdogName, replacements);
        } catch (IOException failure) {
            context.log().warn("native-guard: runtime template injection failed: %s", failure);
            context.stats().add("antiDebug.nativeGuard.fallback", 1);
            return;
        }

        int instrumented = instrument(context, guardName, nativeMethods);
        boolean launcher = installGuardLauncher(context, guardName, random);
        if (library != null) {
            context.classes().putResource(resourceName, library, ZIP_TIME, 8);
            context.stats().add("antiDebug.nativeGuard.dllBytes", library.length);
        } else {
            context.stats().add("antiDebug.nativeGuard.fallback", 1);
        }
        context.stats().add("antiDebug.nativeGuard", 1);
        context.stats().add("antiDebug.nativeGuard.methods", nativeMethods.size());
        context.stats().add("antiDebug.nativeGuard.entryPoints", instrumented);
        context.stats().add("antiDebug.nativeGuard.checks", features.enabledChecks());
        context.stats().add("antiDebug.nativeGuard.level", features.level);
        context.stats().add("antiDebug.nativeGuard.remoteThread", features.remoteThread ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.execMemoryScan", features.execMemoryScan ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.imageBreakpoints", features.imageBreakpoints ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.codeSampling", features.codeSampling ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.moduleIntegrity", features.moduleIntegrity ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.timing", features.timing ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.handleDump", features.handleDump ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.codeCrc", features.codeCrc ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.pageGuard", features.pageGuard ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.textGuard", features.textGuard ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.guardProbe", features.guardProbe ? 1 : 0);
        context.stats().text("antiDebug.nativeGuard.execWhitelist", features.execWhitelist);
        context.stats().add("antiDebug.nativeGuard.linuxChecks", features.linuxChecks ? 1 : 0);
        context.stats().add("antiDebug.nativeGuard.codeSamples", buildSamples);
        if (launcher) {
            context.stats().add("antiDebug.nativeGuard.launcher", 1);
        }
        context.log().info("native-guard: action=%s, features={%s}, nativeLibrary=%s, "
                        + "watchdog=%dms, nativeMethods=%d, entryPoints=%d",
                action, features.describe(),
                library == null ? "java-fallback" : "built (" + library.length + " bytes)",
                watchdogMs, nativeMethods.size(), instrumented);
        context.log().debug("native-guard: generated source length=%d, source kept in memory only",
                Integer.valueOf(source.length()));
    }

    private static String installNativeKey(PassContext context, String compiler, long secret,
                                           NameGenerator names) {
        UmbraConfig config = context.config();

        boolean requested = config.optionBool(NATIVE_KEY_OPTION, true)
                && (config.optionBool("classEncryption.enabled", false)
                || config.optionBool("integrity.enabled", false));
        if (!requested) {
            return "";
        }
        if (compiler == null || !NativeCompiler.hasJniHeaders()) {
            context.log().warn("native-key: classEncryption.nativeKey is on but no C toolchain/"
                    + "JNI headers are available; the archive keeps its embedded Java key path");
            context.stats().add("antiDebug.nativeKey.fallback", 1);
            return "";
        }

        boolean nativeGate = config.optionBool(NATIVE_GATE_OPTION, true);
        byte[] gateSecret = nativeGate ? KeyRootCode.newGateSecret() : null;
        ClassPool pool = context.classes();
        String loader = findKeyLoader(pool);
        boolean injected = false;
        String resourceName = names.random(10) + "/" + names.random(14) + ".bin";
        Map<String, String> loaderReplacements = new LinkedHashMap<String, String>();
        if (loader == null) {

            loaderReplacements.put("@@RESOURCE@@", resourceName);
            loaderReplacements.put("@@ANTIDUMP@@", "true");
            loaderReplacements.put("@@ANTIBACKFILL@@", "false");
            loaderReplacements.put("@@AKEY@@",
                    GuardOptions.hex(config.seed() ^ 0x4B45595A4B45594CL, 16));

            loaderReplacements.put("@@FP0@@", "100000000000000000000000");
            loaderReplacements.put("@@FP1@@", "20000000000000000000");
            loaderReplacements.put("@@FP2@@", "30000000000000000000");
            loader = TemplateInjector.inject(pool, UmbraNativeLoader.class,
                    RuntimeNames.path("N"), config.seed(), loaderReplacements);
            injected = true;

            pool.putMeta("native.loader", loader);

            replaceConstants(pool.getClass(loader), loaderReplacements);
        }

        byte[] root = context.keyRoot();

        String rootFingerprint = KeyRootCode.sha256Hex(root);
        context.log().info("native-key: guard root sha256[0:16]=%s",
                rootFingerprint == null ? "?" : rootFingerprint.substring(0, 16));
        Path temp = null;
        try {
            temp = Files.createTempDirectory(neutralDirectoryName());
            String target = guardTarget();
            int handleScanMs = 100;
            try {
                handleScanMs = Integer.parseInt(config.option("antiDebug.handleScanMs", "100").trim());
            } catch (NumberFormatException ignored) {
                handleScanMs = 100;
            }
            context.stats().add("antiDebug.handleScanMs",
                    Math.max(50, Math.min(1000, handleScanMs)));

            byte[] loaderDigestKey = new byte[32];
            context.random().nextBytes(loaderDigestKey);
            StringBuilder keyHex = new StringBuilder(64);
            for (byte value : loaderDigestKey) {
                keyHex.append(Character.forDigit((value >> 4) & 0xF, 16));
                keyHex.append(Character.forDigit(value & 0xF, 16));
            }
            String loaderDigestKeyHex = keyHex.toString();
            CGenerator.configureLoaderDigestKey(loaderDigestKey);
            String source = CGenerator.keyBridgeSource(loader, root, secret, false,
                    gateSecret, nativeGate, config.option("antiDebug.moduleWhitelist", "")
                            + ";" + config.option("antiDebug.handleWhitelist", ""),
                    handleScanMs,
                    config.option("antiDebug.suspiciousModules", ""));
            Path sourceFile = temp.resolve("k" + names.random(12) + ".c");
            Path libraryFile = temp.resolve("k" + names.random(12) + librarySuffix(target));
            Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
            NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, libraryFile,
                    target, "-s", context.log(), true);
            context.stats().add("antiDebug.nativeKey.compile.ms", result.millis());
            if (!result.success()) {
                context.log().warn("native-key: the key bridge did not compile (%s); the archive "
                        + "keeps its embedded Java key path", result.command());
                String output = result.output();
                if (output != null && !output.trim().isEmpty()) {
                    context.log().warn("native-key: compiler output: %s", abbreviate(output));
                }
                if (injected) {
                    pool.removeClass(loader);
                }
                context.stats().add("antiDebug.nativeKey.fallback", 1);
                return "";
            }
            byte[] bridge = Files.readAllBytes(result.library());
            if (injected) {

                String fingerprint = KeyRootCode.bridgeFingerprint(bridge);
                if (fingerprint == null || fingerprint.length() != 64) {
                    throw new IllegalStateException(
                            "native-key: cannot compute the bridge fingerprint");
                }
                Map<String, String> fingerprintPatch = new LinkedHashMap<String, String>();
                fingerprintPatch.put("100000000000000000000000", fingerprint.substring(0, 24));
                fingerprintPatch.put("20000000000000000000", fingerprint.substring(24, 44));
                fingerprintPatch.put("30000000000000000000", fingerprint.substring(44, 64));
                replaceConstants(pool.getClass(loader), fingerprintPatch);
            }
            pool.putResource(resourceName, bridge, ZIP_TIME, 8);
            pool.putMeta("native.digestKey", loaderDigestKeyHex);

            pool.putMeta("native.bridge.resource", resourceName);

            context.putSecret(PassContext.NATIVE_KEY_ROOT, root);
            if (nativeGate && gateSecret != null) {

                context.putSecret(GATE_SECRET, gateSecret);
            }
            context.stats().add("antiDebug.nativeGate", nativeGate ? 1 : 0);
            context.stats().add("antiDebug.nativeKey", 1);
            context.stats().add("antiDebug.nativeKey.bridgeBytes", bridge.length);
            context.stats().add("antiDebug.nativeKey.loaderInjected", injected ? 1 : 0);
            context.log().info("native-key: key bridge %s (%d bytes) bound to loader %s",
                    resourceName, Integer.valueOf(bridge.length), loader);
            return injected ? "" : resourceName;
        } catch (IOException failure) {
            context.log().warn("native-key: could not build the key bridge: %s", failure);
            if (injected) {
                context.classes().removeClass(loader);
            }
            context.stats().add("antiDebug.nativeKey.fallback", 1);
            return "";
        } finally {
            deleteRecursively(temp);
        }
    }

    private static String neutralDirectoryName() {
        return Long.toHexString(new java.security.SecureRandom().nextLong()
                & 0x7FFFFFFFFFFFFFFFL);
    }

    private static String findKeyLoader(ClassPool pool) {
        List<String> names = new ArrayList<String>(pool.classes().keySet());
        Collections.sort(names);
        for (String name : names) {
            if (!pool.isGenerated(name)) {
                continue;
            }
            ClassNode node = pool.getClass(name);
            if (node == null) {
                continue;
            }
            boolean keyRoot = false;
            boolean register = false;
            for (MethodNode method : node.methods) {
                if ((method.access & Opcodes.ACC_NATIVE) == 0) {
                    continue;
                }
                if (KeyRootCode.KEY_ROOT_METHOD.equals(method.name)
                        && KeyRootCode.KEY_ROOT_DESCRIPTOR.equals(method.desc)) {
                    keyRoot = true;
                }
                if ("register".equals(method.name)
                        && "(ILjava/lang/Class;)I".equals(method.desc)) {
                    register = true;
                }
            }
            if (keyRoot && register) {
                return name;
            }
        }
        return null;
    }

    private static GuardFeatures resolveFeatures(UmbraConfig config, long watchdogMs) {
        int level = config.optionInt("antiDebug.level", 0);
        if (level <= 0) {
            level = 2;
        }
        level = Math.max(1, Math.min(3, level));
        boolean dynamic = level >= 2;
        GuardFeatures.Builder builder = GuardFeatures.forLevel(level);
        builder.level(level)
                .watchdogMs(watchdogMs)
                .frida(config.optionBool("antiDebug.frida", true))
                .hash(config.optionBool("antiDebug.nativeHash", true))
                .remoteThread(config.optionBool("antiDebug.remoteThread", dynamic))
                .execMemoryScan(config.optionBool("antiDebug.execMemoryScan", false))
                .imageBreakpoints(config.optionBool("antiDebug.imageBreakpoints", dynamic))
                .codeSampling(config.optionBool("antiDebug.codeSampling", dynamic))
                .moduleIntegrity(config.optionBool("antiDebug.moduleIntegrity", dynamic))
                .timing(config.optionBool("antiDebug.timing", dynamic))
                .handleDump(config.optionBool("antiDebug.handleDump", level >= 3))
                .codeCrc(config.optionBool("antiDebug.codeCrc", dynamic))
                .pageGuard(config.optionBool("antiDebug.pageGuard", dynamic))
                .textGuard(config.optionBool("antiDebug.textGuard", dynamic))
                .guardProbe(config.optionBool("antiDebug.guardProbe", dynamic))
                .execWhitelist(config.option("antiDebug.execWhitelist",
                        GuardOptions.DEFAULT_EXEC_WHITELIST))
                .linuxChecks(config.optionBool("antiDebug.linuxChecks", true));
        return builder.build();
    }

    private static final class GuardBuild {
        final String source;
        final byte[] library;
        final GuardFeatures features;
        final int codeSamples;

        GuardBuild(String source, byte[] library, GuardFeatures features, int codeSamples) {
            this.source = source;
            this.library = library;
            this.features = features;
            this.codeSamples = codeSamples;
        }
    }

    private static void assertGuardHygiene(PassContext context, byte[] library, String resourceName) {
        int javaExports = 0;
        int oldTable = 0;
        int exportsCount = 0;
        StringBuilder joined = new StringBuilder();
        for (String name : PeImage.exportNames(library)) {
            exportsCount++;
            if (joined.length() > 0) {
                joined.append(',');
            }
            joined.append(name);
            if (name.startsWith("Java_")) {
                javaExports++;
            }
            if ("umbra_code_sample_table".equals(name)) {
                oldTable++;
            }
        }
        if (javaExports > 0 || oldTable > 0
                || resourceName.contains("umbra") || resourceName.contains("guard")) {
            throw new IllegalStateException("native-guard hygiene assertion failed: "
                    + "javaExports=" + javaExports + ", oldSampleTable=" + oldTable
                    + ", exports=[" + joined + "], resource=" + resourceName);
        }
        context.stats().add("antiDebug.nativeGuard.exports", exportsCount);
        context.stats().text("antiDebug.nativeGuard.exportNames", joined.toString());
        int plaintextHits = countOf(library, "umbra");
        context.stats().add("antiDebug.nativeGuard.plaintextHits", plaintextHits);

        if (plaintextHits > 1) {
            String contexts = "";
            try {
                String text = new String(library, StandardCharsets.ISO_8859_1);
                int at = -1;
                while ((at = text.indexOf("umbra", at + 1)) >= 0) {
                    int from = Math.max(0, at - 16);
                    contexts = contexts + " @" + at + "["
                            + text.substring(from, Math.min(text.length(), at + 48))
                            .replace('\0', '.') + "]";
                }
            } catch (Exception ignored) {

            }
            throw new IllegalStateException("native-guard hygiene assertion failed: "
                    + plaintextHits + " plaintext 'umbra' strings remain in the guard PE:"
                    + contexts);
        }
        context.stats().add("antiDebug.nativeGuard.peTimestamp",
                PeImage.timestamp(library) & 0xFFFFFFFFL);
        context.stats().text("antiDebug.nativeGuard.sections",
                java.util.Arrays.toString(PeImage.sectionNames(library)));
    }

    private static int indexOf(byte[] data, String text, int from) {
        byte[] needle = text.getBytes(StandardCharsets.UTF_8);
        outer:
        for (int i = Math.max(0, from); i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static int countOf(byte[] data, String text) {
        byte[] needle = text.getBytes(StandardCharsets.UTF_8);
        int count = 0;
        outer:
        for (int i = 0; i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            count++;
        }
        return count;
    }
    private static GuardBuild buildGuard(PassContext context, String compiler, String guardName,
                                         long secret, GuardFeatures features, long sampleSeed,
                                         String otpClass) {
        String target = guardTarget();
        String suffix = librarySuffix(target);

        if (features.codeSampling && !"windows".equals(target)) {
            features = withoutCodeSampling(features);
        }
        Path temp = null;
        try {

            String neutral = "m" + GuardOptions.hex(
                    secret ^ 0x4D4F44554C454E41L, 16);
            temp = Files.createTempDirectory(neutral);
            Path sourceFile = temp.resolve("g" + neutral.substring(1) + ".c");
            Path libraryFile = temp.resolve(neutral + suffix);
            String source = GuardCodeGenerator.generate(guardName, secret, features, null, otpClass);
            if (source.indexOf("@@") >= 0) {
                throw new IllegalStateException(
                        "native-guard hygiene assertion failed: generated C still has @@ placeholders");
            }
            Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));

            boolean reproducible = !context.config().optionBool("native.timestamp", false);

            NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, libraryFile,
                    target, "-s", context.log(), reproducible);
            context.stats().add("antiDebug.nativeGuard.compile.ms", result.millis());
            if (!result.success()) {
                return failedGuardBuild(context, result);
            }
            byte[] library = Files.readAllBytes(result.library());
            int samples = 0;
            if (features.codeSampling) {
                byte[] patched = PeImage.withCodeSamples(library, sampleSeed,
                        GuardCodeGenerator.sampleMagic(secret));
                if (patched != null && patched.length == library.length) {
                    library = patched;
                    samples = GuardCodeGenerator.CODE_SAMPLE_COUNT;
                } else {
                    context.log().warn("native-guard: could not patch randomized code-section "
                            + "samples into the compiled guard; the sample check stays inert");
                }
            }
            context.stats().add("antiDebug.nativeGuard.compiles", 1);
            return new GuardBuild(source, library, features, samples);
        } catch (IOException failure) {
            context.log().warn("native-guard: could not build the guard library: %s", failure);
            return null;
        } finally {
            deleteRecursively(temp);
        }
    }

    private static GuardBuild failedGuardBuild(PassContext context, NativeCompiler.Result result) {
        context.log().warn("native-guard: guard library compilation failed (%s); "
                + "using the Java fallback guard", result.command());
        String output = result.output();
        if (output != null && !output.trim().isEmpty()) {
            context.log().warn("native-guard: compiler output: %s", abbreviate(output));
        }
        return null;
    }

    private static GuardFeatures withoutCodeSampling(GuardFeatures features) {
        GuardFeatures.Builder builder = GuardFeatures.forLevel(features.level);
        builder.watchdogMs(features.watchdogMs)
                .frida(features.frida)
                .hash(features.hash)
                .remoteThread(features.remoteThread)
                .execMemoryScan(features.execMemoryScan)
                .imageBreakpoints(features.imageBreakpoints)
                .codeSampling(false)
                .moduleIntegrity(features.moduleIntegrity)
                .timing(features.timing)
                .handleDump(features.handleDump)
                .codeCrc(features.codeCrc)
                .pageGuard(features.pageGuard)
                .textGuard(features.textGuard)
                .guardProbe(features.guardProbe)
                .execWhitelist(features.execWhitelist)
                .linuxChecks(features.linuxChecks);
        return builder.build();
    }

    private static String guardTarget() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.indexOf("win") >= 0) {
            return "windows";
        }
        if (os.indexOf("mac") >= 0) {
            return "macos";
        }
        return "linux";
    }

    private static String librarySuffix(String target) {
        if ("windows".equals(target)) {
            return ".dll";
        }
        if ("macos".equals(target)) {
            return ".dylib";
        }
        return ".so";
    }
    private static String resolveAction(UmbraConfig config) {
        String value = config.option("antiDebug.action", "throw").trim()
                .toLowerCase(java.util.Locale.ROOT);
        if ("exit".equals(value) || "throw".equals(value) || "corrupt".equals(value)
                || "log".equals(value)) {
            return value;
        }
        return "throw";
    }

    private static boolean installGuardLauncher(PassContext context, String guardName, Random random) {
        String original = context.classes().mainClass();

        ClassPool.Resource launcherManifest = context.classes().resource("META-INF/MANIFEST.MF");
        if (launcherManifest != null) {
            String rsrcMain = io.umbra.core.util.Jars
                    .parseManifest(launcherManifest.bytes()).get("Rsrc-Main-Class");
            if (rsrcMain != null && !rsrcMain.trim().isEmpty()) {
                original = rsrcMain.trim().replace('.', '/');
            }
        }
        if (original == null || original.isEmpty() || RuntimeNames.isRuntime(original) || original.startsWith("umbra/")) {
            return false;
        }
        String mapped = context.mappings().classes().get(original);
        if (mapped != null && !mapped.isEmpty()) {
            original = mapped;
        }
        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put("@@GUARD@@", guardName.replace('/', '.'));
        replacements.put("@@MAIN@@", original.replace('/', '.'));
        try {
            String launcher = TemplateInjector.inject(context.classes(),
                    UmbraGuardLauncher.class, RuntimeNames.path("L"), context.config().seed(),
                    replacements);
            ClassPool.Resource manifest = context.classes().resource("META-INF/MANIFEST.MF");
            if (manifest != null) {
                Map<String, String> attributes = io.umbra.core.util.Jars.parseManifest(manifest.bytes());
                if (attributes.get("Rsrc-Main-Class") != null) {

                    attributes.put("Rsrc-Main-Class", launcher.replace('/', '.'));
                    context.classes().putResource("META-INF/MANIFEST.MF",
                            io.umbra.core.util.Jars.writeManifest(attributes),
                            manifest.time(), manifest.method());
                    context.log().info("native-guard: Eclipse runnable jar detected, "
                            + "guard routed through Rsrc-Main-Class (%s)", original);
                    return true;
                }
                attributes.put("Main-Class", launcher.replace('/', '.'));
                context.classes().setMainClass(launcher);

                context.classes().putResource("META-INF/MANIFEST.MF",
                        io.umbra.core.util.Jars.writeManifest(attributes),
                        manifest.time(), manifest.method());
            } else {
                context.classes().setMainClass(launcher);
            }
            return true;
        } catch (RuntimeException failure) {
            context.log().warn("native-guard: launcher injection failed: %s", failure);
            return false;
        }
    }
    private static String abbreviate(String text) {
        String trimmed = text.trim();
        return trimmed.length() <= 6000 ? trimmed : trimmed.substring(0, 6000) + "... (truncated)";
    }

    private static List<String> collectNativeMethods(ClassPool pool) {
        List<String> names = new ArrayList<String>(pool.classes().keySet());
        Collections.sort(names);
        List<String> result = new ArrayList<String>();
        for (String name : names) {
            if (pool.isGenerated(name)) {
                continue;
            }
            ClassNode node = pool.getClass(name);
            if (node == null) {
                continue;
            }
            for (MethodNode method : node.methods) {
                if ((method.access & Opcodes.ACC_NATIVE) != 0) {
                    result.add(node.name + "#" + method.name + "#" + method.desc);
                }
            }
        }
        return result;
    }

    private static String joinMethods(List<String> methods) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < methods.size(); i++) {
            if (i > 0) {
                out.append('\n');
            }
            out.append(methods.get(i));
        }
        return out.toString();
    }

    private static String uniqueName(ClassPool pool, NameGenerator names, String prefix) {
        for (int attempt = 0; attempt < 10000; attempt++) {
            String candidate = prefix + names.random(10);
            if (pool.getClass(candidate) == null) {
                return candidate;
            }
        }
        throw new IllegalStateException("unable to allocate a unique guard class name");
    }

    private static void injectGuardTemplates(ClassPool pool, String guardName, String watchdogName,
                                             Map<String, String> replacements) throws IOException {
        Map<String, String> watchdogRemap = new LinkedHashMap<String, String>();
        watchdogRemap.put(UmbraGuard.class.getName().replace('.', '/'), watchdogName);
        watchdogRemap.put(UmbraNativeGuard.class.getName().replace('.', '/'), guardName);
        inject(pool, UmbraGuard.class, watchdogName, watchdogRemap, new LinkedHashMap<String, String>());

        Map<String, String> guardRemap = new LinkedHashMap<String, String>();
        guardRemap.put(UmbraNativeGuard.class.getName().replace('.', '/'), guardName);
        guardRemap.put(UmbraGuard.class.getName().replace('.', '/'), watchdogName);
        inject(pool, UmbraNativeGuard.class, guardName, guardRemap, replacements);
    }

    private static void inject(ClassPool pool, Class<?> template, String newName,
                               Map<String, String> classRemap,
                               Map<String, String> replacements) throws IOException {
        ClassNode node = TemplateInjector.read(template);
        ClassNode remapped = new ClassNode();
        node.accept(new ClassRemapper(remapped, new SimpleRemapper(classRemap)));
        remapped.access |= Opcodes.ACC_SYNTHETIC;
        remapped.version = Math.min(remapped.version, Opcodes.V1_8);
        replaceConstants(remapped, replacements);

        TemplateInjector.stripDebugInfo(remapped);
        pool.addGenerated(remapped);
    }

    private static void replaceConstants(ClassNode node, Map<String, String> replacements) {
        if (replacements.isEmpty()) {
            return;
        }
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    if (ldc.cst instanceof String) {
                        ldc.cst = substitute(String.valueOf(ldc.cst), replacements);
                    }
                }
            }
        }
        for (FieldNode field : node.fields) {
            if (field.value instanceof String) {
                field.value = substitute(String.valueOf(field.value), replacements);
            }
        }
    }

    private static String substitute(String value, Map<String, String> replacements) {
        String result = value;
        for (Map.Entry<String, String> entry : replacements.entrySet()) {
            if (result.indexOf(entry.getKey()) >= 0) {
                result = result.replace(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    private static int instrument(PassContext context, String guardName, List<String> nativeMethods) {
        ClassPool pool = context.classes();
        String guardCheck = guardName;
        int instrumented = GuardSupport.instrumentMains(pool, guardCheck);
        List<String> owners = new ArrayList<String>();
        String mainClass = pool.mainClass();
        if (mainClass != null) {
            owners.add(mainClass);
        }
        for (String method : nativeMethods) {
            int hash = method.indexOf('#');
            String owner = hash > 0 ? method.substring(0, hash) : method;
            if (!owners.contains(owner)) {
                owners.add(owner);
            }
        }
        String dispatch = GuardSupport.ensureGuardDispatch(pool, guardCheck);
        for (String owner : owners) {
            ClassNode node = pool.getClass(owner);
            if (node == null || pool.isGenerated(owner) || pool.isFrozen(owner)) {
                continue;
            }
            if (addClinitHook(node, guardCheck, dispatch)) {
                instrumented++;
            }
        }
        return instrumented;
    }

    private static boolean addClinitHook(ClassNode node, String guardName, String dispatch) {
        MethodNode clinit = null;
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                clinit = method;
                break;
            }
        }
        InsnList hook = new InsnList();
        hook.add(GuardSupport.guardCall(dispatch, guardName));
        if (clinit != null) {
            if (alreadyHooked(clinit, guardName)) {
                return false;
            }
            clinit.instructions.insert(hook);
            clinit.maxStack = Math.max(clinit.maxStack, 1);
            return true;
        }
        MethodNode created = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        created.instructions.add(hook);
        created.instructions.add(new InsnNode(Opcodes.RETURN));
        created.maxStack = 1;
        created.maxLocals = 0;
        node.methods.add(created);
        return true;
    }

    private static boolean alreadyHooked(MethodNode method, String guardName) {
        AbstractInsnNode first = method.instructions.getFirst();
        while (first != null && first.getOpcode() < 0) {
            first = first.getNext();
        }
        if (first instanceof InvokeDynamicInsnNode) {
            InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) first;
            return "check".equals(indy.name) && "()V".equals(indy.desc)
                    && indy.bsmArgs != null && indy.bsmArgs.length == 1
                    && guardName.equals(indy.bsmArgs[0]);
        }
        if (!(first instanceof MethodInsnNode)) {
            return false;
        }
        MethodInsnNode call = (MethodInsnNode) first;
        return call.getOpcode() == Opcodes.INVOKESTATIC && guardName.equals(call.owner)
                && "check".equals(call.name) && "()V".equals(call.desc);
    }

    private static void deleteRecursively(Path path) {
        if (path == null) {
            return;
        }
        try {
            if (!Files.exists(path)) {
                return;
            }
            Files.walk(path)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException ignored) {

                        }
                    });
        } catch (IOException ignored) {

        }
    }
}

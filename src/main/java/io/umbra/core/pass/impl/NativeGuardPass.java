package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
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

    @Override
    public String name() {
        return "native-guard";
    }

    @Override
    public int order() {
        return 114;
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
        String guardName = uniqueName(context.classes(), names, "umbra/runtime/G");
        String watchdogName = uniqueName(context.classes(), names, "umbra/runtime/W");

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
        if (compiler != null && NativeCompiler.hasJniHeaders()) {
            GuardBuild build = buildGuard(context, compiler, guardName, secret, features,
                    sampleSeed);
            if (build != null) {
                library = build.library;
                source = build.source;
                features = build.features;
                buildSamples = build.codeSamples;
                resourceName = "umbra/guard/" + names.random(16) + ".dat";
                fileHashHex = GuardOptions.hex(GuardOptions.fnv1a64(library), 16);
                prologueCheckHex = GuardOptions.bytesToHex(PeImage.exportPrologue(library,
                        GuardCodeGenerator.exportSymbol(guardName, "nativeCheck"),
                        NATIVE_CHECK_PROLOGUE));
                prologueTokenHex = GuardOptions.bytesToHex(PeImage.exportPrologue(library,
                        GuardCodeGenerator.exportSymbol(guardName, "nativeToken"),
                        NATIVE_CHECK_PROLOGUE));
            }
        } else {
            context.log().warn("native-guard: no C toolchain/JNI headers; "
                    + "using the Java fallback guard");
        }

        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put("@@RESOURCE@@", resourceName);
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

    // ------------------------------------------------------------------
    // Options and guard build
    // ------------------------------------------------------------------

    /**
     * Derives the dynamic-protection feature set from {@code antiDebug.level}
     * (1 = classic checks, 2 = dynamic set, 3 = + handle scan) and the explicit
     * {@code antiDebug.*} overrides.
     */
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
                .execMemoryScan(config.optionBool("antiDebug.execMemoryScan", dynamic))
                .imageBreakpoints(config.optionBool("antiDebug.imageBreakpoints", dynamic))
                .codeSampling(config.optionBool("antiDebug.codeSampling", dynamic))
                .moduleIntegrity(config.optionBool("antiDebug.moduleIntegrity", dynamic))
                .timing(config.optionBool("antiDebug.timing", dynamic))
                .handleDump(config.optionBool("antiDebug.handleDump", level >= 3))
                .linuxChecks(config.optionBool("antiDebug.linuxChecks", true));
        return builder.build();
    }

    /** Result of the guard build (single compile, optional post-link sample patch). */
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

    /**
     * Compiles the guard library and returns its bytes.
     *
     * <p>Randomized code-section sampling does not need a second compilation: the
     * guard exports a fixed-size sample table with {@code count = 0} and the
     * protection pass patches the random RVAs/expected bytes into the linked
     * image ({@link PeImage#withCodeSamples}). The runtime check is a no-op while
     * the table count is zero, so a failed patch degrades safely. Any compile
     * failure falls back to the Java guard with a warning instead of emitting a
     * broken library.</p>
     */
    private static GuardBuild buildGuard(PassContext context, String compiler, String guardName,
                                         long secret, GuardFeatures features, long sampleSeed) {
        String target = guardTarget();
        String suffix = librarySuffix(target);
        // Samples are PE RVAs: only Windows guard images can be patched this way.
        if (features.codeSampling && !"windows".equals(target)) {
            features = withoutCodeSampling(features);
        }
        Path temp = null;
        try {
            temp = Files.createTempDirectory("umbra-guard");
            Path sourceFile = temp.resolve("umbra_guard.c");
            Path libraryFile = temp.resolve("umbra_guard" + suffix);
            String source = GuardCodeGenerator.generate(guardName, secret, features);
            Files.write(sourceFile, source.getBytes(StandardCharsets.UTF_8));
            NativeCompiler.Result result = NativeCompiler.compile(compiler, sourceFile, libraryFile,
                    target, "", context.log());
            context.stats().add("antiDebug.nativeGuard.compile.ms", result.millis());
            if (!result.success()) {
                return failedGuardBuild(context, result);
            }
            byte[] library = Files.readAllBytes(result.library());
            int samples = 0;
            if (features.codeSampling) {
                byte[] patched = PeImage.withCodeSamples(library, sampleSeed);
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
                .linuxChecks(features.linuxChecks);
        return builder.build();
    }

    /** Guard target platform derived from the host OS. */
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

    /**
     * Installs the guard launcher template as the new manifest entry point:
     * the guard runs before the original main class is loaded, then the real
     * main(String[]) is invoked reflectively. This prevents a premain agent
     * from backfilling the main class to remove the guard call.
     */
    private static boolean installGuardLauncher(PassContext context, String guardName, Random random) {
        String original = context.classes().mainClass();
        if (original == null || original.isEmpty() || original.startsWith("umbra/")) {
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
                    UmbraGuardLauncher.class, "umbra/runtime/L", context.config().seed(),
                    replacements);
            context.classes().setMainClass(launcher);
            // Make the launcher visible in the manifest immediately so later
            // passes (resource rewrite, watermark, writer) keep it instead of
            // restoring the original entry point.
            ClassPool.Resource manifest = context.classes().resource("META-INF/MANIFEST.MF");
            if (manifest != null) {
                Map<String, String> attributes = io.umbra.core.util.Jars.parseManifest(manifest.bytes());
                attributes.put("Main-Class", launcher.replace('/', '.'));
                context.classes().putResource("META-INF/MANIFEST.MF",
                        io.umbra.core.util.Jars.writeManifest(attributes),
                        manifest.time(), manifest.method());
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

    // ------------------------------------------------------------------
    // Native method inventory (anti-backfill target list)
    // ------------------------------------------------------------------

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

    // ------------------------------------------------------------------
    // Template injection
    // ------------------------------------------------------------------

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
                        String replaced = replacements.get(ldc.cst);
                        if (replaced != null) {
                            ldc.cst = replaced;
                        }
                    }
                }
            }
        }
        for (FieldNode field : node.fields) {
            if (field.value instanceof String) {
                String replaced = replacements.get(field.value);
                if (replaced != null) {
                    field.value = replaced;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Entry point instrumentation
    // ------------------------------------------------------------------

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
        for (String owner : owners) {
            ClassNode node = pool.getClass(owner);
            if (node == null || pool.isGenerated(owner) || pool.isFrozen(owner)) {
                continue;
            }
            if (addClinitHook(node, guardCheck)) {
                instrumented++;
            }
        }
        return instrumented;
    }

    private static boolean addClinitHook(ClassNode node, String guardName) {
        MethodNode clinit = null;
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                clinit = method;
                break;
            }
        }
        InsnList hook = new InsnList();
        hook.add(new MethodInsnNode(Opcodes.INVOKESTATIC, guardName, "check", "()V", false));
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
                            // best effort
                        }
                    });
        } catch (IOException ignored) {
            // best effort
        }
    }
}

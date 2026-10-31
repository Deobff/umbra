package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.rules.Glob;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.crypto.CryptoSupport;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import io.umbra.core.util.RuntimeNames;

/**
 * Opt-in reflection gate (KBox {@code reflectionGate} parity).
 *
 * <p>The pass seals the protected program's classes at run time and routes the
 * reflective lookup call sites that appear <em>inside the protected code</em>
 * through an injected seal class:</p>
 *
 * <ul>
 *   <li>{@code Class.forName(String)} / {@code Class.forName(String, boolean,
 *       ClassLoader)} are replaced by the seal's own lookups, which deny or mask
 *       loading a sealed class from a foreign caller;</li>
 *   <li>{@code Class.getDeclaredMethod/getMethod/getDeclaredMethods/getMethods/
 *       getDeclaredField/getField/getDeclaredFields/getFields/
 *       getDeclaredConstructor(s)/getConstructor(s)} receive the target class as
 *       an explicit first argument and are checked before the real lookup.</li>
 * </ul>
 *
 * <p>"Sealed" classes are the transformed program classes matching
 * {@code reflectionGate.sealed} (default {@code *}). A lookup is allowed when
 * the target is not sealed, the caller is the target class itself, or the
 * caller matches one of {@code reflectionGate.allow} globs. Otherwise
 * {@code reflectionGate.action=deny} throws {@code SecurityException} while
 * {@code mask} throws the lookup's natural not-found exception, so a
 * decompiled/injected caller cannot distinguish a sealed member from a missing
 * one.</p>
 *
 * <p><b>This changes observable semantics</b> (frameworks that reflect across
 * protected classes stop working unless allow-listed), therefore the pass is
 * disabled by default ({@code reflectionGate.enabled=false}) exactly as the
 * plan requires. The seal itself is a normal Java class injected next to the
 * other runtime helpers; no JVM agent, JNI or Unsafe is involved.</p>
 */
public final class ReflectionGatePass implements Pass {

    private static final String SEALED_SPEC = "@@SEALED@@";
    private static final String ALLOW_SPEC = "@@ALLOW@@";
    private static final String DENY_SPEC = "@@DENY@@";
    private static final String HIDDEN_SPEC = "@@HIDDEN@@";

    /** Placeholder class name of the injected seal (remapped at injection time). */
    private static final String SEAL_REFERENCE = "io/umbra/core/pass/impl/UmbraReflectionSeal";

    @Override
    public String name() {
        return "reflection-gate";
    }

    @Override
    public int order() {
        return 119;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("reflectionGate.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        Options options = Options.resolve(context);
        if (!options.enabled) {
            return;
        }
        List<String> sealed = collectSealed(context, options);
        if (sealed.isEmpty()) {
            context.log().info("reflection-gate: no sealed classes matched, pass skipped");
            context.stats().add("reflectionGate.sealed", 0);
            return;
        }
        int key = deriveKey(context);
        String sealName = injectSeal(context, sealed, options, key);
        int classes = 0;
        int sites = 0;
        int forNameSites = 0;
        int lookupSites = 0;
        int skipped = 0;
        for (ClassNode node : new ArrayList<ClassNode>(context.classes().classes().values())) {
            if (skip(context, node, options)) {
                continue;
            }
            Counts counts;
            try {
                counts = transformClass(node, sealName, options);
            } catch (RuntimeException failure) {
                skipped++;
                context.log().debug("reflection-gate: skipped class %s: %s", node.name, failure);
                continue;
            }
            if (counts.total > 0) {
                classes++;
                sites += counts.total;
                forNameSites += counts.forName;
                lookupSites += counts.lookups;
            }
        }
        context.stats().add("reflectionGate.classes", classes);
        context.stats().add("reflectionGate.sites", sites);
        context.stats().add("reflectionGate.forName", forNameSites);
        context.stats().add("reflectionGate.lookups", lookupSites);
        context.stats().add("reflectionGate.sealed", sealed.size());
        context.stats().add("reflectionGate.action", options.deny ? 1 : 0);
        context.stats().add("reflectionGate.skipped", skipped);
        context.log().info("reflection-gate[%s]: sealed %d classes, rewrote %d reflective call sites "
                        + "(%d forName, %d member lookups) across %d classes",
                options.deny ? "deny" : "mask", sealed.size(), sites, forNameSites, lookupSites, classes);
    }

    private static boolean skip(PassContext context, ClassNode node, Options options) {
        if (node == null || node.name == null) {
            return true;
        }
        if ("module-info".equals(node.name) || node.name.endsWith("/module-info")) {
            return true;
        }
        if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
            return true;
        }
        if (context.rules().skipBodyTransform(node.name)) {
            return true;
        }
        // Keep rules protect names from renaming; they do not make the reflection
        // call sites disappear, and a gate that only covers non-kept classes would
        // miss the reflection calls that actually matter (kept/probe classes).
        // Method bodies are only rewritten at the call site and the target's
        // descriptor never changes, so kept contracts stay intact.
        if (context.rules().hasKeepAnnotation(node)) {
            return true;
        }
        return !options.matchesClass(node.name);
    }

    // ------------------------------------------------------------------
    // Injection
    // ------------------------------------------------------------------

    private static List<String> collectSealed(PassContext context, Options options) {
        List<String> sealed = new ArrayList<String>();
        for (ClassNode node : context.classes().classes().values()) {
            if (node == null || node.name == null || node.name.startsWith("[")) {
                continue;
            }
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (options.isSealed(node.name)) {
                // The seal compares against Class#getName(), i.e. the dotted form.
                sealed.add(node.name.replace('/', '.'));
            }
        }
        java.util.Collections.sort(sealed);
        return sealed;
    }

    private static String injectSeal(PassContext context, List<String> sealed, Options options,
                                     int key) {
        String name = CryptoSupport.randomName(context.classes(), context.config().seed(),
                "reflection-gate-seal", RuntimeNames.path("R"));
        ClassNode template = TemplateInjector.read(UmbraReflectionSeal.class);
        ClassNode remapped = new ClassNode();
        template.accept(new ClassRemapper(remapped, new SimpleRemapper(template.name, name)));
        remapped.name = name;
        remapped.access |= Opcodes.ACC_PUBLIC | Opcodes.ACC_SYNTHETIC;
        remapped.version = Math.min(remapped.version, Opcodes.V1_8);
        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put(SEALED_SPEC, encode(sealed, key));
        replacements.put(ALLOW_SPEC, encode(options.allow, key));
        replacements.put(DENY_SPEC, options.deny ? "1" : "0");
        replacements.put(HIDDEN_SPEC, String.valueOf(key));
        CryptoSupport.replaceConstants(remapped, replacements);
        // The seal is an injected runtime template: its SourceFile attribute would
        // otherwise publish "UmbraReflectionSeal.java" in the constant pool.
        TemplateInjector.stripDebugInfo(remapped);
        context.classes().addGenerated(remapped);
        context.log().debug("reflection-gate: injected seal %s (template %s)", name, SEAL_REFERENCE);
        return name;
    }

    /** XOR + Base64 encoding of a newline separated string list. */
    static String encode(List<String> values, int key) {
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                raw.append('\n');
            }
            raw.append(values.get(i));
        }
        byte[] bytes = raw.toString().getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] ^= (byte) (key >>> (8 * (i & 3)));
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static int deriveKey(PassContext context) {
        long mixed = context.config().seed() * 0x9E3779B97F4A7C15L + 0x5DEECE66DL;
        int key = (int) (mixed ^ (mixed >>> 32));
        return key == 0 ? 0x5A17 : key;
    }

    // ------------------------------------------------------------------
    // Call-site rewriting
    // ------------------------------------------------------------------

    private static Counts transformClass(ClassNode node, String sealName, Options options) {
        Counts counts = new Counts();
        for (MethodNode method : node.methods) {
            if (method.instructions == null || method.instructions.size() == 0) {
                continue;
            }
            int methodSites = 0;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
                AbstractInsnNode next = insn.getNext();
                if (methodSites >= options.maxPerMethod) {
                    break;
                }
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode call = (MethodInsnNode) insn;
                    Repair repair = repairFor(call);
                    if (repair != null) {
                        method.instructions.insertBefore(call, new MethodInsnNode(
                                Opcodes.INVOKESTATIC, sealName, repair.name, repair.desc, false));
                        method.instructions.remove(call);
                        methodSites++;
                        if (repair.forName) {
                            counts.forName++;
                        } else {
                            counts.lookups++;
                        }
                    }
                }
                insn = next;
            }
            counts.total += methodSites;
        }
        return counts;
    }

    private static final class Counts {
        private int total;
        private int forName;
        private int lookups;
    }

    /** How one call site maps to the seal helper, or {@code null} when it is not gated. */
    private static Repair repairFor(MethodInsnNode call) {
        if (Opcodes.INVOKESTATIC == call.getOpcode() && "java/lang/Class".equals(call.owner)
                && "forName".equals(call.name)) {
            if ("(Ljava/lang/String;)Ljava/lang/Class;".equals(call.desc)
                    || "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;".equals(call.desc)) {
                return new Repair("forName", call.desc, true);
            }
            return null;
        }
        if (Opcodes.INVOKEVIRTUAL != call.getOpcode() || !"java/lang/Class".equals(call.owner)) {
            return null;
        }
        String name = call.name;
        String desc = call.desc;
        if ("(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;".equals(desc)
                && ("getDeclaredMethod".equals(name) || "getMethod".equals(name))) {
            return new Repair(name, "(Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/Class;)"
                    + "Ljava/lang/reflect/Method;", false);
        }
        if ("()[Ljava/lang/reflect/Method;".equals(desc)
                && ("getDeclaredMethods".equals(name) || "getMethods".equals(name))) {
            return new Repair(name, "(Ljava/lang/Class;)[Ljava/lang/reflect/Method;", false);
        }
        if ("(Ljava/lang/String;)Ljava/lang/reflect/Field;".equals(desc)
                && ("getDeclaredField".equals(name) || "getField".equals(name))) {
            return new Repair(name, "(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;",
                    false);
        }
        if ("()[Ljava/lang/reflect/Field;".equals(desc)
                && ("getDeclaredFields".equals(name) || "getFields".equals(name))) {
            return new Repair(name, "(Ljava/lang/Class;)[Ljava/lang/reflect/Field;", false);
        }
        if ("([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;".equals(desc)
                && ("getDeclaredConstructor".equals(name) || "getConstructor".equals(name))) {
            return new Repair(name, "(Ljava/lang/Class;[Ljava/lang/Class;)"
                    + "Ljava/lang/reflect/Constructor;", false);
        }
        if ("()[Ljava/lang/reflect/Constructor;".equals(desc)
                && ("getDeclaredConstructors".equals(name) || "getConstructors".equals(name))) {
            return new Repair(name, "(Ljava/lang/Class;)[Ljava/lang/reflect/Constructor;", false);
        }
        return null;
    }

    private static final class Repair {
        private final String name;
        private final String desc;
        private final boolean forName;

        private Repair(String name, String desc, boolean forName) {
            this.name = name;
            this.desc = desc;
            this.forName = forName;
        }
    }

    // ------------------------------------------------------------------
    // Options
    // ------------------------------------------------------------------

    /** Resolved pass configuration. */
    static final class Options {
        private boolean enabled;
        private boolean deny = true;
        private int maxPerMethod = 64;
        private List<Glob> sealed = new ArrayList<Glob>();
        private List<Glob> methods = new ArrayList<Glob>();
        private List<String> allow = new ArrayList<String>();
        private List<Glob> allowGlobs = new ArrayList<Glob>();

        static Options resolve(PassContext context) {
            Options options = new Options();
            options.enabled = context.config().optionBool("reflectionGate.enabled", false);
            options.deny = !"mask".equalsIgnoreCase(
                    context.config().option("reflectionGate.action", "deny").trim());
            options.maxPerMethod = Math.max(1,
                    context.config().optionInt("reflectionGate.maxPerMethod", 64));
            options.sealed = parseGlobs(context.config().option("reflectionGate.sealed", "**"));
            options.methods = parseGlobs(context.config().option("reflectionGate.methods", "**"));
            String allow = context.config().option("reflectionGate.allow", "");
            if (allow != null) {
                for (String token : allow.split("[,;\\s]+")) {
                    if (!token.trim().isEmpty()) {
                        // Runtime caller names are dotted (Class#getName()).
                        options.allow.add(token.trim().replace('/', '.'));
                        options.allowGlobs.add(new Glob(token.trim()));
                    }
                }
            }
            return options;
        }

        private static List<Glob> parseGlobs(String raw) {
            List<Glob> globs = new ArrayList<Glob>();
            if (raw != null) {
                for (String token : raw.split("[,;\\s]+")) {
                    if (!token.trim().isEmpty()) {
                        globs.add(new Glob(token.trim()));
                    }
                }
            }
            if (globs.isEmpty()) {
                globs.add(new Glob("**"));
            }
            return globs;
        }

        boolean isSealed(String internalName) {
            for (int i = 0; i < sealed.size(); i++) {
                if (sealed.get(i).matches(internalName)) {
                    return true;
                }
            }
            return false;
        }

        boolean matchesClass(String internalName) {
            for (int i = 0; i < methods.size(); i++) {
                if (methods.get(i).matches(internalName)) {
                    return true;
                }
            }
            return false;
        }
    }
}

/**
 * Runtime seal template injected by {@link ReflectionGatePass} (same file, so no
 * extra ownership surface). Package-private here, made public in the injected
 * copy. Contains no nested classes and references only JDK types.
 */
final class UmbraReflectionSeal {

    private static final String SEALED_SPEC = "@@SEALED@@";
    private static final String ALLOW_SPEC = "@@ALLOW@@";
    private static final String DENY_SPEC = "@@DENY@@";
    private static final String HIDDEN_SPEC = "@@HIDDEN@@";

    private static final int HIDDEN = parseInt(HIDDEN_SPEC);
    private static final String SELF = UmbraReflectionSeal.class.getName();

    private static final String[] SEALED;
    private static final String[] ALLOW;
    private static final boolean DENY;

    static {
        SEALED = decode(SEALED_SPEC, HIDDEN);
        ALLOW = decode(ALLOW_SPEC, HIDDEN);
        DENY = !"0".equals(DENY_SPEC);
    }

    private UmbraReflectionSeal() {
    }

    // ---- Class.forName -------------------------------------------------

    public static Class<?> forName(String name) throws ClassNotFoundException {
        Class<?> target = Class.forName(name);
        checkTarget(target);
        return target;
    }

    public static Class<?> forName(String name, boolean initialize, ClassLoader loader)
            throws ClassNotFoundException {
        Class<?> target = Class.forName(name, initialize, loader);
        checkTarget(target);
        return target;
    }

    // ---- Method lookups ------------------------------------------------

    public static java.lang.reflect.Method getDeclaredMethod(Class<?> target, String name,
                                                             Class<?>[] types)
            throws NoSuchMethodException {
        checkMethod(target);
        return target.getDeclaredMethod(name, types);
    }

    public static java.lang.reflect.Method getMethod(Class<?> target, String name, Class<?>[] types)
            throws NoSuchMethodException {
        checkMethod(target);
        return target.getMethod(name, types);
    }

    public static java.lang.reflect.Method[] getDeclaredMethods(Class<?> target) {
        if (!anyAllowed(target)) {
            return new java.lang.reflect.Method[0];
        }
        return target.getDeclaredMethods();
    }

    public static java.lang.reflect.Method[] getMethods(Class<?> target) {
        if (!anyAllowed(target)) {
            return new java.lang.reflect.Method[0];
        }
        return target.getMethods();
    }

    public static java.lang.reflect.Field getDeclaredField(Class<?> target, String name)
            throws NoSuchFieldException {
        checkField(target);
        return target.getDeclaredField(name);
    }

    public static java.lang.reflect.Field getField(Class<?> target, String name)
            throws NoSuchFieldException {
        checkField(target);
        return target.getField(name);
    }

    public static java.lang.reflect.Field[] getDeclaredFields(Class<?> target) {
        if (!anyAllowed(target)) {
            return new java.lang.reflect.Field[0];
        }
        return target.getDeclaredFields();
    }

    public static java.lang.reflect.Field[] getFields(Class<?> target) {
        if (!anyAllowed(target)) {
            return new java.lang.reflect.Field[0];
        }
        return target.getFields();
    }

    public static java.lang.reflect.Constructor<?> getDeclaredConstructor(Class<?> target,
                                                                          Class<?>[] types)
            throws NoSuchMethodException {
        checkMethod(target);
        return target.getDeclaredConstructor(types);
    }

    public static java.lang.reflect.Constructor<?> getConstructor(Class<?> target, Class<?>[] types)
            throws NoSuchMethodException {
        checkMethod(target);
        return target.getConstructor(types);
    }

    public static java.lang.reflect.Constructor<?>[] getDeclaredConstructors(Class<?> target) {
        if (!anyAllowed(target)) {
            return new java.lang.reflect.Constructor<?>[0];
        }
        return target.getDeclaredConstructors();
    }

    public static java.lang.reflect.Constructor<?>[] getConstructors(Class<?> target) {
        if (!anyAllowed(target)) {
            return new java.lang.reflect.Constructor<?>[0];
        }
        return target.getConstructors();
    }

    // ---- Seal policy ---------------------------------------------------

    private static void checkTarget(Class<?> target) throws ClassNotFoundException {
        if (allowed(target)) {
            return;
        }
        if (DENY) {
            throw new SecurityException("reflection denied");
        }
        throw new ClassNotFoundException("");
    }

    private static void checkMethod(Class<?> target) throws NoSuchMethodException {
        if (allowed(target)) {
            return;
        }
        if (DENY) {
            throw new SecurityException("reflection denied");
        }
        throw new NoSuchMethodException("");
    }

    private static void checkField(Class<?> target) throws NoSuchFieldException {
        if (allowed(target)) {
            return;
        }
        if (DENY) {
            throw new SecurityException("reflection denied");
        }
        throw new NoSuchFieldException("");
    }

    /** Plural lookups cannot throw checked exceptions; denial masks as "nothing found". */
    private static boolean anyAllowed(Class<?> target) {
        if (allowed(target)) {
            return true;
        }
        if (DENY) {
            throw new SecurityException("reflection denied");
        }
        return false;
    }

    private static boolean allowed(Class<?> target) {
        if (target == null) {
            return true;
        }
        String targetName = target.getName();
        if (!isSealed(targetName)) {
            return true;
        }
        String caller = caller();
        if (caller == null || caller.equals(targetName)) {
            return true;
        }
        for (int i = 0; i < ALLOW.length; i++) {
            if (glob(ALLOW[i], caller)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSealed(String name) {
        for (int i = 0; i < SEALED.length; i++) {
            if (SEALED[i].equals(name)) {
                return true;
            }
        }
        return false;
    }

    /** First stack frame that is not this helper (the reflective call site). */
    private static String caller() {
        StackTraceElement[] trace = new Throwable().getStackTrace();
        for (int i = 0; i < trace.length; i++) {
            String name = trace[i].getClassName();
            if (!SELF.equals(name)) {
                return name;
            }
        }
        return null;
    }

    /** Minimal glob: {@code *} matches any characters including dots. */
    private static boolean glob(String pattern, String value) {
        int p = 0;
        int v = 0;
        int star = -1;
        int mark = 0;
        while (v < value.length()) {
            if (p < pattern.length() && pattern.charAt(p) == '*') {
                star = p++;
                mark = v;
            } else if (p < pattern.length() && pattern.charAt(p) == value.charAt(v)) {
                p++;
                v++;
            } else if (star >= 0) {
                p = star + 1;
                v = ++mark;
            } else {
                return false;
            }
        }
        while (p < pattern.length() && pattern.charAt(p) == '*') {
            p++;
        }
        return p == pattern.length();
    }

    private static String[] decode(String encoded, int key) {
        byte[] bytes = java.util.Base64.getDecoder().decode(encoded);
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] ^= (byte) (key >>> (8 * (i & 3)));
        }
        String raw = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        if (raw.isEmpty()) {
            return new String[0];
        }
        return raw.split("\n");
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }
}

package io.umbra.core.runtime.crypto;

import io.umbra.core.model.ClassPool;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.UmbraGuardCall;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.Map;
import java.util.Random;
import io.umbra.core.util.RuntimeNames;

/**
 * Shared pass-side helper that wires startup guards into program entry points
 * and injects the unified runtime guard template.
 *
 * <p>The runtime guards are ordinary runtime templates with a
 * {@code public static void check()} method. {@link #instrumentEntryPoints}
 * inserts a call at the start of every {@code main(String[])} method (and at an
 * explicitly configured encrypted-archive entry point), keeping the guard
 * classes free of any knowledge about the program layout.</p>
 *
 * <p>{@link #ensureRuntimeGuard} injects {@link UmbraRuntimeGuard} under a name
 * that is derived deterministically from the run seed, so independent passes
 * (anti-debug, integrity, class encryption) reuse the same injected copy instead
 * of shipping duplicate detection code. The runtime guard has no compile-time
 * references to other Umbra classes; passes that need to call it resolve the
 * name through this helper (or an injected placeholder).</p>
 */
public final class GuardSupport {

    private static final String MAIN_DESC = "([Ljava/lang/String;)V";

    /** Internal-name prefix of the unified runtime guard. */
    /** Resolved per run, because one JVM may protect several archives. */
    private static String runtimeGuardPrefix() {
        return RuntimeNames.path("G");
    }

    /** Salt that distinguishes the guard's deterministic name from other helpers. */
    private static final String RUNTIME_GUARD_SALT = "umbra-runtime-guard";

    private GuardSupport() {
    }

    /**
     * Returns the injected name of the unified runtime guard, injecting it on
     * first use.
     *
     * <p>The name only depends on the seed, so the anti-debug, integrity and
     * class-encryption passes all reach the same injected class (the first caller
     * supplies the placeholder substitutions). A pre-existing user class with the
     * same name is skipped deterministically.</p>
     *
     * @param pool         program class pool
     * @param seed         run seed
     * @param replacements string-constant substitutions for the template
     *                     (may be {@code null}); ignored when the guard already
     *                     exists
     * @return internal name of the injected runtime guard
     */
    public static String ensureRuntimeGuard(ClassPool pool, long seed,
                                            Map<String, String> replacements) {
        for (int attempt = 0; attempt < 64; attempt++) {
            String candidate = deterministicName(seed, RUNTIME_GUARD_SALT + "#" + attempt);
            ClassNode existing = pool.getClass(candidate);
            if (existing != null) {
                if (pool.isGenerated(candidate)) {
                    return candidate;
                }
                continue; // A real program class owns this name; try the next one.
            }
            CryptoSupport.injectWithCrypto(pool, UmbraRuntimeGuard.class, candidate, null,
                    replacements);
            return candidate;
        }
        throw new IllegalStateException("Unable to allocate a name for the unified runtime guard");
    }

    /** Internal-name prefix of the guard call-site dispatcher. */
    private static String dispatchPrefix() {
        return RuntimeNames.path("D");
    }

    /** Bootstrap descriptor of {@link UmbraGuardCall#bootstrap}. */
    private static final String DISPATCH_DESCRIPTOR =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;Ljava/lang/String;)"
                    + "Ljava/lang/invoke/CallSite;";

    private static String deterministicName(long seed, String salt) {
        Random random = new Random(seed ^ ((long) salt.hashCode() * 0x9E3779B97F4A7C15L));
        NameGenerator names = new NameGenerator(random, "");
        return runtimeGuardPrefix() + names.random(10);
    }

    /**
     * Ensures the indirect call-site dispatcher exists and returns its internal name.
     *
     * <p>The name is derived from the target class, so the independent passes that
     * emit calls into the same injected helper reuse one copy.</p>
     *
     * @param pool   program pool
     * @param target internal name of the class the call sites target
     * @return internal name of the injected dispatcher
     */
    public static String ensureGuardDispatch(ClassPool pool, String target) {
        String base = dispatchPrefix() + Integer.toHexString(target.hashCode() & 0x7FFFFFFF);
        for (int attempt = 0; attempt < 64; attempt++) {
            String candidate = attempt == 0 ? base : base + "$" + attempt;
            ClassNode existing = pool.getClass(candidate);
            if (existing != null) {
                if (pool.isGenerated(candidate)) {
                    return candidate;
                }
                continue; // A real program class owns this name; try the next one.
            }
            CryptoSupport.injectWithCrypto(pool, UmbraGuardCall.class, candidate, null, null);
            return candidate;
        }
        throw new IllegalStateException("Unable to allocate a name for the call dispatcher");
    }

    /**
     * Builds an {@code invokedynamic} that replaces a direct {@code invokestatic}
     * into an injected runtime helper.
     *
     * <p>The call site carries no reference to the target in the method body: the
     * bootstrap resolves the method once while the site links.</p>
     *
     * @param dispatch internal name returned by {@link #ensureGuardDispatch}
     * @param owner    internal name of the target class
     * @param name     target method name
     * @param desc     target method descriptor
     * @return the call-site instruction
     */
    public static AbstractInsnNode indirectCall(String dispatch, String owner, String name,
                                                String desc) {
        return new InvokeDynamicInsnNode(name, desc,
                new Handle(Opcodes.H_INVOKESTATIC, dispatch, "bootstrap", DISPATCH_DESCRIPTOR,
                        false),
                owner);
    }

    /**
     * Builds the {@code invokedynamic} that replaces {@code invokestatic
     * guard.check()}.
     *
     * @param dispatch internal name returned by {@link #ensureGuardDispatch}
     * @param guard    internal name of the guard class
     * @return the call-site instruction
     */
    public static AbstractInsnNode guardCall(String dispatch, String guard) {
        return indirectCall(dispatch, guard, "check", "()V");
    }

    /**
     * Inserts the guard check at the start of every program main method
     * and - when {@code entryOwner}/{@code entryMethod} are given - at that
     * entry point (used by the encrypted-archive loader).
     *
     * @return number of instrumented methods
     */
    public static int instrumentEntryPoints(ClassPool pool, String guard, String entryOwner,
                                            String entryMethod) {
        int instrumented = 0;
        String dispatch = ensureGuardDispatch(pool, guard);
        for (ClassNode node : pool.classes().values()) {
            if (pool.isGenerated(node.name) || pool.isFrozen(node.name)) {
                continue;
            }
            boolean explicit = entryOwner != null && entryOwner.equals(node.name)
                    && entryMethod != null && !entryMethod.isEmpty();
            boolean explicitDone = false;
            for (MethodNode method : node.methods) {
                if (method.instructions == null || method.instructions.size() == 0) {
                    continue;
                }
                if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                    continue;
                }
                boolean main = "main".equals(method.name) && MAIN_DESC.equals(method.desc);
                boolean entry = explicit && !explicitDone && entryMethod.equals(method.name);
                if (!main && !entry) {
                    continue;
                }
                if (alreadyGuarded(method, guard)) {
                    continue;
                }
                method.instructions.insert(guardCall(dispatch, guard));
                instrumented++;
                if (entry) {
                    explicitDone = true;
                }
            }
        }
        return instrumented;
    }

    /** Convenience overload without an explicit loader entry point. */
    public static int instrumentMains(ClassPool pool, String guard) {
        return instrumentEntryPoints(pool, guard, null, null);
    }

    /** Parses {@code class#method} into a two-element array ({@code class}, {@code method}). */
    public static String[] parseEntryPoint(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        String text = value.trim();
        int hash = text.indexOf('#');
        String owner;
        String method;
        if (hash >= 0) {
            owner = text.substring(0, hash).trim();
            method = text.substring(hash + 1).trim();
        } else {
            owner = text;
            method = "main";
        }
        if (owner.isEmpty()) {
            return null;
        }
        owner = owner.replace('.', '/');
        if (method.isEmpty()) {
            method = "main";
        }
        return new String[] { owner, method };
    }

    private static boolean alreadyGuarded(MethodNode method, String guard) {
        AbstractInsnNode first = method.instructions.getFirst();
        while (first != null && first.getOpcode() < 0) {
            first = first.getNext();
        }
        if (first instanceof InvokeDynamicInsnNode) {
            // Current form: invokedynamic check()V with the guard as bootstrap argument.
            InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) first;
            return "check".equals(indy.name) && "()V".equals(indy.desc)
                    && indy.bsmArgs != null && indy.bsmArgs.length == 1
                    && guard.equals(indy.bsmArgs[0]);
        }
        if (!(first instanceof MethodInsnNode)) {
            return false;
        }
        // Legacy form kept for pools instrumented by an older pass run.
        MethodInsnNode call = (MethodInsnNode) first;
        return call.getOpcode() == Opcodes.INVOKESTATIC && guard.equals(call.owner)
                && "check".equals(call.name) && "()V".equals(call.desc);
    }
}

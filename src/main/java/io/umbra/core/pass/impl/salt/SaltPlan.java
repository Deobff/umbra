package io.umbra.core.pass.impl.salt;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Immutable-by-construction plan produced before a single byte is written.
 *
 * <p>{@link io.umbra.core.pass.impl.SaltPass} decides every salt value, every
 * generated identifier and every call site up front, then applies the plan in
 * two transactions: the per-class class salts (field + {@code <clinit>} write +
 * method-local salt) and the cross-class method-parameter salts (descriptor
 * change plus call-site encoding). Planning first is what makes the transform
 * deterministic for a seed and lets an entire transaction be dropped without
 * leaving a half-rewritten descriptor behind.</p>
 */
public final class SaltPlan {

    private SaltPlan() {
    }

    /**
     * One class salt: the {@code public static final int} field of a class and the
     * value the dispatcher (or the constant fallback) writes into it.
     */
    public static final class ClassSalt {
        public final String owner;
        public final String fieldName;
        public final int value;
        public final int fakeValue;
        /** Where the field is inserted, so member order varies per build. */
        public final int position;
        public boolean materialized;

        public ClassSalt(String owner, String fieldName, int value, int fakeValue, int position) {
            this.owner = owner;
            this.fieldName = fieldName;
            this.value = value;
            this.fakeValue = fakeValue;
            this.position = position;
        }

        public String dottedName() {
            return owner.replace('/', '.');
        }
    }

    /**
     * One method salt: the value the method head materialises into a fresh local
     * through the self-cancelling class-salt shape.
     */
    public static final class MethodSalt {
        public final String owner;
        public final String name;
        public final String desc;
        public final int value;
        public final int mask;
        /** Slot the method head stores the resolved salt into; -1 until applied. */
        public int local = -1;
        public boolean applied;
        /** The live method node, used to key the exported secret by its final descriptor. */
        public MethodNode node;

        public MethodSalt(String owner, String name, String desc, int value, int mask) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
            this.value = value;
            this.mask = mask;
        }

        public String key() {
            return owner + "#" + name + "#" + desc;
        }
    }

    /** One method whose descriptor gains a trailing {@code int} salt parameter. */
    public static final class ParamSalt {
        public final String owner;
        public final String name;
        public final String desc;
        public final String newDesc;
        public final int value;

        public ParamSalt(String owner, String name, String desc, String newDesc, int value) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
            this.newDesc = newDesc;
            this.value = value;
        }

        public String key() {
            return owner + "#" + name + "#" + desc;
        }
    }

    /** One invocation of a salted method: the instruction plus the method holding it. */
    public static final class CallSite {
        public final ClassNode callerClass;
        public final MethodNode caller;
        public final MethodInsnNode insn;
        /** The call names a subclass of the declaring class instead of the owner. */
        public final boolean indirect;

        public CallSite(ClassNode callerClass, MethodNode caller, MethodInsnNode insn, boolean indirect) {
            this.callerClass = callerClass;
            this.caller = caller;
            this.insn = insn;
            this.indirect = indirect;
        }
    }

    /**
     * The generated identifiers of the strict salt dispatcher. They live in the
     * plan so the per-class {@code <clinit>} code can reference the dispatcher
     * before it is materialised.
     */
    public static final class DispatcherNames {
        public String className;
        public String hasher;
        public String initValues;
        public String retrieve;
        public String retrieveOrdered;
        public String classValues;
        public String initializedValues;

        public boolean complete() {
            return className != null && hasher != null && initValues != null
                    && retrieve != null && retrieveOrdered != null
                    && classValues != null && initializedValues != null;
        }
    }
}

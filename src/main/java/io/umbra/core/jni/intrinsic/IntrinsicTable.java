package io.umbra.core.jni.intrinsic;

import org.objectweb.asm.tree.MethodInsnNode;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Build-time table of JDK calls that the translator replaces with direct JNI
 * primitives.
 *
 * <p>The shape follows the reference implementation's intrinsic framework: a handler is identified by
 * the {@code (opcode, owner, name, descriptor)} quadruple, so a match is exact
 * and a JDK change cannot silently bind the wrong overload. the reference implementation ships the
 * framework without a single handler; this table is the first set of real ones.</p>
 *
 * <p>What qualifies: the call can be expressed with JNI calls that are both
 * cheaper than {@code GetMethodID + Call<Type>MethodA} and <em>do not name the
 * API in the constant pool</em>. That second property is the point — a native
 * library that never mentions {@code String.equals} no longer advertises which
 * JDK methods the program uses.</p>
 *
 * <p>Deliberately absent, with reasons: {@code System.arraycopy} cannot be
 * expressed without a runtime element-type dispatch (JNI has no memcpy for
 * arrays), which costs more calls than the Java invocation it would replace;
 * {@code Integer.valueOf} must return the JDK's cached instances, so it cannot
 * be re-implemented in native code without changing identity semantics.</p>
 */
public final class IntrinsicTable {

    /** {@code String.equals(Object)} - JNI region compare. */
    public static final String STRING_EQUALS = "string.equals";
    /** {@code String.length()} - JNI GetStringLength. */
    public static final String STRING_LENGTH = "string.length";
    /** {@code Object.getClass()} - JNI GetObjectClass. */
    public static final String OBJECT_GET_CLASS = "object.getClass";

    private static final Map<String, String> HANDLERS = new LinkedHashMap<String, String>();

    static {
        HANDLERS.put(key("java/lang/String", "equals", "(Ljava/lang/Object;)Z"), STRING_EQUALS);
        HANDLERS.put(key("java/lang/String", "length", "()I"), STRING_LENGTH);
        HANDLERS.put(key("java/lang/Object", "getClass", "()Ljava/lang/Class;"),
                OBJECT_GET_CLASS);
    }

    private IntrinsicTable() {
    }

    private static String key(String owner, String name, String descriptor) {
        return owner + '#' + name + '#' + descriptor;
    }

    /**
     * @return the handler id for this call, or {@code null} when the call must go
     *         through the generic {@code Call<Type>MethodA} path.
     */
    public static String lookup(MethodInsnNode insn) {
        if (insn == null) {
            return null;
        }
        return HANDLERS.get(key(insn.owner, insn.name, insn.desc));
    }

    public static int size() {
        return HANDLERS.size();
    }
}

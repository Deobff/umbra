package io.umbra.core.util;

import io.umbra.core.model.ClassPool;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;

/** ASM helpers shared by all passes. */
public final class AsmUtil implements Opcodes {

    /** Minimum class file version for MethodHandle/MethodType/InvokeDynamic constants. */
    public static final int MIN_INVOKE_DYNAMIC_VERSION = Opcodes.V1_7;

    /** Minimum class file version for {@code CONSTANT_Dynamic} (condy) constants. */
    public static final int MIN_CONSTANT_DYNAMIC_VERSION = Opcodes.V11;

    private AsmUtil() {
    }

    /**
     * Returns the minimum class file <em>major</em> version this class needs
     * because of its constant pool contents: 55 for {@code ConstantDynamic}, 51
     * for MethodHandle/MethodType/InvokeDynamic, or {@code 0} when no upgrade is
     * required. Note that {@link ClassNode#version} stores minor version in the
     * high 16 bits (a JDK 1.1 class reads as {@code V1_1 == 3 << 16 | 45}), so
     * only the low 16 bits are compared.
     */
    public static int requiredConstantVersion(ClassNode node) {
        if ((node.version & 0xFFFF) >= MIN_CONSTANT_DYNAMIC_VERSION) {
            return 0;
        }
        int required = 0;
        boolean constantDynamic = false;
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode) {
                    required = Math.max(required, MIN_INVOKE_DYNAMIC_VERSION);
                } else if (insn instanceof LdcInsnNode) {
                    Object constant = ((LdcInsnNode) insn).cst;
                    if (constant instanceof ConstantDynamic) {
                        constantDynamic = true;
                    } else if (constant instanceof Handle
                            || (constant instanceof Type && ((Type) constant).getSort() == Type.METHOD)) {
                        required = Math.max(required, MIN_INVOKE_DYNAMIC_VERSION);
                    }
                }
            }
        }
        if (constantDynamic) {
            required = Math.max(required, MIN_CONSTANT_DYNAMIC_VERSION);
        }
        return required;
    }

    /**
     * Safety net run just before writing: bumps every pool class whose
     * constants require a newer class file version (51 for invoke-dynamic
     * constants, 55 for condy). Returns the number of classes upgraded.
     */
    public static int ensureConstantCompatibleVersions(ClassPool pool, Log log) {
        int upgraded = 0;
        for (ClassNode node : pool.classes().values()) {
            int required = requiredConstantVersion(node);
            if (required <= (node.version & 0xFFFF)) {
                continue;
            }
            if (containsJsrOrRet(node) && log != null) {
                log.warn("version-safety: class %s needs class file version %d for its constants "
                        + "but contains JSR/RET; JVM may reject the result", node.name, required);
            }
            if (log != null) {
                log.debug("version-safety: %s class file version %d -> %d",
                        node.name, node.version & 0xFFFF, required);
            }
            node.version = required;
            upgraded++;
        }
        return upgraded;
    }

    /** True when any method of the class contains a JSR or RET instruction. */
    public static boolean containsJsrOrRet(ClassNode node) {
        for (MethodNode method : node.methods) {
            if (containsJsrOrRet(method)) {
                return true;
            }
        }
        return false;
    }

    /** True when the method contains a JSR or RET instruction. */
    public static boolean containsJsrOrRet(MethodNode method) {
        if (method.instructions == null) {
            return false;
        }
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.JSR || opcode == Opcodes.RET) {
                return true;
            }
        }
        return false;
    }

    public static boolean hasAnnotation(List<AnnotationNode> annotations, String desc) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (desc.equals(annotation.desc)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Reads a boolean attribute from an annotation, returning {@code null}
     * when the annotation is absent.
     */
    public static Boolean annotationBoolean(List<AnnotationNode> annotations, String desc, String key) {
        if (annotations == null) {
            return null;
        }
        for (AnnotationNode annotation : annotations) {
            if (!desc.equals(annotation.desc)) {
                continue;
            }
            if (annotation.values != null) {
                for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
                    if (key.equals(annotation.values.get(i))) {
                        Object value = annotation.values.get(i + 1);
                        return value == null ? Boolean.FALSE : Boolean.valueOf(String.valueOf(value));
                    }
                }
            }
            return Boolean.TRUE;
        }
        return null;
    }

    public static boolean hasAnnotation(ClassNode node, String desc) {
        return hasAnnotation(node.visibleAnnotations, desc) || hasAnnotation(node.invisibleAnnotations, desc);
    }

    public static boolean hasAnnotation(MethodNode node, String desc) {
        return hasAnnotation(node.visibleAnnotations, desc) || hasAnnotation(node.invisibleAnnotations, desc);
    }

    public static boolean hasAnnotation(FieldNode node, String desc) {
        return hasAnnotation(node.visibleAnnotations, desc) || hasAnnotation(node.invisibleAnnotations, desc);
    }

    /** Removes every annotation with the given descriptor. */
    public static void removeAnnotation(ClassNode node, String desc) {
        node.visibleAnnotations = remove(node.visibleAnnotations, desc);
        node.invisibleAnnotations = remove(node.invisibleAnnotations, desc);
    }

    public static void removeAnnotation(MethodNode node, String desc) {
        node.visibleAnnotations = remove(node.visibleAnnotations, desc);
        node.invisibleAnnotations = remove(node.invisibleAnnotations, desc);
    }

    public static void removeAnnotation(FieldNode node, String desc) {
        node.visibleAnnotations = remove(node.visibleAnnotations, desc);
        node.invisibleAnnotations = remove(node.invisibleAnnotations, desc);
    }

    private static List<AnnotationNode> remove(List<AnnotationNode> annotations, String desc) {
        if (annotations == null) {
            return null;
        }
        annotations.removeIf(a -> desc.equals(a.desc));
        return annotations;
    }

    /** Pushes a constant, using compact opcodes where possible. */
    public static void push(InsnList list, Object value) {
        if (value instanceof Integer) {
            pushInt(list, (Integer) value);
        } else if (value instanceof Long) {
            list.add(new LdcInsnNode(value));
        } else if (value instanceof Float) {
            list.add(new LdcInsnNode(value));
        } else if (value instanceof Double) {
            list.add(new LdcInsnNode(value));
        } else if (value instanceof String) {
            list.add(new LdcInsnNode(value));
        } else if (value == null) {
            list.add(new InsnNode(ACONST_NULL));
        } else {
            list.add(new LdcInsnNode(value));
        }
    }

    public static void pushInt(InsnList list, int value) {
        if (value >= -1 && value <= 5) {
            list.add(new InsnNode(ICONST_0 + value));
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            list.add(new IntInsnNode(BIPUSH, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            list.add(new IntInsnNode(SIPUSH, value));
        } else {
            list.add(new LdcInsnNode(value));
        }
    }

    /** Pushes the default value for a type, or nothing for {@code void}. */
    public static void pushDefault(InsnList list, Type type) {
        switch (type.getSort()) {
            case Type.VOID:
                return;
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                list.add(new InsnNode(ICONST_0));
                return;
            case Type.LONG:
                list.add(new InsnNode(LCONST_0));
                return;
            case Type.FLOAT:
                list.add(new InsnNode(FCONST_0));
                return;
            case Type.DOUBLE:
                list.add(new InsnNode(DCONST_0));
                return;
            default:
                list.add(new InsnNode(ACONST_NULL));
        }
    }

    public static int returnOpcode(Type type) {
        switch (type.getSort()) {
            case Type.VOID: return RETURN;
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT: return IRETURN;
            case Type.LONG: return LRETURN;
            case Type.FLOAT: return FRETURN;
            case Type.DOUBLE: return DRETURN;
            default: return ARETURN;
        }
    }

    public static int loadOpcode(Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT: return ILOAD;
            case Type.LONG: return LLOAD;
            case Type.FLOAT: return FLOAD;
            case Type.DOUBLE: return DLOAD;
            default: return ALOAD;
        }
    }

    public static int storeOpcode(Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT: return ISTORE;
            case Type.LONG: return LSTORE;
            case Type.FLOAT: return FSTORE;
            case Type.DOUBLE: return DSTORE;
            default: return ASTORE;
        }
    }

    /** True for instructions that are labels, line numbers or frames. */
    public static boolean isPseudo(AbstractInsnNode node) {
        return node.getOpcode() < 0;
    }

    /** Converts a descriptor to a human-readable Java type for mapping files. */
    public static String descriptorToJava(String desc) {
        Type type = Type.getType(desc);
        return typeToJava(type);
    }

    /** Converts a method descriptor to {@code returnType name(args)}. */
    public static String methodSignatureToJava(String name, String desc) {
        Type method = Type.getMethodType(desc);
        StringBuilder out = new StringBuilder();
        out.append(typeToJava(method.getReturnType())).append(' ').append(name).append('(');
        Type[] args = method.getArgumentTypes();
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append(typeToJava(args[i]));
        }
        out.append(')');
        return out.toString();
    }

    private static String typeToJava(Type type) {
        switch (type.getSort()) {
            case Type.VOID: return "void";
            case Type.BOOLEAN: return "boolean";
            case Type.BYTE: return "byte";
            case Type.CHAR: return "char";
            case Type.SHORT: return "short";
            case Type.INT: return "int";
            case Type.LONG: return "long";
            case Type.FLOAT: return "float";
            case Type.DOUBLE: return "double";
            case Type.ARRAY: return typeToJava(type.getElementType()) + repeat("[", type.getDimensions());
            case Type.OBJECT: return type.getClassName();
            default: return type.getDescriptor();
        }
    }

    private static String repeat(String value, int count) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < count; i++) {
            out.append(value);
        }
        return out.toString();
    }
}

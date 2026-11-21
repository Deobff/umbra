package io.umbra.core.pass.impl.salt;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.List;

/**
 * Builds the strict salt dispatcher class of the reference implementation.
 *
 * <p>The generated class owns two {@code Map} fields and answers a salt lookup for
 * the class that is <em>currently initialising</em>:</p>
 *
 * <ul>
 *   <li>{@code classValues}: {@code FNV1a(dottedName)} of the salted class to
 *       {@code saltValue ^ fakeValue};</li>
 *   <li>{@code initializedValues}: {@code FNV1a(callerName)} to the salt of the
 *       caller that has already run its own store, so the ordered variant can
 *       cancel a chain of initialisers.</li>
 * </ul>
 *
 * <p>Both retrievers walk {@code new Throwable().getStackTrace()[2]} to recover
 * the initialising class, so the value a class receives depends on the call
 * chain rather than on a constant in its own bytecode. Every identifier is
 * generated, so the class carries no recognisable string.</p>
 */
public final class SaltDispatcher implements Opcodes {

    private SaltDispatcher() {
    }

    /** The dispatcher class, fully populated but not yet verified or registered. */
    public static ClassNode build(List<SaltPlan.ClassSalt> salts, SaltPlan.DispatcherNames names) {
        ClassNode node = new ClassNode();
        node.version = V1_8;
        node.access = ACC_PUBLIC | ACC_SUPER;
        node.name = names.className;
        node.superName = SaltCode.OBJECT_NAME;
        node.fields.add(new FieldNode(ACC_PRIVATE | ACC_STATIC, names.classValues, SaltCode.MAP_DESC, null, null));
        node.fields.add(new FieldNode(ACC_PRIVATE | ACC_STATIC, names.initializedValues, SaltCode.MAP_DESC,
                null, null));
        node.methods.add(hasher(names));
        node.methods.add(initValues(names, salts));
        node.methods.add(retrieve(names));
        node.methods.add(retrieveOrdered(names));
        node.methods.add(clinit(names));
        return node;
    }

    /** {@code private static long hasher(String s)}: FNV-1a over the UTF-16 code units. */
    private static MethodNode hasher(SaltPlan.DispatcherNames names) {
        MethodNode method = new MethodNode(ACC_PRIVATE | ACC_STATIC, names.hasher,
                "(L" + SaltCode.STRING_NAME + ";)J", null, null);
        InsnList code = method.instructions;
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        code.add(new LdcInsnNode(Long.valueOf(SaltCode.FNV_OFFSET)));
        code.add(new VarInsnNode(LSTORE, 1));
        code.add(new InsnNode(ICONST_0));
        code.add(new VarInsnNode(ISTORE, 3));
        code.add(loop);
        code.add(new VarInsnNode(ILOAD, 3));
        code.add(new VarInsnNode(ALOAD, 0));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.STRING_NAME, "length", "()I", false));
        code.add(new JumpInsnNode(IF_ICMPGE, end));
        code.add(new VarInsnNode(LLOAD, 1));
        code.add(new VarInsnNode(ALOAD, 0));
        code.add(new VarInsnNode(ILOAD, 3));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.STRING_NAME, "charAt", "(I)C", false));
        code.add(new InsnNode(I2L));
        code.add(new InsnNode(LXOR));
        code.add(new VarInsnNode(LSTORE, 1));
        code.add(new VarInsnNode(LLOAD, 1));
        code.add(new LdcInsnNode(Long.valueOf(SaltCode.FNV_PRIME)));
        code.add(new InsnNode(LMUL));
        code.add(new VarInsnNode(LSTORE, 1));
        code.add(new IincInsnNode(3, 1));
        code.add(new JumpInsnNode(GOTO, loop));
        code.add(end);
        code.add(new VarInsnNode(LLOAD, 1));
        code.add(new InsnNode(LRETURN));
        method.maxStack = 4;
        method.maxLocals = 4;
        return method;
    }

    /**
     * {@code private static void <init>Values()}: fills {@code classValues} with
     * {@code salt ^ fake} per salted class. The dispatcher never touches the salted
     * classes' own constant pools, so it cannot trigger their initialisation.
     */
    private static MethodNode initValues(SaltPlan.DispatcherNames names, List<SaltPlan.ClassSalt> salts) {
        MethodNode method = new MethodNode(ACC_PRIVATE | ACC_STATIC, names.initValues, "()V", null, null);
        InsnList code = method.instructions;
        code.add(new FieldInsnNode(GETSTATIC, names.className, names.classValues, SaltCode.MAP_DESC));
        for (SaltPlan.ClassSalt salt : salts) {
            code.add(new InsnNode(DUP));
            code.add(new LdcInsnNode(Long.valueOf(SaltCode.fnv(salt.dottedName()))));
            code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.LONG_NAME, "valueOf",
                    "(J)L" + SaltCode.LONG_NAME + ";", false));
            io.umbra.core.util.AsmUtil.pushInt(code, salt.value ^ salt.fakeValue);
            code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.INT_NAME, "valueOf",
                    "(I)L" + SaltCode.INT_NAME + ";", false));
            code.add(new MethodInsnNode(INVOKEINTERFACE, SaltCode.MAP_NAME, "put",
                    "(L" + SaltCode.OBJECT_NAME + ";L" + SaltCode.OBJECT_NAME + ";)L" + SaltCode.OBJECT_NAME + ";",
                    true));
            code.add(new InsnNode(POP));
        }
        code.add(new InsnNode(POP));
        code.add(new InsnNode(RETURN));
        method.maxStack = 4;
        method.maxLocals = 0;
        return method;
    }

    /**
     * {@code public static int retrieve(Object, int)}: {@code classValues[name] ^ n},
     * also publishing the result under the <em>caller</em> class name so a chained
     * initialiser can cancel it again (this mirrors the reference implementation,
     * including its {@code initializedValues.put} side effect).
     */
    private static MethodNode retrieve(SaltPlan.DispatcherNames names) {
        MethodNode method = new MethodNode(ACC_PUBLIC | ACC_STATIC, names.retrieve,
                SaltCode.RETRIEVE_DESC, null, null);
        InsnList code = method.instructions;
        code.add(new FieldInsnNode(GETSTATIC, names.className, names.classValues, SaltCode.MAP_DESC));
        code.add(new VarInsnNode(ALOAD, 0));
        code.add(new TypeInsnNode(CHECKCAST, SaltCode.CLASS_NAME));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getName", "()L" + SaltCode.STRING_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKESTATIC, names.className, names.hasher,
                "(L" + SaltCode.STRING_NAME + ";)J", false));
        code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.LONG_NAME, "valueOf",
                "(J)L" + SaltCode.LONG_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKEINTERFACE, SaltCode.MAP_NAME, "get",
                "(L" + SaltCode.OBJECT_NAME + ";)L" + SaltCode.OBJECT_NAME + ";", true));
        code.add(new TypeInsnNode(CHECKCAST, SaltCode.INT_NAME));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.INT_NAME, "intValue", "()I", false));
        code.add(new VarInsnNode(ILOAD, 1));
        code.add(new InsnNode(IXOR));
        // Keep the resolved value on the stack while publishing it for chained
        // initialisers: dup; Integer.valueOf; <key>; swap; map; dup_x2; pop; put; pop
        code.add(new InsnNode(DUP));
        code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.INT_NAME, "valueOf",
                "(I)L" + SaltCode.INT_NAME + ";", false));
        code.add(new VarInsnNode(ALOAD, 0));
        code.add(new TypeInsnNode(CHECKCAST, "java/lang/Class"));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getName", "()L" + SaltCode.STRING_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKESTATIC, names.className, names.hasher,
                "(L" + SaltCode.STRING_NAME + ";)J", false));
        code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.LONG_NAME, "valueOf",
                "(J)L" + SaltCode.LONG_NAME + ";", false));
        code.add(new InsnNode(SWAP));
        code.add(new FieldInsnNode(GETSTATIC, names.className, names.initializedValues, SaltCode.MAP_DESC));
        code.add(new InsnNode(DUP_X2));
        code.add(new InsnNode(POP));
        code.add(new MethodInsnNode(INVOKEINTERFACE, SaltCode.MAP_NAME, "put",
                "(L" + SaltCode.OBJECT_NAME + ";L" + SaltCode.OBJECT_NAME + ";)L" + SaltCode.OBJECT_NAME + ";",
                true));
        code.add(new InsnNode(POP));
        code.add(new InsnNode(IRETURN));
        method.maxStack = 8;
        method.maxLocals = 2;
        return method;
    }

    /**
     * {@code public static int retrieveOrdered(Object, int)}: the reference variant
     * for a class that has a known first initialiser. When the {@code <clinit>} that
     * triggered the lookup belongs to a {@code java.*} class (frame 2), frame 7 is
     * used instead so the real initialiser is recovered.
     */
    private static MethodNode retrieveOrdered(SaltPlan.DispatcherNames names) {
        MethodNode method = new MethodNode(ACC_PUBLIC | ACC_STATIC, names.retrieveOrdered,
                SaltCode.RETRIEVE_DESC, null, null);
        InsnList code = method.instructions;
        LabelNode regular = new LabelNode();
        LabelNode last = new LabelNode();

        code.add(new TypeInsnNode(NEW, SaltCode.THROWABLE));
        code.add(new InsnNode(DUP));
        code.add(new MethodInsnNode(INVOKESPECIAL, SaltCode.THROWABLE, "<init>", "()V", false));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.THROWABLE, "getStackTrace",
                "()[L" + SaltCode.STACK_ELEMENT + ";", false));
        code.add(new VarInsnNode(ASTORE, 2));

        code.add(new VarInsnNode(ALOAD, 2));
        code.add(new InsnNode(ICONST_2));
        code.add(new InsnNode(AALOAD));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.STACK_ELEMENT, "getClassName",
                "()L" + SaltCode.STRING_NAME + ";", false));
        code.add(new LdcInsnNode("java"));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.STRING_NAME, "startsWith",
                "(L" + SaltCode.STRING_NAME + ";)Z", false));
        code.add(new JumpInsnNode(IFEQ, regular));

        code.add(new VarInsnNode(ALOAD, 2));
        code.add(new IntInsnNode(BIPUSH, 7));
        code.add(new InsnNode(AALOAD));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.STACK_ELEMENT, "getClassName",
                "()L" + SaltCode.STRING_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKESTATIC, names.className, names.hasher,
                "(L" + SaltCode.STRING_NAME + ";)J", false));
        code.add(new VarInsnNode(LSTORE, 3));
        code.add(new JumpInsnNode(GOTO, last));

        code.add(regular);
        code.add(new VarInsnNode(ALOAD, 2));
        code.add(new InsnNode(ICONST_2));
        code.add(new InsnNode(AALOAD));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.STACK_ELEMENT, "getClassName",
                "()L" + SaltCode.STRING_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKESTATIC, names.className, names.hasher,
                "(L" + SaltCode.STRING_NAME + ";)J", false));
        code.add(new VarInsnNode(LSTORE, 3));

        code.add(last);
        code.add(new FieldInsnNode(GETSTATIC, names.className, names.classValues, SaltCode.MAP_DESC));
        code.add(new VarInsnNode(ALOAD, 0));
        code.add(new TypeInsnNode(CHECKCAST, "java/lang/Class"));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getName", "()L" + SaltCode.STRING_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKESTATIC, names.className, names.hasher,
                "(L" + SaltCode.STRING_NAME + ";)J", false));
        code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.LONG_NAME, "valueOf",
                "(J)L" + SaltCode.LONG_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKEINTERFACE, SaltCode.MAP_NAME, "get",
                "(L" + SaltCode.OBJECT_NAME + ";)L" + SaltCode.OBJECT_NAME + ";", true));
        code.add(new TypeInsnNode(CHECKCAST, SaltCode.INT_NAME));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.INT_NAME, "intValue", "()I", false));
        code.add(new VarInsnNode(ILOAD, 1));
        code.add(new InsnNode(IXOR));
        code.add(new FieldInsnNode(GETSTATIC, names.className, names.initializedValues, SaltCode.MAP_DESC));
        code.add(new VarInsnNode(LLOAD, 3));
        code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.LONG_NAME, "valueOf",
                "(J)L" + SaltCode.LONG_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKEINTERFACE, SaltCode.MAP_NAME, "get",
                "(L" + SaltCode.OBJECT_NAME + ";)L" + SaltCode.OBJECT_NAME + ";", true));
        code.add(new TypeInsnNode(CHECKCAST, SaltCode.INT_NAME));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, SaltCode.INT_NAME, "intValue", "()I", false));
        code.add(new InsnNode(IXOR));
        code.add(new VarInsnNode(ISTORE, 5));

        code.add(new FieldInsnNode(GETSTATIC, names.className, names.initializedValues, SaltCode.MAP_DESC));
        code.add(new VarInsnNode(ALOAD, 0));
        code.add(new TypeInsnNode(CHECKCAST, "java/lang/Class"));
        code.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getName", "()L" + SaltCode.STRING_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKESTATIC, names.className, names.hasher,
                "(L" + SaltCode.STRING_NAME + ";)J", false));
        code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.LONG_NAME, "valueOf",
                "(J)L" + SaltCode.LONG_NAME + ";", false));
        code.add(new VarInsnNode(ILOAD, 5));
        code.add(new MethodInsnNode(INVOKESTATIC, SaltCode.INT_NAME, "valueOf",
                "(I)L" + SaltCode.INT_NAME + ";", false));
        code.add(new MethodInsnNode(INVOKEINTERFACE, SaltCode.MAP_NAME, "put",
                "(L" + SaltCode.OBJECT_NAME + ";L" + SaltCode.OBJECT_NAME + ";)L" + SaltCode.OBJECT_NAME + ";",
                true));
        code.add(new InsnNode(POP));

        code.add(new VarInsnNode(ILOAD, 5));
        code.add(new InsnNode(IRETURN));
        method.maxStack = 8;
        method.maxLocals = 6;
        return method;
    }

    /** {@code <clinit>}: publish both maps, then fill the class-value map. */
    private static MethodNode clinit(SaltPlan.DispatcherNames names) {
        MethodNode method = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList code = method.instructions;
        code.add(new TypeInsnNode(NEW, SaltCode.HASH_MAP));
        code.add(new InsnNode(DUP));
        code.add(new MethodInsnNode(INVOKESPECIAL, SaltCode.HASH_MAP, "<init>", "()V", false));
        code.add(new FieldInsnNode(PUTSTATIC, names.className, names.classValues, SaltCode.MAP_DESC));
        code.add(new TypeInsnNode(NEW, SaltCode.HASH_MAP));
        code.add(new InsnNode(DUP));
        code.add(new MethodInsnNode(INVOKESPECIAL, SaltCode.HASH_MAP, "<init>", "()V", false));
        code.add(new FieldInsnNode(PUTSTATIC, names.className, names.initializedValues, SaltCode.MAP_DESC));
        code.add(new MethodInsnNode(INVOKESTATIC, names.className, names.initValues, "()V", false));
        code.add(new InsnNode(RETURN));
        method.maxStack = 3;
        method.maxLocals = 0;
        return method;
    }
}

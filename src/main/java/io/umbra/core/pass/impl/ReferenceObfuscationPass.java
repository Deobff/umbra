package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.model.ClassInfo;
import io.umbra.core.model.Hierarchy;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.Cipher;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.Map;

/**
 * Hides member references behind {@code invokedynamic}.
 *
 * <p>Supported modes: static calls, virtual/interface calls, and field
 * get/put. Owner and member names are encrypted bootstrap arguments; the
 * target is resolved lazily through {@code MethodHandles.Lookup}. Only
 * accessible members of program classes are rewritten.</p>
 */
public final class ReferenceObfuscationPass implements Pass {

    private static final String BOOTSTRAP_DESC =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;Ljava/lang/String;JLjava/lang/String;J)"
                    + "Ljava/lang/invoke/CallSite;";

    @Override
    public String name() {
        return "reference-obfuscation";
    }

    @Override
    public int order() {
        return 65;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().referenceObfuscation().enabled();
    }

    @Override
    public void run(PassContext context) {
        UmbraConfigAccess options = new UmbraConfigAccess(context);
        String helper = context.runtime().ensureIndyBootstrap(context.classes(), context.config().seed());
        int statics = 0;
        int virtuals = 0;
        int fields = 0;
        int constructors = 0;
        int classes = 0;
        int versionUpgraded = 0;
        int indySkipped = 0;
        Map<String, ClassNode> helpers = new java.util.LinkedHashMap<String, ClassNode>();
        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (!context.rules().transformClass(node)) {
                continue;
            }
            // invokedynamic needs class file version >= 51 (constant tags 15/18).
            // Legacy classes are upgraded unless they still use JSR/RET, which is
            // illegal in version 51+ class files; those keep direct references.
            boolean rewriteIndy = true;
            if ((node.version & 0xFFFF) < Opcodes.V1_7) {
                if (AsmUtil.containsJsrOrRet(node)) {
                    rewriteIndy = false;
                    indySkipped++;
                    context.log().debug("reference-obfuscation: skipping invokedynamic rewriting for legacy class %s "
                            + "(JSR/RET present, class file version %d)", node.name, node.version & 0xFFFF);
                } else {
                    node.version = Opcodes.V1_7;
                    versionUpgraded++;
                }
            }
            int before = statics + virtuals + fields + constructors;
            if (options.constructors()) {
                constructors += rewriteConstructors(context, node, helpers);
            }
            if (rewriteIndy) {
                for (MethodNode method : node.methods) {
                    if (method.instructions == null) {
                        continue;
                    }
                    for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
                        AbstractInsnNode next = insn.getNext();
                        if (insn instanceof MethodInsnNode) {
                            MethodInsnNode call = (MethodInsnNode) insn;
                            if (call.getOpcode() == Opcodes.INVOKESTATIC && options.staticCalls()) {
                                if (rewriteStatic(context, node, method, call, helper)) {
                                    statics++;
                                }
                            } else if ((call.getOpcode() == Opcodes.INVOKEVIRTUAL
                                    || call.getOpcode() == Opcodes.INVOKEINTERFACE) && options.virtualCalls()) {
                                if (rewriteVirtual(context, node, method, call, helper)) {
                                    virtuals++;
                                }
                            }
                        } else if (insn instanceof FieldInsnNode && options.fields()) {
                            if (rewriteField(context, node, method, (FieldInsnNode) insn, helper)) {
                                fields++;
                            }
                        }
                        insn = next;
                    }
                }
            }
            if (statics + virtuals + fields + constructors > before) {
                classes++;
            }
        }
        for (ClassNode helperClass : helpers.values()) {
            context.classes().addGenerated(helperClass);
        }
        context.stats().add("references.static", statics);
        context.stats().add("references.virtual", virtuals);
        context.stats().add("references.fields", fields);
        context.stats().add("references.constructors", constructors);
        context.stats().add("references.indy", statics + virtuals + fields);
        context.stats().add("references.classes", classes);
        context.stats().add("references.versionUpgraded", versionUpgraded);
        context.stats().add("references.skippedLegacyClasses", indySkipped);
        context.log().info("reference-obfuscation: %d static, %d virtual, %d field, %d constructor references across %d classes",
                statics, virtuals, fields, constructors, classes);
        if (versionUpgraded > 0 || indySkipped > 0) {
            context.log().info("reference-obfuscation: upgraded %d legacy class(es) to class file version 51, "
                    + "skipped invokedynamic in %d legacy class(es) with JSR/RET", versionUpgraded, indySkipped);
        }
    }

    private static int rewriteConstructors(PassContext context, ClassNode caller,
                                           Map<String, ClassNode> helpers) {
        int count = 0;
        for (MethodNode method : caller.methods) {
            if (method.instructions == null) {
                continue;
            }
            AbstractInsnNode[] insns = method.instructions.toArray();
            for (int i = 0; i < insns.length; i++) {
                AbstractInsnNode insn = insns[i];
                if (!(insn instanceof TypeInsnNode) || insn.getOpcode() != Opcodes.NEW) {
                    continue;
                }
                String owner = ((TypeInsnNode) insn).desc;
                ClassInfo info = context.hierarchy().resolve(owner);
                if (info == null || !info.isInput()) {
                    continue;
                }
                int dupIndex = nextReal(insns, i + 1);
                if (dupIndex < 0 || insns[dupIndex].getOpcode() != Opcodes.DUP) {
                    continue;
                }
                int constructorIndex = -1;
                boolean invalid = false;
                int scanned = 0;
                for (int k = dupIndex + 1; k < insns.length && scanned++ < 256; k++) {
                    AbstractInsnNode current = insns[k];
                    int opcode = current.getOpcode();
                    if (current instanceof LabelNode || current instanceof JumpInsnNode
                            || opcode == Opcodes.TABLESWITCH || opcode == Opcodes.LOOKUPSWITCH
                            || (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN)
                            || opcode == Opcodes.ATHROW
                            || (current instanceof TypeInsnNode
                            && (opcode == Opcodes.NEW || opcode == Opcodes.ANEWARRAY))) {
                        invalid = true;
                        break;
                    }
                    if (current instanceof VarInsnNode
                            && opcode >= Opcodes.ISTORE && opcode <= Opcodes.ASTORE) {
                        invalid = true;
                        break;
                    }
                    if (current instanceof InsnNode
                            && (opcode == Opcodes.DUP || opcode == Opcodes.DUP_X1
                            || opcode == Opcodes.DUP_X2 || opcode == Opcodes.DUP2
                            || opcode == Opcodes.DUP2_X1 || opcode == Opcodes.DUP2_X2
                            || opcode == Opcodes.SWAP || opcode == Opcodes.POP
                            || opcode == Opcodes.POP2)) {
                        invalid = true;
                        break;
                    }
                    if (current instanceof MethodInsnNode) {
                        MethodInsnNode call = (MethodInsnNode) current;
                        if (call.getOpcode() == Opcodes.INVOKESPECIAL
                                && "<init>".equals(call.name) && owner.equals(call.owner)) {
                            constructorIndex = k;
                            break;
                        }
                    }
                }
                if (invalid || constructorIndex < 0) {
                    continue;
                }
                MethodInsnNode constructor = (MethodInsnNode) insns[constructorIndex];
                Integer access = info.methodAccess("<init>", constructor.desc);
                if (access == null || (access.intValue() & Opcodes.ACC_PRIVATE) != 0) {
                    continue;
                }

                String packageName = packageOf(owner);
                String helperName;
                do {
                    helperName = (packageName.isEmpty() ? "" : packageName + "/")
                            + "Z" + Integer.toHexString(context.random().nextInt());
                } while (context.classes().getClass(helperName) != null
                        || helpers.containsKey(helperName));
                ClassNode helper = helper(helperName, packageName);
                helpers.put(helperName, helper);

                String factoryName = "create";
                String argumentsDesc = constructor.desc.substring(0,
                        constructor.desc.indexOf(')') + 1);
                String factoryDesc = argumentsDesc + "L" + owner + ";";
                MethodNode factory = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                        factoryName, factoryDesc, null, null);
                factory.instructions.add(new TypeInsnNode(Opcodes.NEW, owner));
                factory.instructions.add(new InsnNode(Opcodes.DUP));
                int slot = 0;
                for (Type argument : Type.getArgumentTypes(constructor.desc)) {
                    factory.instructions.add(new VarInsnNode(AsmUtil.loadOpcode(argument), slot));
                    slot += argument.getSize();
                }
                factory.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                        owner, "<init>", constructor.desc, false));
                factory.instructions.add(new InsnNode(Opcodes.ARETURN));
                factory.maxLocals = slot;
                factory.maxStack = slot + 2;
                helper.methods.add(factory);

                method.instructions.remove(insn);
                method.instructions.remove(insns[dupIndex]);
                method.instructions.set(constructor, new MethodInsnNode(Opcodes.INVOKESTATIC,
                        helperName, factoryName, factoryDesc, false));
                count++;
            }
        }
        return count;
    }

    private static int nextReal(AbstractInsnNode[] insns, int from) {
        for (int i = from; i < insns.length; i++) {
            if (insns[i].getOpcode() >= 0) {
                return i;
            }
        }
        return -1;
    }

    private static ClassNode helper(String name, String packageName) {
        ClassNode helper = new ClassNode();
        helper.version = Opcodes.V1_8;
        helper.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER;
        helper.name = name;
        helper.superName = "java/lang/Object";
        helper.sourceFile = "UmbraHelper.java";
        MethodNode constructor = new MethodNode(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
        constructor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        constructor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        constructor.instructions.add(new InsnNode(Opcodes.RETURN));
        constructor.maxLocals = 1;
        constructor.maxStack = 1;
        helper.methods.add(constructor);
        return helper;
    }

    private static boolean rewriteStatic(PassContext context, ClassNode caller, MethodNode method,
                                         MethodInsnNode call, String helper) {
        if (call.name.startsWith("<")) {
            return false;
        }
        ClassInfo declaring = context.hierarchy().resolveMethod(call.owner, call.name, call.desc);
        if (declaring == null || !declaring.isInput()) {
            return false;
        }
        Integer access = declaring.methodAccess(call.name, call.desc);
        if (access == null || (access.intValue() & Opcodes.ACC_STATIC) == 0) {
            return false;
        }
        if (!accessible(context.hierarchy(), caller, declaring, access.intValue())) {
            return false;
        }
        InvokeDynamicInsnNode indy = indy(context, call.desc, helper, "bootstrap",
                declaring.name(), call.name);
        method.instructions.set(call, indy);
        return true;
    }

    private static boolean rewriteVirtual(PassContext context, ClassNode caller, MethodNode method,
                                          MethodInsnNode call, String helper) {
        if (call.name.startsWith("<")) {
            return false;
        }
        ClassInfo declaring = context.hierarchy().resolveMethod(call.owner, call.name, call.desc);
        if (declaring == null || !declaring.isInput()) {
            return false;
        }
        Integer access = declaring.methodAccess(call.name, call.desc);
        if (access == null) {
            return false;
        }
        int flags = access.intValue();
        if ((flags & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0) {
            return false;
        }
        if (!accessible(context.hierarchy(), caller, declaring, flags)) {
            return false;
        }
        String receiver = receiverDescriptor(call.owner);
        String newDesc = "(" + receiver + call.desc.substring(1);
        InvokeDynamicInsnNode indy = indy(context, newDesc, helper, "bootstrapVirtual",
                declaring.name(), call.name);
        method.instructions.set(call, indy);
        return true;
    }

    private static boolean rewriteField(PassContext context, ClassNode caller, MethodNode method,
                                        FieldInsnNode access, String helper) {
        ClassInfo declaring = context.hierarchy().resolveField(access.owner, access.name, access.desc);
        if (declaring == null || !declaring.isInput()) {
            return false;
        }
        Integer flagsValue = declaring.fieldAccess(access.name, access.desc);
        if (flagsValue == null) {
            return false;
        }
        int flags = flagsValue.intValue();
        boolean isStatic = access.getOpcode() == Opcodes.GETSTATIC || access.getOpcode() == Opcodes.PUTSTATIC;
        if (((flags & Opcodes.ACC_STATIC) != 0) != isStatic) {
            return false;
        }
        boolean isWrite = access.getOpcode() == Opcodes.PUTFIELD || access.getOpcode() == Opcodes.PUTSTATIC;
        if (isWrite && (flags & Opcodes.ACC_FINAL) != 0) {
            return false;
        }
        if (!accessibleField(context.hierarchy(), caller, declaring, flags)) {
            return false;
        }
        String ownerDesc = receiverDescriptor(access.owner);
        String desc;
        String bootstrap;
        switch (access.getOpcode()) {
            case Opcodes.GETSTATIC:
                desc = "()" + access.desc;
                bootstrap = "bootstrapFieldGetStatic";
                break;
            case Opcodes.GETFIELD:
                desc = "(" + ownerDesc + ")" + access.desc;
                bootstrap = "bootstrapFieldGet";
                break;
            case Opcodes.PUTSTATIC:
                desc = "(" + access.desc + ")V";
                bootstrap = "bootstrapFieldSetStatic";
                break;
            default:
                desc = "(" + ownerDesc + access.desc + ")V";
                bootstrap = "bootstrapFieldSet";
                break;
        }
        InvokeDynamicInsnNode indy = indy(context, desc, helper, bootstrap,
                declaring.name(), access.name);
        method.instructions.set(access, indy);
        return true;
    }

    private static InvokeDynamicInsnNode indy(PassContext context, String desc, String helper,
                                              String bootstrapName, String owner, String member) {
        long ownerKey = context.random().nextLong();
        long memberKey = context.random().nextLong();
        if (ownerKey == 0L) {
            ownerKey = 0x5A17L;
        }
        if (memberKey == 0L) {
            memberKey = 0x2F2FL;
        }
        String encryptedOwner = Cipher.encrypt(owner, ownerKey);
        String encryptedMember = Cipher.encrypt(member, memberKey);
        String indyName = "z$" + Integer.toHexString(context.random().nextInt());
        Handle bootstrap = new Handle(Opcodes.H_INVOKESTATIC, helper, bootstrapName,
                BOOTSTRAP_DESC, false);
        return new InvokeDynamicInsnNode(indyName, desc, bootstrap,
                encryptedOwner, Long.valueOf(ownerKey), encryptedMember, Long.valueOf(memberKey));
    }

    private static String receiverDescriptor(String owner) {
        if (owner.startsWith("[")) {
            return Type.getType(owner).getDescriptor();
        }
        return Type.getObjectType(owner).getDescriptor();
    }

    private static boolean accessible(Hierarchy hierarchy, ClassNode caller, ClassInfo declaring, int access) {
        if (!classAccessible(caller, declaring)) {
            return false;
        }
        if ((access & Opcodes.ACC_PUBLIC) != 0) {
            return true;
        }
        if (caller.name.equals(declaring.name())) {
            return true;
        }
        if ((access & Opcodes.ACC_PROTECTED) != 0
                && hierarchy.isAssignableFrom(declaring.name(), caller.name)) {
            return true;
        }
        return samePackage(caller, declaring) && (access & Opcodes.ACC_PRIVATE) == 0;
    }

    private static boolean accessibleField(Hierarchy hierarchy, ClassNode caller, ClassInfo declaring, int access) {
        return accessible(hierarchy, caller, declaring, access);
    }

    private static boolean classAccessible(ClassNode caller, ClassInfo declaring) {
        return (declaring.access() & Opcodes.ACC_PUBLIC) != 0 || samePackage(caller, declaring);
    }

    private static boolean samePackage(ClassNode caller, ClassInfo declaring) {
        return packageOf(caller.name).equals(packageOf(declaring.name()));
    }

    private static String packageOf(String name) {
        int slash = name.lastIndexOf('/');
        return slash < 0 ? "" : name.substring(0, slash);
    }

    /** Small adapter to keep the pass readable. */
    private static final class UmbraConfigAccess {
        private final PassContext context;

        UmbraConfigAccess(PassContext context) {
            this.context = context;
        }

        boolean staticCalls() {
            return context.config().referenceObfuscation().staticCalls();
        }

        boolean virtualCalls() {
            return context.config().referenceObfuscation().virtualCalls();
        }

        boolean fields() {
            return context.config().referenceObfuscation().fields();
        }

        boolean constructors() {
            return context.config().referenceObfuscation().constructors();
        }
    }
}

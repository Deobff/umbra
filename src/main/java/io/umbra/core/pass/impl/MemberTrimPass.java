package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Removes unreferenced private members.
 *
 * <p>This is a deliberately conservative subset: only private methods and
 * fields are considered, annotated members are kept, and the pass is disabled
 * by default. Three iterations handle chains of unused private helpers.</p>
 */
public final class MemberTrimPass implements Pass {

    @Override
    public String name() {
        return "member-trim";
    }

    @Override
    public int order() {
        return 15;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().trim().enabled();
    }

    @Override
    public void run(PassContext context) {
        Set<String> methodRefs = new LinkedHashSet<String>();
        Set<String> fieldRefs = new LinkedHashSet<String>();
        scanReferences(context, methodRefs, fieldRefs);

        int removedMethods = 0;
        int removedFields = 0;
        for (int round = 0; round < 3; round++) {
            int methodsThisRound = 0;
            int fieldsThisRound = 0;
            for (ClassNode node : context.classes().classes().values()) {
                if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                    continue;
                }
                    if (context.rules().skipBodyTransform(node.name)) {
                        continue;
                    }
                if (!context.rules().transformClass(node)) {
                    continue;
                }
                if (context.config().trim().removeUnusedPrivateMethods()) {
                    for (Iterator<MethodNode> it = node.methods.iterator(); it.hasNext(); ) {
                        MethodNode method = it.next();
                        if (!removableMethod(context, node, method, methodRefs)) {
                            continue;
                        }
                        it.remove();
                        methodsThisRound++;
                    }
                }
                if (context.config().trim().removeUnusedPrivateFields()) {
                    for (Iterator<FieldNode> it = node.fields.iterator(); it.hasNext(); ) {
                        FieldNode field = it.next();
                        if (!removableField(context, node, field, fieldRefs)) {
                            continue;
                        }
                        it.remove();
                        fieldsThisRound++;
                    }
                }
            }
            removedMethods += methodsThisRound;
            removedFields += fieldsThisRound;
            if (methodsThisRound == 0 && fieldsThisRound == 0) {
                break;
            }
        }
        context.stats().add("trim.methods", removedMethods);
        context.stats().add("trim.fields", removedFields);
        context.log().info("member-trim: removed %d private methods and %d private fields",
                removedMethods, removedFields);
    }

    private static boolean removableMethod(PassContext context, ClassNode owner, MethodNode method,
                                           Set<String> refs) {
        if ((method.access & Opcodes.ACC_PRIVATE) == 0) {
            return false;
        }
        if ((method.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) {
            return false;
        }
        if (method.name.startsWith("<") || "main".equals(method.name)) {
            return false;
        }
        if (context.rules().keepMethod(owner.name, method)) {
            return false;
        }
        if (method.visibleAnnotations != null || method.invisibleAnnotations != null
                || method.visibleParameterAnnotations != null || method.invisibleParameterAnnotations != null) {
            return false;
        }
        return !refs.contains(owner.name + "#" + method.name + "#" + method.desc);
    }

    private static boolean removableField(PassContext context, ClassNode owner, FieldNode field,
                                          Set<String> refs) {
        if ((field.access & Opcodes.ACC_PRIVATE) == 0) {
            return false;
        }
        if ("serialVersionUID".equals(field.name)) {
            return false;
        }
        if (context.rules().keepField(owner.name, field)) {
            return false;
        }
        if (field.visibleAnnotations != null || field.invisibleAnnotations != null) {
            return false;
        }
        return !refs.contains(owner.name + "#" + field.name + ":" + field.desc);
    }

    private static void scanReferences(PassContext context, Set<String> methodRefs, Set<String> fieldRefs) {
        for (ClassNode node : context.classes().classes().values()) {
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode call = (MethodInsnNode) insn;
                        methodRefs.add(call.owner + "#" + call.name + "#" + call.desc);
                    } else if (insn instanceof FieldInsnNode) {
                        FieldInsnNode access = (FieldInsnNode) insn;
                        fieldRefs.add(access.owner + "#" + access.name + ":" + access.desc);
                    } else if (insn instanceof InvokeDynamicInsnNode) {
                        InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                        addHandle(indy.bsm, methodRefs, fieldRefs);
                        for (Object arg : indy.bsmArgs) {
                            if (arg instanceof Handle) {
                                addHandle((Handle) arg, methodRefs, fieldRefs);
                            }
                        }
                    } else if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof Handle) {
                        addHandle((Handle) ((LdcInsnNode) insn).cst, methodRefs, fieldRefs);
                    }
                }
            }
        }
    }

    private static void addHandle(Handle handle, Set<String> methodRefs, Set<String> fieldRefs) {
        if (handle == null) {
            return;
        }
        switch (handle.getTag()) {
            case Opcodes.H_GETFIELD:
            case Opcodes.H_GETSTATIC:
            case Opcodes.H_PUTFIELD:
            case Opcodes.H_PUTSTATIC:
                fieldRefs.add(handle.getOwner() + "#" + handle.getName() + ":" + handle.getDesc());
                break;
            default:
                methodRefs.add(handle.getOwner() + "#" + handle.getName() + "#" + handle.getDesc());
        }
    }
}

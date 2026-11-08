package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.KeyRootMask;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.pass.impl.flow.RuntimeTable;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Exception-flow obfuscation.
 *
 * <p>Selected methods are wrapped in synthetic catch-all handlers that rethrow
 * the exact same {@link Throwable}, split into several nested registration
 * ranges. Appended entries always come <em>after</em> the original exception
 * table, so existing catch / finally handlers keep their precedence and the
 * observable behaviour (same exception instance, same stack trace) is
 * unchanged. Additional never-executed throw paths and one fake handler entry
 * over a non-throwing {@code NOP} region create bogus control-flow that a
 * decompiler has to reason about.</p>
 *
 * <p>Levels ({@code exception.level}, default {@code 2}):</p>
 * <ul>
 *   <li>1 — one whole-body catch-all + one dead throw path;</li>
 *   <li>2 — 3 body ranges with catch-all guards + two dead throw paths;</li>
 *   <li>3 — 5 body ranges, opaque guard around every rethrow, three dead throw
 *       paths and a fake handler entry.</li>
 * </ul>
 *
 * <p>Rethrow handlers are verifier-safe by construction: they only touch their
 * own local, never read method locals whose merged type may be {@code top},
 * and never introduce a new throwing instruction inside a protected range.</p>
 */
public final class ExceptionObfuscationPass implements Pass {

    @Override
    public String name() {
        return "exception-obfuscation";
    }

    @Override
    public int order() {
        return 95;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().exceptionObfuscation().enabled();
    }

    @Override
    public void run(PassContext context) {
        int level = Math.max(1, Math.min(3, context.config().optionInt("exception.level", 2)));
        int methods = 0;
        int handlers = 0;
        int fakeThrows = 0;
        int fakeHandlers = 0;
        int runtimeCarriers = 0;
        int runtimeTables = 0;
        int skipped = 0;
        int max = context.config().flow().maxInstructions();
        int pairBudget = Math.max(2, context.config().optionInt("exceptions.tablePairs", 16));
        KeyRootMask tableMask = KeyRootMask.create(context, true);
        String tableMode = tableMask == null ? "static" : "native";
        MethodGate gate = new MethodGate(context);
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
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                    || "module-info".equals(node.name)) {
                continue;
            }
            List<MethodNode> savedMethods = new ArrayList<MethodNode>();
            for (MethodNode method : node.methods) {
                savedMethods.add(MethodGate.copy(method));
            }
            List<FieldNode> savedFields = new ArrayList<FieldNode>(node.fields);

            RuntimeTable table = RuntimeTable.create(context, node, pairBudget, tableMask);
            RuntimeTable.Pair carrierMask = table.pair(nonZero(context.random().nextInt()));
            int classMethods = 0;
            int classHandlers = 0;
            int classThrows = 0;
            int classFakeHandlers = 0;
            int classCarriers = 0;
            try {
                for (MethodNode method : node.methods) {
                    if (!eligible(context, method, max)) {
                        continue;
                    }
                    try {
                        MethodNode work = MethodGate.copy(method);
                        int[] result = wrap(context, work, level, table, carrierMask);
                        if (!gate.verify(node, work)) {
                            skipped++;
                            context.log().debug("exception-obfuscation: verification rejected %s.%s",
                                    node.name, method.name);
                            continue;
                        }
                        MethodGate.commit(method, work);
                        classMethods++;
                        classHandlers += result[0];
                        classThrows += result[1];
                        classFakeHandlers += result[2];
                        classCarriers += result[3];
                    } catch (RuntimeException e) {
                        skipped++;
                        context.log().debug("exception-obfuscation: skipped %s.%s: %s",
                                node.name, method.name, e.toString());
                    }
                }
                if (classMethods > 0) {
                    if (!table.isEmpty()) {
                        table.materialize(node);
                        runtimeTables += table.chunkCount();
                    }
                    if (!gate.writes(node)) {
                        throw new IllegalStateException("class does not serialize");
                    }
                }
            } catch (RuntimeException e) {
                node.methods = new ArrayList<MethodNode>(savedMethods);
                node.fields = new ArrayList<FieldNode>(savedFields);
                skipped += classMethods;
                context.log().debug("exception-obfuscation: rolled back class %s: %s",
                        node.name, e.toString());
                classMethods = 0;
                classHandlers = 0;
                classThrows = 0;
                classFakeHandlers = 0;
                classCarriers = 0;
            }
            methods += classMethods;
            handlers += classHandlers;
            fakeThrows += classThrows;
            fakeHandlers += classFakeHandlers;
            runtimeCarriers += classCarriers;
        }
        context.stats().add("exceptions.wrapped", methods);
        context.stats().add("exceptions.handlers", handlers);
        context.stats().add("exceptions.fakeThrows", fakeThrows);
        context.stats().add("exceptions.fakeHandlers", fakeHandlers);
        context.stats().add("exceptions.skipped", skipped);
        context.stats().add("exceptions.runtimeCarriers", runtimeCarriers);
        context.stats().add("exceptions.runtimeTables", runtimeTables);
        context.stats().text("exceptions.tableMode", tableMode);
        context.log().info("exception-obfuscation[level=%d]: wrapped %d methods, %d synthetic handlers, "
                        + "%d dead throw paths, %d fake handler entries, %d table-keyed carriers "
                        + "(table=%s, %d verification skips)",
                level, methods, handlers, fakeThrows, fakeHandlers, runtimeCarriers, tableMode,
                skipped);
    }

    private static boolean eligible(PassContext context, MethodNode method, int max) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() == 0
                || method.instructions.size() > max) {
            return false;
        }
        if (AsmUtil.containsJsrOrRet(method)) {
            return false;
        }
        return !context.rules().hasKeepAnnotation(method);
    }

    private static int[] wrap(PassContext context, MethodNode method, int level,
                              RuntimeTable table, RuntimeTable.Pair carrierMask) {
        int rangeCount = level == 1 ? 1 : (level == 2 ? 3 : 5);
        int deadThrowPaths = level;

        List<AbstractInsnNode> sites = boundarySites(method, rangeCount);
        int next = nextFreeLocal(method);
        int carrier = next++;
        int throwableLocal = next++;
        method.maxLocals = Math.max(method.maxLocals, next);

        InsnList prologue = new InsnList();
        boolean tableKeyed = emitCarrierInit(context, prologue, carrier, table, carrierMask);
        for (int i = 0; i < deadThrowPaths; i++) {
            emitDeadThrowPath(context, prologue, carrier);
        }
        LabelNode fakeStart = null;
        LabelNode fakeEnd = null;
        if (level >= 3) {
            fakeStart = new LabelNode();
            fakeEnd = new LabelNode();
            prologue.add(fakeStart);
            prologue.add(new InsnNode(Opcodes.NOP));
            prologue.add(fakeEnd);
        }
        LabelNode start = new LabelNode();
        prologue.add(start);
        method.instructions.insert(prologue);

        LabelNode end = new LabelNode();
        method.instructions.add(end);

        if (method.tryCatchBlocks == null) {
            method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        }

        List<LabelNode> boundaries = new ArrayList<LabelNode>();
        boundaries.add(start);
        for (AbstractInsnNode site : sites) {
            LabelNode boundary = new LabelNode();
            method.instructions.insertBefore(site, boundary);
            boundaries.add(boundary);
        }
        boundaries.add(end);

        int handlerCount = 0;
        List<int[]> ranges = new ArrayList<int[]>();
        for (int i = 0; i + 1 < boundaries.size(); i++) {
            ranges.add(new int[] {i, i + 1});
        }
        List<LabelNode> handlerLabels = new ArrayList<LabelNode>();
        for (int i = 0; i < ranges.size(); i++) {
            LabelNode handler = new LabelNode();
            handlerLabels.add(handler);
            int[] range = ranges.get(i);
            method.tryCatchBlocks.add(new TryCatchBlockNode(
                    boundaries.get(range[0]), boundaries.get(range[1]), handler, null));
            handlerCount++;
        }
        if (fakeStart != null && fakeEnd != null) {
            LabelNode fakeHandler = new LabelNode();
            handlerLabels.add(fakeHandler);
            method.tryCatchBlocks.add(new TryCatchBlockNode(fakeStart, fakeEnd, fakeHandler, null));
            handlerCount++;
        }

        for (int i = 0; i < handlerLabels.size(); i++) {
            boolean fake = i == handlerLabels.size() - 1 && level >= 3;
            method.instructions.add(handlerLabels.get(i));
            if (fake) {

                method.instructions.add(new InsnNode(Opcodes.ATHROW));
                continue;
            }
            method.instructions.add(new VarInsnNode(Opcodes.ASTORE, throwableLocal));
            if (level >= 2) {
                emitGuard(context, method.instructions, carrier, throwableLocal, level);
            }
            method.instructions.add(new VarInsnNode(Opcodes.ALOAD, throwableLocal));
            method.instructions.add(new InsnNode(Opcodes.ATHROW));
        }
        method.maxStack = Math.max(method.maxStack, 4);
        return new int[] {handlerCount, deadThrowPaths, level >= 3 ? 1 : 0, tableKeyed ? 1 : 0};
    }

    private static boolean emitCarrierInit(PassContext context, InsnList out, int carrier,
                                           RuntimeTable table, RuntimeTable.Pair carrierMask) {
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "nanoTime", "()J", false));
        out.add(new InsnNode(Opcodes.L2I));
        if (carrierMask != null) {
            table.emitInt(out, carrierMask);
            out.add(new InsnNode(Opcodes.IXOR));
            out.add(new VarInsnNode(Opcodes.ISTORE, carrier));
            return true;
        }
        int seed = context.random().nextInt();
        if (seed == 0) {
            seed = 0x7E37;
        }
        AsmUtil.pushInt(out, seed);
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, carrier));
        return false;
    }

    private static void emitDeadThrowPath(PassContext context, InsnList out, int carrier) {
        LabelNode after = new LabelNode();
        emitIntervalAlwaysTrue(out, carrier, after);
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new LdcInsnNode(Integer.valueOf(context.random().nextInt())));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException",
                "<init>", "(I)V", false));
        out.add(new InsnNode(Opcodes.ATHROW));
        out.add(after);
    }

    private static void emitIntervalAlwaysTrue(InsnList out, int carrier, LabelNode target) {
        out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
        AsmUtil.pushInt(out, 0x7FFFFFFF);
        out.add(new InsnNode(Opcodes.IAND));
        out.add(new InsnNode(Opcodes.DUP));
        AsmUtil.pushInt(out, 8);
        out.add(new InsnNode(Opcodes.IOR));
        out.add(new InsnNode(Opcodes.SWAP));
        AsmUtil.pushInt(out, 7);
        out.add(new InsnNode(Opcodes.IAND));
        out.add(new JumpInsnNode(Opcodes.IF_ICMPGT, target));
    }

    private static void emitGuard(PassContext context, InsnList out, int carrier,
                                  int throwableLocal, int level) {
        LabelNode after = new LabelNode();
        emitIntervalAlwaysTrue(out, carrier, after);
        if (level >= 3) {
            AsmUtil.pushInt(out, context.random().nextInt());
            AsmUtil.pushInt(out, context.random().nextInt());
            out.add(new InsnNode(Opcodes.IADD));
            out.add(new InsnNode(Opcodes.POP));

            out.add(new VarInsnNode(Opcodes.ALOAD, throwableLocal));
            out.add(new InsnNode(Opcodes.ATHROW));
        } else {
            AsmUtil.pushInt(out, context.random().nextInt());
            out.add(new InsnNode(Opcodes.POP));
        }
        out.add(after);
    }

    private static List<AbstractInsnNode> boundarySites(MethodNode method, int rangeCount) {
        List<AbstractInsnNode> real = new ArrayList<AbstractInsnNode>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) {
                real.add(insn);
            }
        }
        List<AbstractInsnNode> sites = new ArrayList<AbstractInsnNode>();
        if (real.size() < 2) {
            return sites;
        }
        for (int i = 1; i < rangeCount; i++) {
            int index = (int) ((long) real.size() * i / rangeCount);
            index = Math.max(1, Math.min(real.size() - 1, index));
            AbstractInsnNode site = real.get(index);
            if (sites.isEmpty() || sites.get(sites.size() - 1) != site) {
                sites.add(site);
            }
        }
        return sites;
    }

    private static int nonZero(int value) {
        return value == 0 ? 0x7E37 : value;
    }

    private static int nextFreeLocal(MethodNode method) {
        int used = Math.max(0, method.maxLocals);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                int slot = ((VarInsnNode) insn).var;
                int size = (insn.getOpcode() == Opcodes.LLOAD || insn.getOpcode() == Opcodes.LSTORE
                        || insn.getOpcode() == Opcodes.DLOAD || insn.getOpcode() == Opcodes.DSTORE) ? 2 : 1;
                used = Math.max(used, slot + size);
            } else if (insn instanceof IincInsnNode) {
                used = Math.max(used, ((IincInsnNode) insn).var + 1);
            }
        }
        return used;
    }
}

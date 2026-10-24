package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Control-flow obfuscation: opaque predicates, inverted branches with junk
 * payloads, dead blocks and stack-neutral junk arithmetic.
 *
 * <p>Every opaque predicate is mathematically provable and verifier-safe:</p>
 * <ul>
 *   <li>{@code (x * (x + 1)) & 1} is always {@code 0} (one of two consecutive
 *       values is even; parity is preserved under two's complement overflow);</li>
 *   <li>{@code (x | 1) != 0} always holds (bit 0 is forced);</li>
 *   <li>{@code x - x == 0} always holds.</li>
 * </ul>
 *
 * <p>The long forms use the same parity identity, which also holds modulo
 * 2<sup>64</sup>. Predicates are anchored on a runtime carrier local seeded from
 * {@code System.nanoTime()}, so the opaque values cannot be folded statically.
 * Junk payloads never touch existing locals and keep the operand stack balanced,
 * so exception handler ranges and stack maps stay valid.</p>
 */
public final class FlowObfuscationPass implements Pass {

    private static final String ANNOTATION = "Lio/umbra/annotations/FlowObfuscation;";

    @Override
    public String name() {
        return "flow-obfuscation";
    }

    @Override
    public int order() {
        return 90;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().flow().enabled();
    }

    @Override
    public void run(PassContext context) {
        int methods = 0;
        int classes = 0;
        int predicates = 0;
        int branches = 0;
        int deadBlocks = 0;
        int junkBlocks = 0;
        int transposed = 0;
        int bogusRanges = 0;
        int rangePredicates = 0;
        int hashPredicates = 0;
        int skipped = 0;
        int reducedClasses = 0;
        int reducedMethods = 0;
        int maxInstructions = context.config().flow().maxInstructions();
        String level = context.config().flow().level().toLowerCase(java.util.Locale.ROOT);
        boolean normal = "normal".equals(level) || "aggressive".equals(level);
        boolean aggressive = "aggressive".equals(level)
                || context.config().optionBool("flow.aggressive", false);
        boolean transpose = context.config().optionBool("flow.transpose", aggressive);
        boolean bogus = context.config().optionBool("flow.bogusRanges", aggressive);
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
            Boolean classEnabled = AsmUtil.annotationBoolean(node.invisibleAnnotations, ANNOTATION, "enabled");
            if (classEnabled == null) {
                classEnabled = AsmUtil.annotationBoolean(node.visibleAnnotations, ANNOTATION, "enabled");
            }
            if (Boolean.FALSE.equals(classEnabled)) {
                continue;
            }

            String fieldName = uniqueFieldName(node);
            int expected = nonZero(context.random().nextInt());
            // Transactional class transform: on any failure (including a class
            // that no longer serializes) the whole class is restored.
            List<MethodNode> savedMethods = new ArrayList<MethodNode>();
            for (MethodNode method : node.methods) {
                savedMethods.add(MethodGate.copy(method));
            }
            List<FieldNode> savedFields = new ArrayList<FieldNode>(node.fields);
            int classMethods = 0;
            int classPredicates = 0;
            int classBranches = 0;
            int classDead = 0;
            int classJunk = 0;
            int classTransposed = 0;
            int classBogus = 0;
            int classRange = 0;
            int classHash = 0;
            try {
                for (MethodNode method : node.methods) {
                    if (!eligible(context, method, maxInstructions)) {
                        continue;
                    }
                    try {
                        MethodNode work = MethodGate.copy(method);
                        Result result = transformMethod(context, node, work, fieldName, expected,
                                normal, aggressive, maxInstructions, transpose, bogus, true);
                        if (!gate.verify(node, work)) {
                            skipped++;
                            context.log().debug("flow-obfuscation: verification rejected %s.%s",
                                    node.name, method.name);
                            continue;
                        }
                        MethodGate.commit(method, work);
                        if (result.transformed) {
                            classMethods++;
                            classPredicates += result.predicates;
                            classBranches += result.inverted;
                            classDead += result.deadBlocks;
                            classJunk += result.junkBlocks;
                            classTransposed += result.transposed;
                            classBogus += result.bogusRanges;
                            classRange += result.rangePredicates;
                            classHash += result.hashPredicates;
                        }
                    } catch (RuntimeException e) {
                        skipped++;
                        context.log().debug("flow-obfuscation: skipped %s.%s: %s",
                                node.name, method.name, e.toString());
                    }
                }
                if (classMethods > 0) {
                    addFieldInit(node, fieldName, expected);
                    if (!gate.writes(node)) {
                        explainUnserializable(context, node, gate);
                        // Salvage the class instead of losing all protection: retry
                        // with a conservative transform (entry guard only, no junk,
                        // dead blocks, transposition or bogus ranges) on clean copies.
                        node.methods = new ArrayList<MethodNode>(savedMethods);
                        node.fields = new ArrayList<FieldNode>(savedFields);
                        int reduced = conservativeTransform(context, node, fieldName, expected,
                                maxInstructions, gate);
                        if (reduced > 0) {
                            reducedClasses++;
                            reducedMethods += reduced;
                            classes++;
                            methods += reduced;
                            continue;
                        }
                        skipped += classMethods;
                        context.log().debug("flow-obfuscation: rolled back class %s: class does not "
                                + "serialize", node.name);
                        continue;
                    }
                    methods += classMethods;
                    predicates += classPredicates;
                    branches += classBranches;
                    deadBlocks += classDead;
                    junkBlocks += classJunk;
                    transposed += classTransposed;
                    bogusRanges += classBogus;
                    rangePredicates += classRange;
                    hashPredicates += classHash;
                    classes++;
                }
            } catch (RuntimeException e) {
                node.methods = new ArrayList<MethodNode>(savedMethods);
                node.fields = new ArrayList<FieldNode>(savedFields);
                skipped += classMethods;
                context.log().debug("flow-obfuscation: rolled back class %s: %s", node.name, e.toString());
            }
        }
        context.stats().add("flow.methods", methods);
        context.stats().add("flow.classes", classes);
        context.stats().add("flow.predicates", predicates);
        context.stats().add("flow.branches.inverted", branches);
        context.stats().add("flow.deadBlocks", deadBlocks);
        context.stats().add("flow.junkBlocks", junkBlocks);
        context.stats().add("flow.transposed", transposed);
        context.stats().add("flow.bogusRanges", bogusRanges);
        context.stats().add("flow.rangePredicates", rangePredicates);
        context.stats().add("flow.hashPredicates", hashPredicates);
        context.stats().add("flow.aggressive", aggressive ? 1 : 0);
        context.stats().add("flow.skipped", skipped);
        if (reducedClasses > 0) {
            context.stats().add("flow.reduced.classes", reducedClasses);
            context.stats().add("flow.reduced.methods", reducedMethods);
        }
        context.log().info("flow-obfuscation[%s]: %d methods across %d classes, %d predicates "
                        + "(%d range, %d hash), %d branches inverted, %d dead blocks, %d junk blocks, "
                        + "%d transposed blocks, %d bogus exception ranges (%d verification skips, "
                        + "%d classes kept conservative)",
                level, methods, classes, predicates, rangePredicates, hashPredicates, branches,
                deadBlocks, junkBlocks, transposed, bogusRanges, skipped, reducedClasses);
    }

    /** Debug aid: when a transformed class no longer serializes, name the failing method. */
    private static void explainUnserializable(PassContext context, ClassNode node, MethodGate gate) {
        for (MethodNode method : node.methods) {
            ClassNode mini = new ClassNode();
            mini.version = node.version;
            mini.access = node.access;
            mini.name = node.name;
            mini.superName = node.superName;
            mini.interfaces = node.interfaces;
            mini.methods.add(method);
            try {
                org.objectweb.asm.ClassWriter writer = new org.objectweb.asm.ClassWriter(
                        org.objectweb.asm.ClassWriter.COMPUTE_FRAMES
                                | org.objectweb.asm.ClassWriter.COMPUTE_MAXS) {
                    @Override
                    protected String getCommonSuperClass(String a, String b) {
                        return context.hierarchy().getCommonSuperClass(a, b);
                    }
                };
                mini.accept(writer);
                writer.toByteArray();
            } catch (Throwable failure) {
                java.io.StringWriter trace = new java.io.StringWriter();
                failure.printStackTrace(new java.io.PrintWriter(trace));
                context.log().debug("flow-obfuscation: class %s method %s%s does not serialize: %s",
                        node.name, method.name, method.desc, trace.toString());
            }
        }
    }

    /**
     * Retry a class whose full transform no longer serializes with the minimal
     * shape: only the entry guard prelude, no junk/dead blocks/transposition/
     * bogus ranges. Returns the number of transformed methods, or 0 when even the
     * conservative shape cannot be serialized (the caller then restores the
     * original class).
     */
    private static int conservativeTransform(PassContext context, ClassNode node, String fieldName,
                                             int expected, int maxInstructions, MethodGate gate) {
        List<MethodNode> backups = new ArrayList<MethodNode>();
        for (MethodNode method : node.methods) {
            backups.add(MethodGate.copy(method));
        }
        List<FieldNode> fieldBackups = new ArrayList<FieldNode>(node.fields);
        int transformed = 0;
        try {
            for (MethodNode method : node.methods) {
                if (!eligible(context, method, maxInstructions)) {
                    continue;
                }
                MethodNode work = MethodGate.copy(method);
                Result result = transformMethod(context, node, work, fieldName, expected,
                        false, false, maxInstructions, false, false, false);
                if (!gate.verify(node, work)) {
                    context.log().debug("flow-obfuscation: conservative verify rejected %s.%s",
                            node.name, method.name);
                    continue;
                }
                MethodGate.commit(method, work);
                if (result.transformed) {
                    transformed++;
                }
            }
            if (transformed == 0) {
                node.methods = backups;
                node.fields = fieldBackups;
                return 0;
            }
            addFieldInit(node, fieldName, expected);
            if (gate.writes(node)) {
                return transformed;
            }
            context.log().debug("flow-obfuscation: conservative class %s still does not serialize",
                    node.name);
            node.methods = backups;
            node.fields = fieldBackups;
            return 0;
        } catch (RuntimeException failure) {
            node.methods = backups;
            node.fields = fieldBackups;
            context.log().debug("flow-obfuscation: conservative retry failed for %s: %s",
                    node.name, failure);
            return 0;
        }
    }

    private static boolean eligible(PassContext context, MethodNode method, int maxInstructions) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        if (method.instructions == null || method.instructions.size() == 0) {
            return false;
        }
        if (method.instructions.size() > maxInstructions
                || method.instructions.size() > maxInstructions - 64) {
            return false;
        }
        if (AsmUtil.containsJsrOrRet(method)) {
            return false;
        }
        Boolean methodEnabled = AsmUtil.annotationBoolean(method.invisibleAnnotations, ANNOTATION, "enabled");
        if (methodEnabled == null) {
            methodEnabled = AsmUtil.annotationBoolean(method.visibleAnnotations, ANNOTATION, "enabled");
        }
        return !Boolean.FALSE.equals(methodEnabled);
    }

    private static Result transformMethod(PassContext context, ClassNode owner, MethodNode method,
                                          String fieldName, int expected, boolean normal,
                                          boolean aggressive, int maxInstructions,
                                          boolean transpose, boolean bogusRanges,
                                          boolean allowJunk) {
        Result result = new Result();
        int budget = Math.max(48, maxInstructions - method.instructions.size());
        int spent = 0;

        // 1. Branch inversion with a junk payload. Must run before the opaque
        //    branches are inserted, otherwise they would be inverted too.
        if (normal) {
            int inverted = invertBranches(context, method, aggressive, budget - spent);
            result.inverted = inverted;
            spent += inverted * 4;
        }

        // 2. Analyse the (already inverted) code to find block entries with an
        //    empty operand stack. A branch over junk is only safe where no
        //    uninitialized object sits on the stack.
        Frame<BasicValue>[] frames = normal ? analyse(owner.name, method) : null;

        // 3. Runtime carrier local + entry opaque predicates.
        int used = nextFreeLocal(method);
        int carrier = -1;
        if (normal || aggressive) {
            carrier = used++;
            method.maxLocals = Math.max(method.maxLocals, used);
        }
        InsnList prelude = new InsnList();
        if (carrier >= 0) {
            emitCarrierInit(context, prelude, carrier);
        }
        emitFieldGuard(context, prelude, owner.name, fieldName, expected);
        result.predicates++;
        if (carrier >= 0) {
            emitOpaqueTrue(context, prelude, carrier, aggressive, result);
            result.predicates++;
        }
        if (aggressive && carrier >= 0) {
            emitOpaqueTrueLong(context, prelude, carrier);
            result.predicates++;
            emitOpaqueTrue(context, prelude, carrier, true, result);
            result.predicates++;
        }
        method.instructions.insert(prelude);

        // 4. Dead blocks at selected reachable block entries (stack empty).
        if (frames != null && (normal || aggressive)) {
            int limit = aggressive ? 6 : 3;
            List<AbstractInsnNode> anchors = selectAnchors(method, frames, limit, context);
            for (AbstractInsnNode anchor : anchors) {
                if (spent >= budget) {
                    break;
                }
                InsnList block = opaqueBranchesOverJunk(context, carrier, aggressive, result);
                if (anchor instanceof LabelNode) {
                    method.instructions.insert(anchor, block);
                } else {
                    method.instructions.insertBefore(anchor, block);
                }
                result.deadBlocks++;
                spent += block.size();
            }
        }

        // 5. Stack-balanced junk arithmetic sprinkled through reachable, ordinary
        //    code positions. Inserting into unreachable code or exception ranges can
        //    make StackMapTable recomputation fail for methods with mixed long/double
        //    locals and handler frames (seen on the hard-input StackStress fixture),
        //    so those sites are skipped instead of risking a whole-class rollback.
        Frame<BasicValue>[] junkFrames = analyse(owner.name, method);
        int junkBudget = aggressive ? Math.min(16, method.instructions.size() / 6 + 2)
                : Math.min(6, method.instructions.size() / 12 + 1);
        AbstractInsnNode[] snapshot = method.instructions.toArray();
        boolean[] unsafe = junkFrames == null ? null
                : unsafeJunkSites(method, snapshot, junkFrames);
        int inserted = 0;
        int guard = snapshot.length * 4 + 16;
        while (allowJunk && unsafe != null && inserted < junkBudget && spent < budget && guard-- > 0) {
            // Deterministic but well mixed site selection.
            if (context.random().nextInt(4) != 0) {
                continue;
            }
            int index = context.random().nextInt(snapshot.length);
            if (unsafe[index]) {
                continue;
            }
            InsnList junk = junk(context, aggressive);
            method.instructions.insertBefore(snapshot[index], junk);
            inserted++;
            spent += junk.size();
        }
        result.junkBlocks = inserted;
        result.maxStack = 12;
        result.transformed = true;
        if (result.maxStack > method.maxStack) {
            method.maxStack = result.maxStack;
        }

        // 6. Code transposition of independent single-entry blocks.
        if (transpose) {
            int limit = aggressive ? 2 : 1;
            for (int i = 0; i < limit; i++) {
                int moved = transposeBlocks(context, owner.name, method);
                if (moved == 0) {
                    break;
                }
                result.transposed += moved;
            }
        }

        // 7. Bogus exception ranges: a range over non-throwing code whose
        //    synthetic handler simply rethrows, so semantics do not change but
        //    the exception table and the code map become misleading.
        if (bogusRanges) {
            result.bogusRanges += addBogusRanges(context, method, aggressive);
        }
        return result;
    }

    // -------------------------------------------------------------- predicates

    private static void emitCarrierInit(PassContext context, InsnList out, int carrier) {
        int seed = nonZero(context.random().nextInt());
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "nanoTime", "()J", false));
        out.add(new InsnNode(Opcodes.L2I));
        AsmUtil.pushInt(out, seed);
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, carrier));
    }

    private static void emitFieldGuard(PassContext context, InsnList out, String owner,
                                       String fieldName, int expected) {
        LabelNode real = new LabelNode();
        out.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, fieldName, "I"));
        AsmUtil.pushInt(out, expected);
        out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, real));
        out.add(junk(context, false));
        out.add(real);
    }

    /** Emits an always-true integer predicate over junk (v1 forms plus range/hash forms). */
    private static void emitOpaqueTrue(PassContext context, InsnList out, int carrier,
                                       boolean aggressive, Result result) {
        LabelNode real = new LabelNode();
        int forms = aggressive ? 6 : 3;
        int variant = context.random().nextInt(forms);
        if (variant == 0) {
            // (x * (x + 1)) & 1 == 0
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            out.add(new InsnNode(Opcodes.DUP));
            out.add(new InsnNode(Opcodes.ICONST_1));
            out.add(new InsnNode(Opcodes.IADD));
            out.add(new InsnNode(Opcodes.IMUL));
            out.add(new InsnNode(Opcodes.ICONST_1));
            out.add(new InsnNode(Opcodes.IAND));
            out.add(new JumpInsnNode(Opcodes.IFEQ, real));
        } else if (variant == 1) {
            // (x | 1) != 0
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            out.add(new InsnNode(Opcodes.ICONST_1));
            out.add(new InsnNode(Opcodes.IOR));
            out.add(new JumpInsnNode(Opcodes.IFNE, real));
        } else if (variant == 2) {
            // x - x == 0
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            out.add(new InsnNode(Opcodes.ISUB));
            out.add(new JumpInsnNode(Opcodes.IFEQ, real));
        } else if (variant == 3) {
            // range predicate: (x >>> 30) is in [0,3], so <= 3 always holds
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            AsmUtil.pushInt(out, 30);
            out.add(new InsnNode(Opcodes.IUSHR));
            out.add(new InsnNode(Opcodes.ICONST_3));
            out.add(new JumpInsnNode(Opcodes.IF_ICMPLE, real));
            result.rangePredicates++;
        } else if (variant == 4) {
            // range predicate: ((x | 1) & 1) == 1 always holds
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            out.add(new InsnNode(Opcodes.ICONST_1));
            out.add(new InsnNode(Opcodes.IOR));
            out.add(new InsnNode(Opcodes.ICONST_1));
            out.add(new InsnNode(Opcodes.IAND));
            out.add(new InsnNode(Opcodes.ICONST_1));
            out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, real));
            result.rangePredicates++;
        } else {
            // hash predicate: h = (x ^ c1) * c2; (h ^ h) == 0 always holds
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            AsmUtil.pushInt(out, 0x5BD1E995);
            out.add(new InsnNode(Opcodes.IXOR));
            AsmUtil.pushInt(out, 0x2C1B3C6D);
            out.add(new InsnNode(Opcodes.IMUL));
            out.add(new InsnNode(Opcodes.DUP));
            out.add(new InsnNode(Opcodes.IXOR));
            out.add(new JumpInsnNode(Opcodes.IFEQ, real));
            result.hashPredicates++;
        }
        out.add(junk(context, aggressive));
        out.add(real);
    }

    /** Emits the long parity identity {@code (y*(y+1))&1 == 0} over junk. */
    private static void emitOpaqueTrueLong(PassContext context, InsnList out, int carrier) {
        LabelNode real = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
        out.add(new InsnNode(Opcodes.I2L));
        out.add(new InsnNode(Opcodes.DUP2));
        out.add(new InsnNode(Opcodes.LCONST_1));
        out.add(new InsnNode(Opcodes.LADD));
        out.add(new InsnNode(Opcodes.LMUL));
        out.add(new InsnNode(Opcodes.LCONST_1));
        out.add(new InsnNode(Opcodes.LAND));
        out.add(new InsnNode(Opcodes.LCONST_0));
        out.add(new InsnNode(Opcodes.LCMP));
        out.add(new JumpInsnNode(Opcodes.IFEQ, real));
        out.add(junk(context, true));
        out.add(real);
    }

    /**
     * Always-true branch over a junk block: the branch is taken on every real
     * execution, so the junk path is dead and the following code is reached by
     * fall-through from the branch target.
     */
    private static InsnList opaqueBranchesOverJunk(PassContext context, int carrier, boolean aggressive,
                                                   Result result) {
        InsnList block = new InsnList();
        emitOpaqueTrue(context, block, carrier, aggressive, result);
        return block;
    }

    // ------------------------------------------------------------------- junk

    private static InsnList junk(PassContext context, boolean aggressive) {
        InsnList out = new InsnList();
        int variant = context.random().nextInt(aggressive ? 5 : 3);
        switch (variant) {
            case 0:
                AsmUtil.pushInt(out, nonZero(context.random().nextInt()));
                AsmUtil.pushInt(out, nonZero(context.random().nextInt()));
                out.add(new InsnNode(Opcodes.IADD));
                out.add(new InsnNode(Opcodes.POP));
                break;
            case 1:
                AsmUtil.pushInt(out, nonZero(context.random().nextInt()));
                AsmUtil.pushInt(out, nonZero(context.random().nextInt()));
                out.add(new InsnNode(Opcodes.IMUL));
                AsmUtil.pushInt(out, nonZero(context.random().nextInt()));
                out.add(new InsnNode(Opcodes.IXOR));
                out.add(new InsnNode(Opcodes.POP));
                break;
            case 2:
                out.add(new LdcInsnNode(Long.valueOf(context.random().nextLong())));
                out.add(new LdcInsnNode(Long.valueOf(context.random().nextLong())));
                out.add(new InsnNode(Opcodes.LXOR));
                out.add(new InsnNode(Opcodes.POP2));
                break;
            case 3:
                out.add(new InsnNode(Opcodes.ICONST_1));
                out.add(new InsnNode(Opcodes.I2L));
                out.add(new LdcInsnNode(Long.valueOf(context.random().nextLong())));
                out.add(new InsnNode(Opcodes.LADD));
                out.add(new InsnNode(Opcodes.POP2));
                break;
            default:
                AsmUtil.pushInt(out, nonZero(context.random().nextInt()));
                AsmUtil.pushInt(out, nonZero(context.random().nextInt()));
                out.add(new InsnNode(Opcodes.IAND));
                AsmUtil.pushInt(out, nonZero(context.random().nextInt()));
                out.add(new InsnNode(Opcodes.IOR));
                out.add(new InsnNode(Opcodes.POP));
                break;
        }
        return out;
    }

    /**
     * Marks instruction indices where stack-neutral junk must not be inserted:
     * pseudo nodes, unreachable instructions, block leaders (jump targets and
     * handler entries), the instruction after a control transfer, and everything
     * inside an exception range. A whole-class rollback is much worse than a
     * slightly smaller junk budget, so the pass prefers conservative sites.
     */
    private static boolean[] unsafeJunkSites(MethodNode method, AbstractInsnNode[] snapshot,
                                             Frame<BasicValue>[] frames) {
        boolean[] unsafe = new boolean[snapshot.length];
        java.util.IdentityHashMap<AbstractInsnNode, Integer> positions =
                new java.util.IdentityHashMap<AbstractInsnNode, Integer>();
        for (int i = 0; i < snapshot.length; i++) {
            positions.put(snapshot[i], Integer.valueOf(i));
            int opcode = snapshot[i].getOpcode();
            boolean pseudo = opcode < 0;
            boolean unreachable = i >= frames.length || frames[i] == null;
            boolean terminal = opcode == Opcodes.RETURN || opcode == Opcodes.ARETURN
                    || opcode == Opcodes.IRETURN || opcode == Opcodes.LRETURN
                    || opcode == Opcodes.FRETURN || opcode == Opcodes.DRETURN
                    || opcode == Opcodes.ATHROW;
            unsafe[i] = pseudo || unreachable || terminal;
        }
        if (unsafe.length > 0) {
            unsafe[0] = true;
        }
        for (int i = 0; i < snapshot.length; i++) {
            AbstractInsnNode insn = snapshot[i];
            if (insn instanceof JumpInsnNode) {
                markJumpLeader(unsafe, positions, ((JumpInsnNode) insn).label);
                markJumpLeader(unsafe, positions, i + 1 < snapshot.length ? snapshot[i + 1] : null);
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
                markJumpLeader(unsafe, positions, table.dflt);
                for (LabelNode label : table.labels) {
                    markJumpLeader(unsafe, positions, label);
                }
                markJumpLeader(unsafe, positions, i + 1 < snapshot.length ? snapshot[i + 1] : null);
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
                markJumpLeader(unsafe, positions, lookup.dflt);
                for (LabelNode label : lookup.labels) {
                    markJumpLeader(unsafe, positions, label);
                }
                markJumpLeader(unsafe, positions, i + 1 < snapshot.length ? snapshot[i + 1] : null);
            } else if (isReturnOrThrow(insn.getOpcode())
                    && i + 1 < snapshot.length) {
                unsafe[i + 1] = true;
            }
        }
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode table : method.tryCatchBlocks) {
                Integer start = positions.get(table.start);
                Integer end = positions.get(table.end);
                if (start != null && end != null) {
                    for (int i = start.intValue(); i < end.intValue() && i < unsafe.length; i++) {
                        unsafe[i] = true;
                    }
                }
                markJumpLeader(unsafe, positions, table.handler);
            }
        }
        return unsafe;
    }

    private static void markJumpLeader(boolean[] unsafe,
                                       java.util.IdentityHashMap<AbstractInsnNode, Integer> positions,
                                       AbstractInsnNode node) {
        if (node == null) {
            return;
        }
        Integer index = positions.get(node);
        if (index != null && index.intValue() < unsafe.length) {
            unsafe[index.intValue()] = true;
        }
    }

    // -------------------------------------------------------------- inversion

    private static int invertBranches(PassContext context, MethodNode method, boolean all, int budget) {
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof JumpInsnNode && count * 5 < budget) {
                int inverse = inverseOpcode(insn.getOpcode());
                if (inverse != -1 && (all || context.random().nextInt(3) == 0)) {
                    JumpInsnNode jump = (JumpInsnNode) insn;
                    LabelNode skip = new LabelNode();
                    InsnList replacement = new InsnList();
                    replacement.add(new JumpInsnNode(inverse, skip));
                    replacement.add(junk(context, all));
                    replacement.add(new JumpInsnNode(Opcodes.GOTO, jump.label));
                    replacement.add(skip);
                    method.instructions.insertBefore(insn, replacement);
                    method.instructions.remove(insn);
                    count++;
                }
            }
            insn = next;
        }
        return count;
    }

    private static int inverseOpcode(int opcode) {
        switch (opcode) {
            case Opcodes.IFEQ: return Opcodes.IFNE;
            case Opcodes.IFNE: return Opcodes.IFEQ;
            case Opcodes.IFLT: return Opcodes.IFGE;
            case Opcodes.IFGE: return Opcodes.IFLT;
            case Opcodes.IFGT: return Opcodes.IFLE;
            case Opcodes.IFLE: return Opcodes.IFGT;
            case Opcodes.IF_ICMPEQ: return Opcodes.IF_ICMPNE;
            case Opcodes.IF_ICMPNE: return Opcodes.IF_ICMPEQ;
            case Opcodes.IF_ICMPLT: return Opcodes.IF_ICMPGE;
            case Opcodes.IF_ICMPGE: return Opcodes.IF_ICMPLT;
            case Opcodes.IF_ICMPGT: return Opcodes.IF_ICMPLE;
            case Opcodes.IF_ICMPLE: return Opcodes.IF_ICMPGT;
            case Opcodes.IF_ACMPEQ: return Opcodes.IF_ACMPNE;
            case Opcodes.IF_ACMPNE: return Opcodes.IF_ACMPEQ;
            case Opcodes.IFNULL: return Opcodes.IFNONNULL;
            case Opcodes.IFNONNULL: return Opcodes.IFNULL;
            default: return -1;
        }
    }

    // --------------------------------------------------------------- analysis

    private static Frame<BasicValue>[] analyse(String owner, MethodNode method) {
        int previousMaxStack = method.maxStack;
        int previousMaxLocals = method.maxLocals;
        try {
            Analyzer<BasicValue> analyzer = new Analyzer<BasicValue>(new BasicInterpreter());
            return analyzer.analyzeAndComputeMaxs(owner, method);
        } catch (AnalyzerException e) {
            method.maxStack = Math.max(1, previousMaxStack);
            method.maxLocals = Math.max(previousMaxLocals, 0);
            return null;
        } catch (RuntimeException e) {
            method.maxStack = Math.max(1, previousMaxStack);
            method.maxLocals = Math.max(previousMaxLocals, 0);
            return null;
        }
    }

    /**
     * Picks block entries whose operand stack is empty. These are safe branch
     * anchors: an uninitialized object can never be carried over the new
     * conditional edge.
     */
    private static List<AbstractInsnNode> selectAnchors(MethodNode method,
                                                        Frame<BasicValue>[] frames, int limit,
                                                        PassContext context) {
        Set<AbstractInsnNode> leaders = new LinkedHashSet<AbstractInsnNode>();
        AbstractInsnNode first = method.instructions.getFirst();
        if (first != null) {
            leaders.add(first);
        }
        for (AbstractInsnNode insn = first; insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                leaders.add(((JumpInsnNode) insn).label);
                if (insn.getNext() != null) {
                    leaders.add(insn.getNext());
                }
            } else if (isReturnOrThrow(insn.getOpcode()) && insn.getNext() != null) {
                leaders.add(insn.getNext());
            }
        }
        List<AbstractInsnNode> candidates = new ArrayList<AbstractInsnNode>();
        for (AbstractInsnNode leader : leaders) {
            int index = method.instructions.indexOf(leader);
            if (index < 0 || index >= frames.length || frames[index] == null) {
                continue;
            }
            if (frames[index].getStackSize() != 0) {
                continue;
            }
            // Never anchor on the very first instruction: the entry prelude
            // already covers it, and inserting before it would run before the
            // carrier is initialised.
            if (leader == first) {
                continue;
            }
            candidates.add(leader);
        }
        List<AbstractInsnNode> selected = new ArrayList<AbstractInsnNode>();
        if (candidates.isEmpty()) {
            return selected;
        }
        int guard = candidates.size() * 4 + 4;
        while (selected.size() < limit && guard-- > 0) {
            AbstractInsnNode candidate = candidates.get(context.random().nextInt(candidates.size()));
            if (!selected.contains(candidate)) {
                selected.add(candidate);
            }
        }
        return selected;
    }

    private static boolean isReturnOrThrow(int opcode) {
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW;
    }

    // -------------------------------------------------------- transposition

    /**
     * Moves one independent basic block to the end of the method.
     *
     * <p>Safety rules: the block must be entered with an empty operand stack,
     * must not be covered by (or contain the boundary of) any exception range,
     * must not contain monitor instructions, must end with an unconditional
     * control transfer, and the physically preceding block must not fall
     * through into it. Under these rules every path that reached the block
     * jumps to its (moved) label, no path depended on the old physical
     * position, and appending the block at the end cannot create a fall-through
     * into the end of the code.</p>
     *
     * @return number of blocks moved (0 or 1)
     */
    private static int transposeBlocks(PassContext context, String owner, MethodNode method) {
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<BasicValue>(new BasicInterpreter()).analyzeAndComputeMaxs(owner, method);
        } catch (AnalyzerException e) {
            return 0;
        } catch (RuntimeException e) {
            return 0;
        }
        AbstractInsnNode[] insns = method.instructions.toArray();
        if (insns.length < 8 || frames.length != insns.length) {
            return 0;
        }
        int[] indexOf = new int[insns.length];
        java.util.IdentityHashMap<AbstractInsnNode, Integer> positions =
                new java.util.IdentityHashMap<AbstractInsnNode, Integer>();
        for (int i = 0; i < insns.length; i++) {
            positions.put(insns[i], Integer.valueOf(i));
            indexOf[i] = i;
        }
        Set<Integer> leaders = new HashSet<Integer>();
        leaders.add(Integer.valueOf(0));
        for (int i = 0; i < insns.length; i++) {
            AbstractInsnNode insn = insns[i];
            if (insn instanceof JumpInsnNode) {
                addLeader(leaders, positions, ((JumpInsnNode) insn).label);
                if (i + 1 < insns.length) {
                    leaders.add(Integer.valueOf(i + 1));
                }
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
                addLeader(leaders, positions, table.dflt);
                for (LabelNode label : table.labels) {
                    addLeader(leaders, positions, label);
                }
                if (i + 1 < insns.length) {
                    leaders.add(Integer.valueOf(i + 1));
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
                addLeader(leaders, positions, lookup.dflt);
                for (LabelNode label : lookup.labels) {
                    addLeader(leaders, positions, label);
                }
                if (i + 1 < insns.length) {
                    leaders.add(Integer.valueOf(i + 1));
                }
            } else if (isReturnOrThrow(insn.getOpcode()) && i + 1 < insns.length) {
                leaders.add(Integer.valueOf(i + 1));
            }
        }
        List<int[]> protectedRanges = new ArrayList<int[]>();
        Set<Integer> tryBoundaries = new HashSet<Integer>();
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode table : method.tryCatchBlocks) {
                Integer start = positions.get(table.start);
                Integer end = positions.get(table.end);
                Integer handler = positions.get(table.handler);
                if (start == null || end == null || handler == null) {
                    continue;
                }
                leaders.add(handler);
                leaders.add(start);
                leaders.add(end);
                tryBoundaries.add(start);
                tryBoundaries.add(end);
                tryBoundaries.add(handler);
                protectedRanges.add(new int[] { start.intValue(), end.intValue() });
            }
        }
        List<Integer> boundaries = new ArrayList<Integer>(leaders);
        java.util.Collections.sort(boundaries);
        List<Block> blocks = new ArrayList<Block>();
        for (int b = 0; b < boundaries.size(); b++) {
            int start = boundaries.get(b).intValue();
            int end = b + 1 < boundaries.size() ? boundaries.get(b + 1).intValue() : insns.length;
            if (start >= end) {
                continue;
            }
            Block block = new Block();
            block.start = start;
            block.end = end;
            for (int i = start; i < end; i++) {
                if (insns[i].getOpcode() >= 0) {
                    block.firstReal = block.firstReal < 0 ? i : block.firstReal;
                    block.lastReal = i;
                }
                if (insns[i] instanceof LabelNode && tryBoundaries.contains(Integer.valueOf(i))) {
                    block.tryBoundary = true;
                }
            }
            block.size = block.lastReal - block.firstReal + 1;
            blocks.add(block);
        }
        List<Integer> candidates = new ArrayList<Integer>();
        for (int b = 1; b < blocks.size(); b++) {
            Block block = blocks.get(b);
            if (block.firstReal < 0 || block.size < 2 || block.size > 24) {
                continue;
            }
            Block previous = blocks.get(b - 1);
            if (previous.lastReal < 0 || !endsWithoutFallthrough(insns[previous.lastReal])) {
                continue;
            }
            if (!endsWithoutFallthrough(insns[block.lastReal])) {
                continue;
            }
            if (frames[block.firstReal] == null || frames[block.firstReal].getStackSize() != 0) {
                continue;
            }
            if (block.tryBoundary) {
                continue;
            }
            boolean covered = false;
            for (int[] range : protectedRanges) {
                if (block.start < range[1] && block.end > range[0]) {
                    covered = true;
                    break;
                }
            }
            if (covered) {
                continue;
            }
            boolean hasMonitor = false;
            for (int i = block.start; i < block.end; i++) {
                int opcode = insns[i].getOpcode();
                if (opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
                    hasMonitor = true;
                    break;
                }
            }
            if (hasMonitor) {
                continue;
            }
            candidates.add(Integer.valueOf(b));
        }
        if (candidates.isEmpty()) {
            return 0;
        }
        Block chosen = blocks.get(candidates.get(context.random().nextInt(candidates.size())).intValue());
        List<AbstractInsnNode> moved = new ArrayList<AbstractInsnNode>(chosen.end - chosen.start);
        for (int i = chosen.start; i < chosen.end; i++) {
            moved.add(insns[i]);
        }
        for (int i = 0; i < moved.size(); i++) {
            method.instructions.remove(moved.get(i));
        }
        for (int i = 0; i < moved.size(); i++) {
            method.instructions.add(moved.get(i));
        }
        return 1;
    }

    private static void addLeader(Set<Integer> leaders,
                                  java.util.IdentityHashMap<AbstractInsnNode, Integer> positions,
                                  AbstractInsnNode node) {
        Integer position = positions.get(node);
        if (position != null) {
            leaders.add(position);
        }
    }

    private static boolean endsWithoutFallthrough(AbstractInsnNode insn) {
        if (insn == null) {
            return false;
        }
        int opcode = insn.getOpcode();
        return opcode == Opcodes.GOTO || opcode == Opcodes.TABLESWITCH
                || opcode == Opcodes.LOOKUPSWITCH || isReturnOrThrow(opcode);
    }

    /** Basic block candidate (instruction-index range, real instruction bounds). */
    private static final class Block {
        int start;
        int end;
        int firstReal = -1;
        int lastReal = -1;
        int size;
        boolean tryBoundary;
    }

    // -------------------------------------------------- bogus exception ranges

    /**
     * Adds up to one or two exception-table entries over ranges that contain no
     * original handler. The synthetic handler only rethrows the caught throwable
     * (same propagation, same stack trace), so behaviour is unchanged while the
     * exception table, the handler graph and decompiler output become wrong.
     *
     * @return number of ranges added
     */
    private static int addBogusRanges(PassContext context, MethodNode method, boolean aggressive) {
        int wanted = aggressive ? 2 : 1;
        int added = 0;
        for (int attempt = 0; attempt < wanted * 2 && added < wanted; attempt++) {
            if (addBogusRange(context, method, aggressive)) {
                added++;
            }
        }
        return added;
    }

    private static boolean addBogusRange(PassContext context, MethodNode method, boolean aggressive) {
        AbstractInsnNode[] insns = method.instructions.toArray();
        if (insns.length < 12) {
            return false;
        }
        java.util.IdentityHashMap<AbstractInsnNode, Integer> positions =
                new java.util.IdentityHashMap<AbstractInsnNode, Integer>();
        List<Integer> real = new ArrayList<Integer>();
        for (int i = 0; i < insns.length; i++) {
            positions.put(insns[i], Integer.valueOf(i));
            if (insns[i].getOpcode() >= 0) {
                real.add(Integer.valueOf(i));
            }
        }
        if (real.size() < 6) {
            return false;
        }
        List<int[]> protectedRanges = new ArrayList<int[]>();
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode table : method.tryCatchBlocks) {
                Integer start = positions.get(table.start);
                Integer end = positions.get(table.end);
                if (start != null && end != null) {
                    protectedRanges.add(new int[] { start.intValue(), end.intValue() });
                }
            }
        }
        int span = Math.min(real.size(), (aggressive ? 6 : 4) + context.random().nextInt(6));
        if (real.size() - span < 1) {
            span = Math.max(2, real.size() / 2);
        }
        int first = context.random().nextInt(Math.max(1, real.size() - span));
        int startIndex = real.get(first).intValue();
        int lastIndex = real.get(first + span - 1).intValue();
        int endIndex = lastIndex + 1;
        if (startIndex >= endIndex) {
            return false;
        }
        for (int[] range : protectedRanges) {
            if (startIndex < range[1] && endIndex > range[0]) {
                return false;
            }
        }
        LabelNode startLabel = new LabelNode();
        method.instructions.insertBefore(insns[startIndex], startLabel);
        LabelNode endLabel = new LabelNode();
        if (endIndex < insns.length) {
            method.instructions.insertBefore(insns[endIndex], endLabel);
        } else {
            method.instructions.add(endLabel);
        }
        LabelNode handler = new LabelNode();
        method.instructions.add(handler);
        method.instructions.add(new InsnNode(Opcodes.ATHROW));
        if (method.tryCatchBlocks == null) {
            method.tryCatchBlocks = new ArrayList<TryCatchBlockNode>();
        }
        method.tryCatchBlocks.add(new TryCatchBlockNode(startLabel, endLabel, handler,
                "java/lang/Throwable"));
        method.maxStack = Math.max(method.maxStack, 2);
        return true;
    }

    // --------------------------------------------------------------- class bits

    private static void addFieldInit(ClassNode node, String fieldName, int expected) {
        FieldNode field = new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                fieldName, "I", null, null);
        node.fields.add(field);

        MethodNode clinit = null;
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                clinit = method;
                break;
            }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            clinit.maxLocals = 0;
            clinit.maxStack = 1;
            node.methods.add(clinit);
        }
        InsnList init = new InsnList();
        AsmUtil.pushInt(init, expected);
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, fieldName, "I"));
        clinit.instructions.insert(init);
        clinit.maxStack = Math.max(clinit.maxStack, 1);
    }

    private static String uniqueFieldName(ClassNode node) {
        Set<String> names = new HashSet<String>();
        for (FieldNode field : node.fields) {
            names.add(field.name);
        }
        int counter = 0;
        String candidate;
        do {
            candidate = "z$f" + Integer.toHexString(counter++);
        } while (names.contains(candidate));
        return candidate;
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

    private static int nonZero(int value) {
        return value == 0 ? 0x51ED : value;
    }

    private static final class Result {
        boolean transformed;
        int predicates;
        int inverted;
        int deadBlocks;
        int junkBlocks;
        int transposed;
        int bogusRanges;
        int rangePredicates;
        int hashPredicates;
        int maxStack;
    }
}

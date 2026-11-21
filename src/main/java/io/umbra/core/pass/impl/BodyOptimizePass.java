package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.pass.impl.optimize.DeadCodeSweeper;
import io.umbra.core.pass.impl.optimize.InsnSupport;
import io.umbra.core.pass.impl.optimize.IntConstantReuser;
import io.umbra.core.pass.impl.optimize.UnusedLocalSweeper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Body-level cleanup: dead code, repeated int constants and write-only locals.
 *
 * <p>This is the Umbra port of aidsfuscator's {@code DeadCodeCleanTransformer},
 * {@code IntegerReuseOptimizationPass} and
 * {@code UnusedLocalVariableCleanTransformer}: three size optimisations that must
 * run after every pass which inserts code, because they remove what those passes
 * leave behind. Unlike the donor's unused-local cleaner this port never treats a
 * field access as inherently unremovable; the donor compared the field owner with
 * the method name, which always differs, and therefore never removed anything
 * behind a field access. Here the removal test is about the producer
 * instruction's side effects alone.</p>
 *
 * <p>Every method is transformed on a copy and only committed when
 * {@link MethodGate} verifies it, so a method this pass cannot handle keeps its
 * original bytes.</p>
 */
public final class BodyOptimizePass implements Pass {

    private static final String PREFIX = "bodyOptimize.";

    @Override
    public String name() {
        return "body-optimize";
    }

    @Override
    public int order() {
        return 119;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool(PREFIX + "enabled", false);
    }

    @Override
    public void run(PassContext context) {
        boolean deadCode = context.config().optionBool(PREFIX + "deadCode", true);
        boolean intReuse = context.config().optionBool(PREFIX + "intReuse", true);
        boolean unusedLocals = context.config().optionBool(PREFIX + "unusedLocals", true);
        int threshold = context.config().optionInt(PREFIX + "intReuseThreshold", 2);
        if (threshold < 2) {
            threshold = 2;
        }
        int maxMethodsPerClass = context.config().optionInt(PREFIX + "maxMethodsPerClass", 0);

        MethodGate gate = new MethodGate(context);
        long deadInstructions = 0L;
        long deadBlocks = 0L;
        long methods = 0L;
        long classes = 0L;
        long reused = 0L;
        long sites = 0L;
        long locals = 0L;
        long skipped = 0L;
        long jsrSkips = 0L;
        long rollbacks = 0L;

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
            int done = 0;
            for (MethodNode method : node.methods) {
                if (maxMethodsPerClass > 0 && done >= maxMethodsPerClass) {
                    break;
                }
                if (!eligible(method)) {
                    continue;
                }
                if (InsnSupport.hasJsrRet(method)) {
                    jsrSkips++;
                    continue;
                }
                MethodNode work = MethodGate.copy(method);
                int sawInstructions = 0;
                int sawBlocks = 0;
                int sawReused = 0;
                int sawSites = 0;
                int sawLocals = 0;
                boolean changed = false;
                try {
                    if (deadCode) {
                        DeadCodeSweeper.Result result = DeadCodeSweeper.sweep(node, work);
                        if (result.skipped()) {
                            skipped++;
                            continue;
                        }
                        sawInstructions = result.instructions();
                        sawBlocks = result.blocks();
                        changed = changed || sawInstructions > 0;
                    }
                    if (intReuse) {
                        IntConstantReuser.Result result = IntConstantReuser.hoist(work, threshold);
                        sawReused = result.reused();
                        sawSites = result.sites();
                        changed = changed || sawSites > 0;
                    }
                    if (unusedLocals) {
                        sawLocals = UnusedLocalSweeper.sweep(work);
                        changed = changed || sawLocals > 0;
                    }
                    if (!changed) {
                        continue;
                    }
                    if (!gate.verify(node, work)) {
                        rollbacks++;
                        continue;
                    }
                    MethodGate.commit(method, work);
                } catch (RuntimeException failure) {
                    rollbacks++;
                    context.log().debug("body-optimize: rolled back %s.%s: %s",
                            node.name, method.name, failure);
                    continue;
                }
                methods++;
                done++;
                deadInstructions += sawInstructions;
                deadBlocks += sawBlocks;
                reused += sawReused;
                sites += sawSites;
                locals += sawLocals;
            }
            if (done > 0) {
                classes++;
            }
        }

        context.stats().add(PREFIX + "deadInstructions", deadInstructions);
        context.stats().add(PREFIX + "deadBlocks", deadBlocks);
        context.stats().add(PREFIX + "methods", methods);
        context.stats().add(PREFIX + "intReuse", reused);
        context.stats().add(PREFIX + "intSites", sites);
        context.stats().add(PREFIX + "localsRemoved", locals);
        context.stats().add(PREFIX + "skip.rollback", rollbacks);
        context.stats().add(PREFIX + "skip.jsr", jsrSkips);
        context.stats().add(PREFIX + "skipped", skipped + jsrSkips + rollbacks);
        context.stats().text(PREFIX + "level", "deadCode=" + deadCode + ", intReuse=" + intReuse
                + " (threshold " + threshold + "), unusedLocals=" + unusedLocals);
        context.log().info("body-optimize: %d methods in %d classes, %d dead instructions (%d blocks), "
                        + "%d int constants over %d sites, %d unused locals, %d rollbacks, %d jsr skips",
                methods, classes, deadInstructions, deadBlocks, reused, sites, locals, rollbacks, jsrSkips);
    }

    private static boolean eligible(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        return method.instructions != null && method.instructions.size() > 0;
    }
}

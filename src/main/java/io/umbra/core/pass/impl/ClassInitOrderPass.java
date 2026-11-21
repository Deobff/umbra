package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.pass.impl.initorder.ClinitEditor;
import io.umbra.core.pass.impl.initorder.StaticInitGraph;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Class initialisation order (aidsfuscator {@code ClassInitOrderHandler} and
 * its {@code ClassInitOrderLoader}/{@code ClassInitOrderWriter} pair).
 *
 * <p>The donor loads an ordered pair list such as {@code [["A","B"], ...]} and
 * wires {@code B}'s initialiser to depend on {@code A}'s; its dispatcher then
 * crashes with a {@code NullPointerException} when the order is violated
 * ({@code StrictSaltDispatcherClassGenerator#retrieverOrder}). A pair list is an
 * input format, not the capability - the capability is "know the static
 * initialisation graph and act on it", so this pass derives the graph itself:</p>
 *
 * <ol>
 *   <li>walk every {@code <clinit>} (plus the same-class static methods it can
 *       reach, which is where {@code FieldInitializationPass} leaves helper
 *       code) and record {@code GETSTATIC}/{@code PUTSTATIC}/{@code INVOKESTATIC}
 *       references to other classes of the program ({@link StaticInitGraph});</li>
 *   <li>report strongly connected components - initialisation cycles, which the
 *       JVM resolves by "whichever thread wins", i.e. a real source of
 *       non-deterministic static state;</li>
 *   <li>order the condensation dependencies-first and publish it as
 *       {@code classInitOrder.order} plus one {@code classInitOrder.cycle} meta
 *       entry per run, and a {@code WARN} line per cycle.</li>
 * </ol>
 *
 * <p>Three actions decide what happens after the analysis, all of them opt-in:</p>
 *
 * <ul>
 *   <li>{@code report} (default) - analysis only, zero bytecode change;</li>
 *   <li>{@code reorderClinit} - permutes independent statement runs inside each
 *       initialiser so that references to earlier-initialised classes execute
 *       first, keeping every dependency inside a run ({@link ClinitEditor}
 *       documents the conservative independence rule: no field write, no local,
 *       no branch, no exception range, only pure constant constructors);</li>
 *   <li>{@code hoist} - moves constant static initialisers into
 *       {@code ConstantValue} attributes, which the VM applies during class
 *       preparation, so those {@code push; PUTSTATIC} pairs leave the
 *       initialiser entirely and can no longer participate in a cycle at
 *       run time.</li>
 * </ul>
 *
 * <p>Every body edit goes through {@link MethodGate}: copy, edit, verify, commit.
 * A rejected body keeps the original initialiser, and the hoisted
 * {@code ConstantValue} values are only written back once the edited body
 * verified, so a class can never keep a half-applied hoist.</p>
 */
public final class ClassInitOrderPass implements Pass {

    private static final String OPTION_ENABLED = "classInitOrder.enabled";
    private static final String OPTION_ACTION = "classInitOrder.action";
    private static final String OPTION_MAX_DEPTH = "classInitOrder.maxDepth";
    private static final String OPTION_STRICT = "classInitOrder.strictIndependence";

    private static final String ACTION_REPORT = "report";
    private static final String ACTION_REORDER = "reorderClinit";
    private static final String ACTION_HOIST = "hoist";

    @Override
    public String name() {
        return "class-init-order";
    }

    @Override
    public int order() {
        return 41;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool(OPTION_ENABLED, false);
    }

    @Override
    public void run(PassContext context) {
        String action = normalize(context.config().option(OPTION_ACTION, ACTION_REPORT));
        int maxDepth = Math.max(1, Math.min(4096,
                context.config().optionInt(OPTION_MAX_DEPTH, 64)));
        boolean strictIndependence = context.config().optionBool(OPTION_STRICT, false);

        StaticInitGraph graph = StaticInitGraph.build(context, maxDepth);
        long classes = 0L;
        long methods = 0L;
        long reordered = 0L;
        long hoisted = 0L;
        long skipped = 0L;
        long rolledBack = 0L;
        long withoutClinit = 0L;

        List<List<String>> cycles = graph.cycles();
        for (int i = 0; i < cycles.size(); i++) {
            List<String> cycle = cycles.get(i);
            StringBuilder text = new StringBuilder();
            for (int c = 0; c < cycle.size(); c++) {
                if (c > 0) {
                    text.append(" -> ");
                }
                text.append(cycle.get(c));
            }
            text.append(" -> ").append(cycle.get(0));
            context.log().warn("class-init-order: static initialisation cycle %s (%d classes); "
                            + "the JVM leaves the winner to whichever thread initialises first",
                    text.toString(), cycle.size());
        }
        String cyclesText = graph.cyclesText();
        context.classes().putMeta("classInitOrder.cycle", cyclesText);
        context.classes().putMeta("classInitOrder.cycles", cyclesText);
        context.classes().putMeta("classInitOrder.order", graph.orderText());

        Map<String, Integer> ranks = new LinkedHashMap<String, Integer>();
        List<String> order = graph.order();
        for (int i = 0; i < order.size(); i++) {
            ranks.put(order.get(i), Integer.valueOf(graph.rank(order.get(i))));
        }

        if (!ACTION_REPORT.equals(action)) {
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
                MethodNode clinit = findClinit(node);
                if (clinit == null || clinit.instructions == null
                        || clinit.instructions.size() == 0) {
                    withoutClinit++;
                    continue;
                }
                Frame<BasicValue>[] frames = ClinitEditor.analyse(node.name, clinit);
                if (frames == null) {
                    skipped++;
                    context.log().debug("class-init-order: cannot analyse the initialiser of %s",
                            node.name);
                    continue;
                }
                MethodNode saved = MethodGate.copy(clinit);
                Map<String, Object> savedValues = snapshotValues(node);
                MethodNode work = MethodGate.copy(clinit);
                Map<String, Object> pending = new LinkedHashMap<String, Object>();
                try {
                    boolean edit;
                    int moved = 0;
                    int lifted = 0;
                    if (ACTION_HOIST.equals(action)) {
                        lifted = ClinitEditor.hoist(node, work, frames, pending);
                        edit = lifted > 0;
                    } else {
                        List<ClinitEditor.Statement> statements =
                                ClinitEditor.statements(work, frames);
                        int seed = (int) (context.config().seed()
                                ^ (long) node.name.hashCode()) ^ 0x9E3779B9;
                        ClinitEditor.classify(work, statements, frames, ranks, seed,
                                strictIndependence);
                        moved = ClinitEditor.reorder(work, statements);
                        edit = moved > 0;
                    }
                    if (!edit) {
                        continue;
                    }
                    if (!gate.verify(node, work)) {
                        skipped++;
                        context.log().debug("class-init-order: %s did not verify after the "
                                + "initialiser edit", node.name);
                        continue;
                    }
                    MethodGate.commit(clinit, work);
                    if (!pending.isEmpty()) {
                        hoisted += ClinitEditor.applyConstants(node, pending);
                    }
                    reordered += moved;
                    methods++;
                    classes++;
                } catch (RuntimeException failure) {
                    restore(clinit, saved);
                    for (FieldNode field : node.fields) {
                        String key = field.name + ((char) 0) + field.desc;
                        if (savedValues.containsKey(key)) {
                            field.value = savedValues.get(key);
                        }
                    }
                    rolledBack++;
                    context.log().debug("class-init-order: rolled back %s: %s",
                            node.name, failure.toString());
                }
            }
        }

        context.stats().add("classInitOrder.classes", classes);
        context.stats().add("classInitOrder.methods", methods);
        context.stats().add("classInitOrder.edges", graph.edgeCount());
        context.stats().add("classInitOrder.cycles", (long) cycles.size());
        context.stats().add("classInitOrder.graphClasses", graph.classCount());
        context.stats().add("classInitOrder.reordered", reordered);
        context.stats().add("classInitOrder.hoisted", hoisted);
        context.stats().add("classInitOrder.skipped", skipped);
        context.stats().add("classInitOrder.skip.rollback", rolledBack);
        context.stats().add("classInitOrder.noClinit", withoutClinit);
        context.stats().text("classInitOrder.action", action);
        context.stats().text("classInitOrder.independence",
                strictIndependence ? "strict" : "disjoint-fields");
        context.classes().putMeta("classInitOrder.action", action);
        context.log().info("class-init-order[action=%s depth=%d]: %d classes / %d static "
                        + "dependencies, %d cycles, %d initialisers rewritten "
                        + "(%d hoisted fields, %d statements reordered, %d skipped)",
                action, maxDepth, graph.classCount(), graph.edgeCount(), cycles.size(),
                methods, hoisted, reordered, skipped);
    }

    private static String normalize(String raw) {
        String value = raw == null ? ACTION_REPORT : raw.trim().toLowerCase(Locale.ROOT);
        if ("reorder".equals(value) || "reorderclinit".equals(value)
                || "reorder-clinit".equals(value)) {
            return ACTION_REORDER;
        }
        if ("hoist".equals(value)) {
            return ACTION_HOIST;
        }
        return ACTION_REPORT;
    }

    private static MethodNode findClinit(ClassNode node) {
        for (int i = 0; i < node.methods.size(); i++) {
            MethodNode method = node.methods.get(i);
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        return null;
    }

    private static Map<String, Object> snapshotValues(ClassNode node) {
        Map<String, Object> values = new LinkedHashMap<String, Object>();
        for (int i = 0; i < node.fields.size(); i++) {
            FieldNode field = node.fields.get(i);
            values.put(field.name + ((char) 0) + field.desc, field.value);
        }
        return values;
    }

    private static void restore(MethodNode target, MethodNode saved) {
        target.instructions = saved.instructions;
        target.tryCatchBlocks = saved.tryCatchBlocks;
        target.maxStack = saved.maxStack;
        target.maxLocals = saved.maxLocals;
    }
}

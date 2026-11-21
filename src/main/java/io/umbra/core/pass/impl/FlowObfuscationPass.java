package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.flow.MethodFlowAnalyzer;
import io.umbra.core.pass.impl.flow.KeyRootMask;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.pass.impl.flow.RuntimeTable;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.mba.AsmMba;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
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
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Control-flow obfuscation: opaque predicates, inverted branches with junk
 * payloads, dead blocks and stack-neutral junk arithmetic.
 *
 * <p>Guards and opaque predicates are anchored on runtime values that no
 * single algebraic rewrite folds (W3/W4/W6):</p>
 * <ul>
 *   <li>per-class {@code int[]} tables are filled in {@code <clinit>} by an
 *       xorshift chain seeded from {@code System.nanoTime()}; guard fields and
 *       predicate operands are read out of the table, so a simplifier has to
 *       scalarise the table loop and carry {@code <clinit>} data flow into
 *       every method before the value becomes constant
 *       ({@link RuntimeTable});</li>
 *   <li>interval predicates compare a non-negative projection of a runtime value,
 *       so the branch direction is fixed at run time but never a one-line
 *       algebraic identity;</li>
 *   <li>differential branches route two genuinely equivalent junk paths through
 *       the parity of the one-time-program carrier, so a static tool sees no
 *       fixed truth value and two identical calls do not execute the same path.</li>
 * </ul>
 *
 * <p>Junk payloads never touch existing locals and keep the operand stack
 * balanced, so exception handler ranges and stack maps stay valid.</p>
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
        int reordered = 0;
        int bogusRanges = 0;
        int intervalPredicates = 0;
        int tablePredicates = 0;
        int mbaPredicates = 0;
        int bogusPops = 0;
        int entryShuffles = 0;
        int crossClassPredicates = 0;
        int differentialBranches = 0;
        int irreducibleEntries = 0;
        int skipped = 0;
        int ineligible = 0;
        int reducedClasses = 0;
        int reducedMethods = 0;
        int runtimeTableClasses = 0;
        int runtimeTables = 0;
        int maskedConstants = 0;
        int fallbackConstants = 0;
        int maxInstructions = context.config().flow().maxInstructions();
        int pairBudget = Math.max(2, context.config().optionInt("flow.tablePairs", 256));

        KeyRootMask tableMask = KeyRootMask.create(context, true);
        String tableMode = tableMask == null ? "static" : "native";
        String level = context.config().flow().level().toLowerCase(java.util.Locale.ROOT);
        // "light" used to fall through every real transform: it produced one
        // entry guard and a handful of junk instructions per method and nothing
        // else, so the default preset shipped with almost no flow protection.
        // Light now runs the real pipeline with a smaller anchor budget instead
        // of skipping it.
        boolean normal = "light".equals(level) || "normal".equals(level)
                || "aggressive".equals(level);
        boolean aggressive = "aggressive".equals(level)
                || context.config().optionBool("flow.aggressive", false);
        boolean transpose = context.config().optionBool("flow.transpose", aggressive);
        boolean bogus = context.config().optionBool("flow.bogusRanges", aggressive);
        boolean crossClass = context.config().optionBool("flow.crossClass", true);
        MethodGate gate = new MethodGate(context);

        String otpClass = context.config().optionBool("otp.enabled", false)
                ? context.runtime().ensureOtp(context.classes(), context.config().seed())
                : null;
        int otpMethods = 0;

        int totalClasses = 0;

        int totalMethods = 0;
        int skipHelper = 0;
        int skipRule = 0;
        int skipShape = 0;
        int skipAnnotation = 0;
        int skipNoMethods = 0;
        int skipRollback = 0;

        Map<String, FlowGroup> groups = selectGroups(context);
        CrossClassHosts crossClassHosts = new CrossClassHosts(context, crossClass);
        boolean analyzerAnchors = context.config().optionBool("flow.analyzerAnchors", true);
        int analyzerMethods = 0;
        int analyzerLoops = 0;
        int analyzerSites = 0;
        for (ClassNode candidate : context.classes().classes().values()) {
            if (!context.classes().isGenerated(candidate.name) && !context.classes().isFrozen(candidate.name)) {
                totalClasses++;
                for (MethodNode candidateMethod : candidate.methods) {
                    if (candidateMethod.name.startsWith("<")) {
                        continue;
                    }
                    if ((candidateMethod.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                        continue;
                    }
                    totalMethods++;
                }
            }
        }
        for (ClassNode node : context.classes().classes().values()) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                skipHelper++;
                continue;
            }
                if (context.rules().skipBodyTransform(node.name)) {
                    skipRule++;
                    continue;
                }
            if (!context.rules().transformClass(node)) {
                skipRule++;
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                    || "module-info".equals(node.name)) {
                skipShape++;
                continue;
            }
            Boolean classEnabled = AsmUtil.annotationBoolean(node.invisibleAnnotations, ANNOTATION, "enabled");
            if (classEnabled == null) {
                classEnabled = AsmUtil.annotationBoolean(node.visibleAnnotations, ANNOTATION, "enabled");
            }
            if (Boolean.FALSE.equals(classEnabled)) {
                skipAnnotation++;
                continue;
            }

            String fieldName = uniqueFieldName(node);
            int expected = nonZero(context.random().nextInt());

            FlowGroup group = groups.get(groupKey(context, node.name));
            boolean holder = group != null && group.holder.equals(node.name);
            if (holder) {

                group.established = true;
            }

            RuntimeTable table = RuntimeTable.create(context, node, pairBudget, tableMask);
            GuardPlan plan = new GuardPlan(context, table, node.name, fieldName, expected);
            attachCrossGuard(plan, crossClassHosts);

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
            int classReordered = 0;
            int classBogus = 0;
            int classInterval = 0;
            int classTable = 0;
            int classMba = 0;
            int classBogusPops = 0;
            int classEntryShuffles = 0;
            int classCross = 0;
            int classDifferential = 0;
            int classIrreducible = 0;
            int classAnalyzerMethods = 0;
            int classAnalyzerLoops = 0;
            int classAnalyzerSites = 0;
            try {
                for (MethodNode method : node.methods) {
                    if (!eligible(context, method, maxInstructions)) {
                        ineligible++;
                        if (!method.name.startsWith("<")) {
                            context.log().info("flow-obfuscation: skipped %s.%s%s "
                                    + "(too large or not eligible) - it keeps its plain control flow",
                                    node.name, method.name, method.desc);
                        }
                        continue;
                    }
                    try {
                        MethodNode work = MethodGate.copy(method);
                        Result result = transformMethod(context, node, work, plan,
                                normal, aggressive, maxInstructions, transpose, bogus, true, otpClass,
                                group, analyzerAnchors);
                        if (!gate.verify(node, work)) {
                            skipped++;
                            context.log().debug("flow-obfuscation: verification rejected %s.%s",
                                    node.name, method.name);
                            continue;
                        }
                        MethodGate.commit(method, work);
                        if (result.transformed) {
                            classMethods++;
                            if (otpClass != null) {
                                otpMethods++;
                            }
                            classPredicates += result.predicates;
                            classBranches += result.inverted;
                            classDead += result.deadBlocks;
                            classJunk += result.junkBlocks;
                            classTransposed += result.transposed;
                            classReordered += result.reordered;
                            classBogus += result.bogusRanges;
                            classInterval += result.intervalPredicates;
                            classTable += result.tablePredicates;
                            classMba += result.mbaPredicates;
                            classBogusPops += result.bogusPops;
                            classEntryShuffles += result.entryShuffles;
                            classCross += result.crossClassPredicates;
                            classDifferential += result.differentialBranches;
                            classIrreducible += result.irreducible;
                            if (result.analyzerSites > 0) {
                                classAnalyzerMethods++;
                                classAnalyzerSites += result.analyzerSites;
                                classAnalyzerLoops += result.analyzerLoops;
                            }
                        }
                    } catch (RuntimeException e) {
                        skipped++;
                        context.log().debug("flow-obfuscation: skipped %s.%s: %s",
                                node.name, method.name, e.toString());
                    }
                }
                if (classMethods > 0) {
                    materializeGroup(node, group);
                    addFieldInit(node, plan);
                    plan.materialize(node);
                    if (!gate.writes(node)) {
                        explainUnserializable(context, node, gate);

                        node.methods = new ArrayList<MethodNode>(savedMethods);
                        node.fields = new ArrayList<FieldNode>(savedFields);
                        RuntimeTable retryTable = RuntimeTable.create(context, node, pairBudget,
                                tableMask);
                        GuardPlan retryPlan = new GuardPlan(context, retryTable, node.name,
                                fieldName, expected);
                        int reduced = conservativeTransform(context, node, retryPlan,
                                maxInstructions, gate, otpClass, group, analyzerAnchors);
                        if (reduced > 0) {
                            if (!retryTable.isEmpty()) {
                                runtimeTableClasses++;
                                runtimeTables += retryTable.chunkCount();
                                maskedConstants += retryTable.pairCount();
                                fallbackConstants += retryPlan.fallbacks;
                            }
                            crossClassHosts.prepare(node);
                            reducedClasses++;
                            reducedMethods += reduced;
                            classes++;
                            methods += reduced;
                            continue;
                        }
                        skipped += classMethods;
                        skipRollback++;
                        if (holder) {

                            group.established = false;
                        }
                        context.log().debug("flow-obfuscation: rolled back class %s: class does not "
                                + "serialize", node.name);
                        continue;
                    }
                    crossClassHosts.prepare(node);
                    if (!table.isEmpty()) {
                        runtimeTableClasses++;
                        runtimeTables += table.chunkCount();
                        maskedConstants += table.pairCount();
                        fallbackConstants += plan.fallbacks;
                    }
                    methods += classMethods;
                    predicates += classPredicates;
                    mbaPredicates += classMba;
                    bogusPops += classBogusPops;
                    entryShuffles += classEntryShuffles;
                    crossClassPredicates += classCross;
                    branches += classBranches;
                    deadBlocks += classDead;
                    junkBlocks += classJunk;
                    transposed += classTransposed;
                    reordered += classReordered;
                    bogusRanges += classBogus;
                    intervalPredicates += classInterval;
                    tablePredicates += classTable;
                    differentialBranches += classDifferential;
                    irreducibleEntries += classIrreducible;
                    analyzerMethods += classAnalyzerMethods;
                    analyzerLoops += classAnalyzerLoops;
                    analyzerSites += classAnalyzerSites;
                    classes++;
                } else {

                    skipNoMethods++;
                    if (holder) {
                        group.established = false;
                    }
                }
            } catch (RuntimeException e) {
                node.methods = new ArrayList<MethodNode>(savedMethods);
                node.fields = new ArrayList<FieldNode>(savedFields);
                if (holder) {
                    group.established = false;
                }
                skipRollback++;
                skipped += classMethods;
                context.log().debug("flow-obfuscation: rolled back class %s: %s", node.name, e.toString());
            }
        }
        context.stats().add("flow.methods", methods);
        context.stats().add("flow.classes", classes);

        context.stats().add("flow.classes.total", totalClasses);
        context.stats().text("flow.coverage", classes + "/" + totalClasses);
        context.stats().add("flow.skip.helper", skipHelper);
        context.stats().add("flow.skip.rule", skipRule);
        context.stats().add("flow.skip.shape", skipShape);
        context.stats().add("flow.skip.annotation", skipAnnotation);
        context.stats().add("flow.skip.noMethods", skipNoMethods);
        context.stats().add("flow.skip.rollback", skipRollback);
        context.stats().add("flow.methodsSkipped", skipped + ineligible);
        context.stats().add("flow.methods.total", totalMethods);
        context.stats().text("flow.methodCoverage", methods + "/" + totalMethods);
        if (totalMethods > 0) {

            int methodPercent = (int) Math.round(methods * 100.0 / totalMethods);
            context.stats().add("flow.methodCoveragePercent", methodPercent);

            context.log().info("flow-obfuscation: method coverage %d%% (%d/%d methods; "
                    + "%d/%d classes)", Integer.valueOf(methodPercent), Integer.valueOf(methods),
                    Integer.valueOf(totalMethods), Integer.valueOf(classes),
                    Integer.valueOf(totalClasses));
        }
        if (totalClasses > 0) {
            int percent = (int) Math.round(classes * 100.0 / totalClasses);
            context.stats().add("flow.coveragePercent", percent);
            int minimum = context.config().optionInt("flow.minCoverage", 80);
            int required = context.config().optionInt("flow.requireCoverage", 0);
            String breakdown = "helper=" + skipHelper + " rule=" + skipRule + " shape=" + skipShape
                    + " annotation=" + skipAnnotation + " noMethods=" + skipNoMethods
                    + " rollback=" + skipRollback;

            context.log().info("flow-obfuscation: coverage %d%% classes, %d%% methods "
                    + "(%d/%d program classes, %d/%d methods; %s)",
                    Integer.valueOf(percent), Integer.valueOf(totalMethods > 0
                            ? (int) Math.round(methods * 100.0 / totalMethods) : 100),
                    Integer.valueOf(classes), Integer.valueOf(totalClasses),
                    Integer.valueOf(methods), Integer.valueOf(totalMethods), breakdown);
            if (required > 0 && percent < required) {
                throw new IllegalStateException("flow-obfuscation: coverage " + percent + "% ("
                        + classes + "/" + totalClasses + ") is below flow.requireCoverage="
                        + required + "% (" + breakdown + ")");
            }
            if (percent < minimum) {
                context.log().warn("flow-obfuscation: coverage %d%% (%d/%d program classes); "
                        + "untouched classes keep their plain control flow (%s). Raise the coverage "
                        + "or set flow.requireCoverage to make this fatal.",
                        Integer.valueOf(percent), Integer.valueOf(classes),
                        Integer.valueOf(totalClasses), breakdown);
            }
        }
        context.stats().add("flow.predicates", predicates);
        context.stats().add("flow.branches.inverted", branches);
        context.stats().add("flow.deadBlocks", deadBlocks);
        context.stats().add("flow.junkBlocks", junkBlocks);
        context.stats().add("flow.transposed", transposed);
        context.stats().add("flow.reordered.blocks", reordered);
        context.stats().add("flow.bogusRanges", bogusRanges);
        context.stats().add("flow.intervalPredicates", intervalPredicates);
        context.stats().add("flow.tablePredicates", tablePredicates);
        context.stats().add("flow.mbaPredicates", mbaPredicates);
        context.stats().add("flow.bogusPops", bogusPops);
        context.stats().add("flow.entryShuffles", entryShuffles);
        context.stats().add("flow.crossClassPredicates", crossClassPredicates);
        context.stats().add("flow.differentialBranches", differentialBranches);

        context.stats().add("flow.irreducibleEntries", irreducibleEntries);

        context.stats().add("flow.rangePredicates", intervalPredicates);
        context.stats().add("flow.hashPredicates", tablePredicates);
        context.stats().add("flow.aggressive", aggressive ? 1 : 0);
        context.stats().add("flow.skipped", skipped);
        context.stats().add("flow.ineligible", ineligible);

        context.stats().add("flow.runtimeTables", runtimeTables);
        context.stats().add("flow.runtimeTableClasses", runtimeTableClasses);
        context.stats().add("flow.runtimeTablePairs", maskedConstants);
        context.stats().add("flow.crossClassHosts", crossClassHosts.hostCount());
        context.stats().add("flow.crossClassPairs", crossClassHosts.pairCount());
        context.stats().add("flow.maskedConstants", maskedConstants);
        context.stats().add("flow.fallbackConstants", fallbackConstants);
        context.stats().text("flow.tableMode", tableMode);
        context.stats().text("flow.table", tableMode);

        int groupCount = 0;
        int groupFields = 0;
        int accessorCount = 0;
        Set<String> predicateTypes = new LinkedHashSet<String>();
        StringBuilder typeMix = new StringBuilder();
        for (FlowGroup candidate : groups.values()) {
            if (!candidate.established) {
                continue;
            }
            ClassNode holderNode = context.classes().getClass(candidate.holder);
            if (holderNode == null || !hasField(holderNode, candidate.fieldName)) {
                continue;
            }
            groupCount++;
            groupFields++;
            accessorCount += countAccessors(holderNode, candidate);
            predicateTypes.add(candidate.fieldType);
            if (typeMix.length() > 0) {
                typeMix.append(',');
            }
            typeMix.append(typeLabel(candidate.fieldType)).append('=')
                    .append(candidate.predicates);
        }
        context.stats().add("flow.groups", groupCount);
        context.stats().add("flow.groupFields", groupFields);
        context.stats().add("flow.accessors", accessorCount);
        context.stats().add("flow.predicateTypes", predicateTypes.size());
        context.stats().text("flow.predicateTypeMix",
                typeMix.length() == 0 ? "none" : typeMix.toString());
        context.stats().add("flow.analyzer.methods", analyzerMethods);
        context.stats().add("flow.analyzer.loops", analyzerLoops);
        context.stats().add("flow.analyzer.anchors", analyzerSites);
        context.stats().add("otp.enabled", otpClass != null ? 1 : 0);
        if (otpClass != null) {
            context.stats().add("otp.methods", otpMethods);
            context.log().info("otp: one-time state advances at the entry of %d protected methods",
                    otpMethods);
        }
        if (reducedClasses > 0) {
            context.stats().add("flow.reduced.classes", reducedClasses);
            context.stats().add("flow.reduced.methods", reducedMethods);
        }
        context.log().info("flow-obfuscation[%s]: %d methods across %d classes, %d predicates "
                        + "(%d interval, %d table, %d differential), %d branches inverted, "
                        + "%d dead blocks, %d junk blocks, %d transposed blocks (%d rescheduled), "
                        + "%d bogus exception ranges, %d irreducible entries, "
                        + "%d runtime tables / %d masked constants (table=%s) "
                        + "(%d verification skips, %d classes kept conservative)",
                level, methods, classes, predicates, intervalPredicates, tablePredicates,
                differentialBranches, branches, deadBlocks, junkBlocks, transposed, reordered,
                bogusRanges, irreducibleEntries, runtimeTables, maskedConstants, tableMode, skipped,
                reducedClasses);
    }

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

    private static int conservativeTransform(PassContext context, ClassNode node, GuardPlan plan,
                                             int maxInstructions, MethodGate gate,
                                             String otpClass, FlowGroup group,
                                             boolean useAnalyzer) {
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
                Result result = transformMethod(context, node, work, plan,
                        false, false, maxInstructions, false, false, false, otpClass,
                        group, useAnalyzer);
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
            materializeGroup(node, group);
            addFieldInit(node, plan);
            plan.materialize(node);
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
                                          GuardPlan plan, boolean normal,
                                          boolean aggressive, int maxInstructions,
                                          boolean transpose, boolean bogusRanges,
                                          boolean allowJunk, String otpClass,
                                          FlowGroup group, boolean useAnalyzer) {
        Result result = new Result();
        int budget = Math.max(48, maxInstructions - method.instructions.size());
        int spent = 0;

        if (normal) {
            int inverted = invertBranches(context, method, aggressive, budget - spent);
            result.inverted = inverted;
            spent += inverted * 4;
        }

        Frame<BasicValue>[] frames = normal ? analyse(owner.name, method) : null;

        MethodFlowAnalyzer analyzer = null;
        if (frames != null && useAnalyzer) {
            analyzer = MethodFlowAnalyzer.of(owner.name, method, frames);
        }

        int used = nextFreeLocal(method);
        int carrier = -1;

        if (normal || aggressive || otpClass != null) {
            carrier = used++;
            method.maxLocals = Math.max(method.maxLocals, used);
        }
        int mbaSlotX = -1;
        int mbaSlotY = -1;
        if (carrier >= 0 && context.config().optionBool("flow.mbaPredicates", true)) {
            mbaSlotX = used++;
            mbaSlotY = used++;
            method.maxLocals = Math.max(method.maxLocals, used);
        }
        InsnList prelude = new InsnList();
        if (carrier >= 0) {
            emitCarrierInit(context, prelude, carrier, otpClass);
        }
        if (emitGuard(context, prelude, plan, group, context.random().nextInt(4) == 0)) {
            result.crossClassPredicates++;
        }
        result.predicates++;
        if (otpClass != null && carrier >= 0) {

            emitDifferentialBranch(context, prelude, carrier, aggressive);
            result.predicates++;
            result.differentialBranches++;
        }
        if (carrier >= 0 && (normal || aggressive)) {
            emitOpaqueTrue(context, prelude, plan, carrier, aggressive, result, mbaSlotX, mbaSlotY);
            result.predicates++;
        }
        if (aggressive && carrier >= 0) {
            emitOpaqueTrueLong(context, prelude, plan, carrier, result);
            result.predicates++;
            emitOpaqueTrue(context, prelude, plan, carrier, true, result, mbaSlotX, mbaSlotY);
            result.predicates++;
        }
        method.instructions.insert(prelude);

        if (frames != null && (normal || aggressive)) {
            int limit = aggressive ? 8 : 5;
            List<AbstractInsnNode> anchors = selectAnchors(method, frames, limit, context,
                    analyzer, result);
            for (AbstractInsnNode anchor : anchors) {
                if (spent >= budget) {
                    break;
                }

                InsnList block = new InsnList();
                if (emitGuard(context, block, plan, group, context.random().nextInt(4) == 0)) {
                    result.crossClassPredicates++;
                }
                block.add(opaqueBranchesOverJunk(context, plan, carrier, aggressive, result,
                        mbaSlotX, mbaSlotY));
                if (anchor instanceof LabelNode) {
                    method.instructions.insert(anchor, block);
                } else {
                    method.instructions.insertBefore(anchor, block);
                }
                result.deadBlocks++;
                spent += block.size();
            }
        }

        Frame<BasicValue>[] junkFrames = analyse(owner.name, method);
        int junkBudget = aggressive ? Math.min(16, method.instructions.size() / 6 + 2)
                : Math.min(6, method.instructions.size() / 12 + 1);
        AbstractInsnNode[] snapshot = method.instructions.toArray();
        boolean[] unsafe = junkFrames == null ? null
                : unsafeJunkSites(method, snapshot, junkFrames);
        int inserted = 0;
        int guard = snapshot.length * 4 + 16;
        while (allowJunk && unsafe != null && inserted < junkBudget && spent < budget && guard-- > 0) {

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

        int bogusPops = 0;
        BogusPop bogusPop = new BogusPop(owner);
        if (allowJunk && unsafe != null && context.config().optionBool("flow.bogusPops", false)) {
            int bogusBudget = aggressive ? 8 : 3;
            int bogusGuard = snapshot.length * 2 + 8;
            while (bogusPops < bogusBudget && spent < budget && bogusGuard-- > 0) {
                int index = context.random().nextInt(snapshot.length);
                if (unsafe[index] || junkFrames[index] == null) {
                    continue;
                }
                Frame<BasicValue> frame = junkFrames[index];
                int depth = Math.min(frame.getStackSize(), aggressive ? 3 : 2);
                if (depth <= 0) {
                    continue;
                }
                InsnList bogus = new InsnList();
                for (int i = 0; i < depth; i++) {
                    Type type = frame.getStack(frame.getStackSize() - 1 - i).getType();
                    if (type == null || !BogusPop.supported(type)) {
                        bogus = null;
                        break;
                    }
                    bogus.add(bogusPop.generateDummyPop(type,
                            context.random().nextLong() ^ (long) index));
                }
                if (bogus == null) {
                    continue;
                }
                method.instructions.insertBefore(snapshot[index], bogus);
                bogusPops++;
                spent += bogus.size();
            }
        }
        result.bogusPops = bogusPops;

        result.maxStack = 12;
        result.transformed = true;
        if (result.maxStack > method.maxStack) {
            method.maxStack = result.maxStack;
        }

        if (context.config().optionBool("flow.entryShuffle", false)) {
            if (emitEntryShuffle(context, method, carrier)) {
                result.entryShuffles++;
            }
        }

        boolean reorder = context.config().optionBool("flow.reorder", false);
        if (reorder) {
            int scheduled = reorderBlocks(context, owner.name, method, Math.max(1, budget / 6));
            result.reordered = scheduled;
            result.transposed += scheduled;
        }
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

        if (carrier >= 0 && context.config().optionBool("flow.irreducible", true)) {
            result.irreducible += addIrreducibleEntry(context, owner.name, method, carrier, plan);
        }

        if (bogusRanges) {
            result.bogusRanges += addBogusRanges(context, method, aggressive);
        }
        return result;
    }

    private static void emitCarrierInit(PassContext context, InsnList out, int carrier, String otpClass) {
        if (otpClass != null) {

            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, otpClass, "carrier", "()I", false));
            out.add(new VarInsnNode(Opcodes.ISTORE, carrier));
            return;
        }
        int seed = nonZero(context.random().nextInt());
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "nanoTime", "()J", false));
        out.add(new InsnNode(Opcodes.L2I));
        AsmUtil.pushInt(out, seed);
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, carrier));
    }

    private static void emitDifferentialBranch(PassContext context, InsnList out, int carrier,
                                               boolean aggressive) {
        LabelNode setPath = new LabelNode();
        LabelNode join = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
        out.add(new InsnNode(Opcodes.ICONST_1));
        out.add(new InsnNode(Opcodes.IAND));
        out.add(new JumpInsnNode(Opcodes.IFNE, setPath));
        out.add(junk(context, aggressive));
        out.add(new JumpInsnNode(Opcodes.GOTO, join));
        out.add(setPath);
        out.add(junk(context, aggressive));
        out.add(join);
    }

    private static void emitIntervalAlwaysTrue(InsnList out, LabelNode target) {
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

    private static void emitFieldGuard(PassContext context, InsnList out, GuardPlan plan,
                                       boolean tableForm) {
        LabelNode real = new LabelNode();
        out.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.owner, plan.fieldName + "0", "I"));
        if (plan.crossHost != null) {
            out.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.crossHost, plan.crossSecond, "I"));
        } else {
            out.add(new FieldInsnNode(Opcodes.GETSTATIC, plan.owner, plan.fieldName + "1", "I"));
        }
        out.add(new InsnNode(Opcodes.IXOR));
        if (tableForm && plan.expectedMask != null) {
            plan.table.emitInt(out, plan.expectedMask);
            out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, real));
        } else {
            emitIntervalAlwaysTrue(out, real);
        }
        out.add(junk(context, false));
        out.add(real);
    }

    private static void emitOpaqueTrue(PassContext context, InsnList out, GuardPlan plan,
                                       int carrier, boolean aggressive, Result result,
                                       int mbaSlotX, int mbaSlotY) {
        LabelNode real = new LabelNode();
        int variant = context.random().nextInt(4);
        if (variant == 3 && mbaSlotX >= 0) {
            out.add(AsmMba.generateMba(mbaSlotX, mbaSlotY, true,
                    context.random().nextInt(1000)));
            out.add(new JumpInsnNode(Opcodes.IFNE, real));
            result.mbaPredicates++;
            out.add(junk(context, aggressive));
            out.add(real);
            return;
        }
        if (variant == 1 && plan.relationA != null && plan.relationB != null) {
            plan.table.emitInt(out, plan.relationA);
            plan.table.emitInt(out, plan.relationB);
            out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, real));
            result.tablePredicates++;
        } else if (variant == 2) {
            emitDifferentialBranch(context, out, carrier, aggressive);
            result.differentialBranches++;
            return;
        } else {
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            if (plan.mask != null) {
                plan.table.emitInt(out, plan.mask);
                out.add(new InsnNode(Opcodes.IXOR));
            }
            emitIntervalAlwaysTrue(out, real);
            result.intervalPredicates++;
        }
        out.add(junk(context, aggressive));
        out.add(real);
    }

    private static void emitOpaqueTrueLong(PassContext context, InsnList out, GuardPlan plan,
                                           int carrier, Result result) {
        LabelNode real = new LabelNode();
        if (plan.relationA != null && plan.relationB != null) {

            plan.table.emitInt(out, plan.relationA);
            out.add(new InsnNode(Opcodes.I2L));
            AsmUtil.pushInt(out, 32);
            out.add(new InsnNode(Opcodes.LSHL));
            plan.table.emitInt(out, plan.relationB);
            out.add(new InsnNode(Opcodes.I2L));
            out.add(new InsnNode(Opcodes.LXOR));
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
            out.add(new InsnNode(Opcodes.I2L));
            out.add(new InsnNode(Opcodes.LXOR));
            out.add(new InsnNode(Opcodes.DUP2));
            AsmUtil.pushInt(out, 32);
            out.add(new InsnNode(Opcodes.LUSHR));
            out.add(new InsnNode(Opcodes.LXOR));
            out.add(new InsnNode(Opcodes.L2I));
        } else {
            out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
        }
        emitIntervalAlwaysTrue(out, real);
        result.intervalPredicates++;
        out.add(junk(context, true));
        out.add(real);
    }

    private static InsnList opaqueBranchesOverJunk(PassContext context, GuardPlan plan, int carrier,
                                                   boolean aggressive, Result result,
                                                   int mbaSlotX, int mbaSlotY) {
        InsnList block = new InsnList();
        emitOpaqueTrue(context, block, plan, carrier, aggressive, result, mbaSlotX, mbaSlotY);
        return block;
    }

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

    private static List<AbstractInsnNode> selectAnchors(MethodNode method,
                                                        Frame<BasicValue>[] frames, int limit,
                                                        PassContext context,
                                                        MethodFlowAnalyzer analyzer,
                                                        Result result) {

        List<AbstractInsnNode> candidates = new ArrayList<AbstractInsnNode>();
        if (analyzer != null) {
            candidates.addAll(analyzer.safePoints());
            if (!candidates.isEmpty()) {
                result.analyzerSites++;
                result.analyzerLoops += analyzer.loopCount();
            }
        }
        if (candidates.isEmpty()) {
            candidates = leaderCandidates(method, frames);
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

    private static List<AbstractInsnNode> leaderCandidates(MethodNode method,
                                                           Frame<BasicValue>[] frames) {
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
            if (leader == first) {
                continue;
            }
            candidates.add(leader);
        }
        return candidates;
    }

    private static boolean isReturnOrThrow(int opcode) {
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW;
    }

    private static boolean emitEntryShuffle(PassContext context, MethodNode method, int carrier) {
        if (method.instructions == null || method.instructions.size() < 12) {
            return false;
        }
        int locals = ((method.access & Opcodes.ACC_STATIC) != 0) ? 0 : 1;
        for (Type type : Type.getArgumentTypes(method.desc)) {
            locals += type.getSize();
        }
        if (locals >= method.maxLocals) {
            return false;
        }
        AbstractInsnNode first = method.instructions.getFirst();
        LabelNode bodyStart = new LabelNode();
        InsnList head = new InsnList();
        Type[] localTypes = new Type[method.maxLocals];
        AbstractInsnNode[] snapshot = method.instructions.toArray();
        for (AbstractInsnNode insn : snapshot) {
            if (!(insn instanceof VarInsnNode)) {
                continue;
            }
            VarInsnNode var = (VarInsnNode) insn;
            int opcode = var.getOpcode();
            Type type = null;
            if (opcode == Opcodes.ILOAD || opcode == Opcodes.ISTORE) {
                type = Type.INT_TYPE;
            } else if (opcode == Opcodes.LLOAD || opcode == Opcodes.LSTORE) {
                type = Type.LONG_TYPE;
            } else if (opcode == Opcodes.FLOAD || opcode == Opcodes.FSTORE) {
                type = Type.FLOAT_TYPE;
            } else if (opcode == Opcodes.DLOAD || opcode == Opcodes.DSTORE) {
                type = Type.DOUBLE_TYPE;
            } else if (opcode == Opcodes.ALOAD || opcode == Opcodes.ASTORE) {
                type = Type.getObjectType("java/lang/Object");
            }
            if (type != null && var.var < localTypes.length && localTypes[var.var] == null) {
                localTypes[var.var] = type;
            }
        }
        int initialized = 0;
        for (int slot = locals; slot < method.maxLocals; slot++) {
            Type type = localTypes[slot];
            if (type == null || slot == carrier) {
                continue;
            }
            pushDefault(head, type);
            head.add(new VarInsnNode(storeOpcode(type), slot));
            initialized++;
            if (type.getSize() == 2 && slot + 1 < method.maxLocals) {
                localTypes[slot + 1] = null;
                slot++;
            }
        }
        if (initialized == 0) {
            return false;
        }
        head.add(new JumpInsnNode(Opcodes.GOTO, bodyStart));
        method.instructions.insertBefore(first, bodyStart);
        method.instructions.insertBefore(bodyStart, head);
        method.maxStack = Math.max(method.maxStack, 2);
        return true;
    }

    private static void pushDefault(InsnList out, Type type) {
        switch (type.getSort()) {
            case Type.LONG:
                out.add(new InsnNode(Opcodes.LCONST_0));
                return;
            case Type.FLOAT:
                out.add(new InsnNode(Opcodes.FCONST_0));
                return;
            case Type.DOUBLE:
                out.add(new InsnNode(Opcodes.DCONST_0));
                return;
            case Type.ARRAY:
            case Type.OBJECT:
                out.add(new InsnNode(Opcodes.ACONST_NULL));
                return;
            default:
                out.add(new InsnNode(Opcodes.ICONST_0));
        }
    }

    private static int storeOpcode(Type type) {
        switch (type.getSort()) {
            case Type.LONG:
                return Opcodes.LSTORE;
            case Type.FLOAT:
                return Opcodes.FSTORE;
            case Type.DOUBLE:
                return Opcodes.DSTORE;
            case Type.ARRAY:
            case Type.OBJECT:
                return Opcodes.ASTORE;
            default:
                return Opcodes.ISTORE;
        }
    }

    private static int reorderBlocks(PassContext context, String owner, MethodNode method, int maxBlocks) {
        if (maxBlocks <= 0 || method.instructions == null) {
            return 0;
        }
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<BasicValue>(new BasicInterpreter()).analyzeAndComputeMaxs(owner, method);
        } catch (AnalyzerException e) {
            return 0;
        } catch (RuntimeException e) {
            return 0;
        }
        AbstractInsnNode[] insns = method.instructions.toArray();
        if (insns.length < 12 || frames.length != insns.length) {
            return 0;
        }
        java.util.IdentityHashMap<AbstractInsnNode, Integer> positions =
                new java.util.IdentityHashMap<AbstractInsnNode, Integer>();
        for (int i = 0; i < insns.length; i++) {
            positions.put(insns[i], Integer.valueOf(i));
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
        int[] blockOf = new int[insns.length];
        for (int b = 0; b < blocks.size(); b++) {
            Block block = blocks.get(b);
            for (int i = block.start; i < block.end && i < blockOf.length; i++) {
                blockOf[i] = b;
            }
        }
        List<Integer> movable = new ArrayList<Integer>();
        for (int b = 1; b < blocks.size(); b++) {
            Block block = blocks.get(b);
            if (block.firstReal < 0 || block.tryBoundary) {
                continue;
            }
            int size = block.lastReal - block.firstReal + 1;
            if (size < 1 || size > 48) {
                continue;
            }
            if (frames[block.firstReal] == null || frames[block.firstReal].getStackSize() != 0) {
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
            boolean monitor = false;
            for (int i = block.start; i < block.end; i++) {
                int opcode = insns[i].getOpcode();
                if (opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
                    monitor = true;
                    break;
                }
            }
            if (monitor) {
                continue;
            }
            movable.add(Integer.valueOf(b));
        }
        if (movable.size() < 2) {
            return 0;
        }
        java.util.Collections.shuffle(movable, context.random());
        int limit = Math.min(Math.min(movable.size(), maxBlocks), 8);
        List<Integer> chosen = new ArrayList<Integer>(movable.subList(0, limit));
        java.util.IdentityHashMap<AbstractInsnNode, LabelNode> labels =
                new java.util.IdentityHashMap<AbstractInsnNode, LabelNode>();
        Set<Integer> chosenBlocks = new HashSet<Integer>(chosen);
        int moved = 0;
        for (Integer index : chosen) {
            Block block = blocks.get(index.intValue());
            LabelNode label = labelFor(method, insns[block.start], labels);
            List<AbstractInsnNode> toMove = new ArrayList<AbstractInsnNode>();
            toMove.add(label);
            for (int i = block.start; i < block.end; i++) {
                if (insns[i] != label) {
                    toMove.add(insns[i]);
                }
            }

            AbstractInsnNode previous = null;
            int previousIndex = -1;
            for (int i = block.start - 1; i >= 0; i--) {
                if (insns[i].getOpcode() >= 0) {
                    previous = insns[i];
                    previousIndex = i;
                    break;
                }
            }
            boolean predecessorMoved = previousIndex >= 0
                    && chosenBlocks.contains(Integer.valueOf(blockOf[previousIndex]));
            if (previous != null && !predecessorMoved && !endsWithoutFallthrough(previous)) {
                method.instructions.insertBefore(label, new JumpInsnNode(Opcodes.GOTO, label));
            }

            AbstractInsnNode trailing = null;
            if (block.lastReal >= 0 && !endsWithoutFallthrough(insns[block.lastReal])
                    && index.intValue() + 1 < blocks.size()) {
                Block next = blocks.get(index.intValue() + 1);
                trailing = new JumpInsnNode(Opcodes.GOTO,
                        labelFor(method, insns[next.start], labels));
            }
            for (AbstractInsnNode node : toMove) {
                method.instructions.remove(node);
            }
            for (AbstractInsnNode node : toMove) {
                method.instructions.add(node);
            }
            if (trailing != null) {
                method.instructions.add(trailing);
            }
            moved++;
        }
        return moved;
    }

    private static LabelNode labelFor(MethodNode method, AbstractInsnNode node,
                                      java.util.IdentityHashMap<AbstractInsnNode, LabelNode> cache) {
        LabelNode cached = cache.get(node);
        if (cached != null) {
            return cached;
        }
        LabelNode label;
        if (node instanceof LabelNode) {
            label = (LabelNode) node;
        } else {
            label = new LabelNode();
            method.instructions.insertBefore(node, label);
        }
        cache.put(node, label);
        return label;
    }

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

    private static int addIrreducibleEntry(PassContext context, String owner, MethodNode method,
                                           int carrier, GuardPlan plan) {
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<BasicValue>(new BasicInterpreter()).analyzeAndComputeMaxs(owner, method);
        } catch (AnalyzerException e) {
            return 0;
        } catch (RuntimeException e) {
            return 0;
        }
        AbstractInsnNode[] insns = method.instructions.toArray();
        if (insns.length < 24 || frames.length != insns.length) {
            return 0;
        }
        int insertIndex = -1;
        for (int i = 0; i < insns.length; i++) {
            if (insns[i].getOpcode() == Opcodes.ISTORE
                    && ((VarInsnNode) insns[i]).var == carrier) {
                insertIndex = i + 1;
                break;
            }
        }
        if (insertIndex < 0 || insertIndex >= insns.length) {
            return 0;
        }
        Frame<BasicValue> entryFrame = frames[insertIndex];
        if (entryFrame == null || entryFrame.getStackSize() != 0) {
            return 0;
        }
        int lastReal = -1;
        for (int i = 0; i < insns.length; i++) {
            if (insns[i].getOpcode() >= 0) {
                lastReal = i;
            }
        }

        if (lastReal < 0 || !endsWithoutFallthrough(insns[lastReal])) {
            return 0;
        }
        LabelNode first = new LabelNode();
        LabelNode second = new LabelNode();
        InsnList cycle = new InsnList();
        cycle.add(first);
        cycle.add(junk(context, false));
        cycle.add(new JumpInsnNode(Opcodes.GOTO, second));
        cycle.add(second);
        cycle.add(junk(context, false));
        cycle.add(new JumpInsnNode(Opcodes.GOTO, first));
        method.instructions.insert(insns[lastReal], cycle);

        InsnList entries = new InsnList();
        if (plan != null && plan.deadRelation != null) {

            emitTableDeadEdge(entries, plan, 0x1657, first);
            emitTableDeadEdge(entries, plan, 0x2B8F, second);
        } else {

            emitDeadEdge(entries, carrier, 7, 9, first);
            emitDeadEdge(entries, carrier, 15, 16, second);
        }
        method.instructions.insertBefore(insns[insertIndex], entries);
        return 1;
    }

    private static void emitTableDeadEdge(InsnList out, GuardPlan plan, int offset, LabelNode target) {
        plan.table.emitInt(out, plan.deadRelation);
        AsmUtil.pushInt(out, plan.deadRelationValue ^ offset);
        out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, target));
    }

    private static void emitDeadEdge(InsnList out, int carrier, int mask, int value,
                                     LabelNode target) {
        out.add(new VarInsnNode(Opcodes.ILOAD, carrier));
        AsmUtil.pushInt(out, mask);
        out.add(new InsnNode(Opcodes.IAND));
        AsmUtil.pushInt(out, value);
        out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, target));
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

    private static final class Block {
        int start;
        int end;
        int firstReal = -1;
        int lastReal = -1;
        int size;
        boolean tryBoundary;
    }

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

    private static void attachCrossGuard(GuardPlan plan, CrossClassHosts hosts) {
        ClassNode owner = plan.context.classes().getClass(plan.owner);
        if (plan.field1 == null) {
            return;
        }
        int secondConstant = plan.field1.value();
        CrossClass cross = hosts.crossClassFor(owner, secondConstant);
        if (cross == null) {
            return;
        }
        plan.crossHost = cross.host;
        plan.crossSecond = cross.second;
        plan.crossFirstConstant = plan.field0 == null ? secondConstant ^ plan.expected : plan.field0.value();
    }

    private static void addFieldInit(ClassNode node, GuardPlan plan) {
        String first = plan.fieldName + "0";
        String second = plan.fieldName + "1";
        boolean cross = plan.crossHost != null;
        node.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                first, "I", null, null));
        if (!cross) {
            node.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    second, "I", null, null));
        }

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
        if (cross) {
            AsmUtil.pushInt(init, plan.crossFirstConstant);
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, first, "I"));
        } else if (plan.field0 != null && plan.field1 != null) {
            plan.table.emitInt(init, plan.field0);
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, first, "I"));
            plan.table.emitInt(init, plan.field1);
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, second, "I"));
        } else {
            int slot = clinit.maxLocals;
            clinit.maxLocals = Math.max(clinit.maxLocals, slot + 1);
            emitScrambledSample(init, slot, nonZero(plan.randomSeed(0)));
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, first, "I"));
            emitScrambledSample(init, slot, nonZero(plan.randomSeed(1)));
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, second, "I"));
        }
        clinit.instructions.insert(init);
        clinit.maxStack = Math.max(clinit.maxStack, 4);
    }

    private static void emitScrambledSample(InsnList out, int slot, int seed) {
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "nanoTime", "()J", false));
        out.add(new InsnNode(Opcodes.L2I));
        AsmUtil.pushInt(out, seed);
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, slot));
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        AsmUtil.pushInt(out, 13);
        out.add(new InsnNode(Opcodes.ISHL));
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, slot));
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        AsmUtil.pushInt(out, 17);
        out.add(new InsnNode(Opcodes.IUSHR));
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, slot));
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
        AsmUtil.pushInt(out, 5);
        out.add(new InsnNode(Opcodes.ISHL));
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, slot));
        out.add(new VarInsnNode(Opcodes.ILOAD, slot));
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

    private static Map<String, FlowGroup> selectGroups(PassContext context) {
        Map<String, List<ClassNode>> buckets = new LinkedHashMap<String, List<ClassNode>>();
        for (ClassNode node : context.classes().classes().values()) {
            if (!transformable(context, node)) {
                continue;
            }
            String key = groupKey(context, node.name);
            List<ClassNode> bucket = buckets.get(key);
            if (bucket == null) {
                bucket = new ArrayList<ClassNode>();
                buckets.put(key, bucket);
            }
            bucket.add(node);
        }
        Map<String, FlowGroup> groups = new LinkedHashMap<String, FlowGroup>();
        for (Map.Entry<String, List<ClassNode>> entry : buckets.entrySet()) {
            List<ClassNode> bucket = entry.getValue();
            if (bucket.isEmpty()) {
                continue;
            }
            groups.put(entry.getKey(), new FlowGroup(context, entry.getKey(), bucket.get(0)));
        }
        return groups;
    }

    private static boolean transformable(PassContext context, ClassNode node) {
        if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
            return false;
        }
        if (context.rules().skipBodyTransform(node.name) || !context.rules().transformClass(node)) {
            return false;
        }
        if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                || "module-info".equals(node.name)) {
            return false;
        }
        Boolean enabled = AsmUtil.annotationBoolean(node.invisibleAnnotations, ANNOTATION, "enabled");
        if (enabled == null) {
            enabled = AsmUtil.annotationBoolean(node.visibleAnnotations, ANNOTATION, "enabled");
        }
        return !Boolean.FALSE.equals(enabled);
    }

    private static String groupKey(PassContext context, String internalName) {
        int slash = internalName.lastIndexOf('/');
        if (slash < 0) {
            return "";
        }
        String scope = context.config().option("flow.groupScope", "package");
        if ("root".equalsIgnoreCase(scope)) {
            int first = internalName.indexOf('/');
            return first < 0 ? "" : internalName.substring(0, first);
        }
        return internalName.substring(0, slash);
    }

    private static boolean emitGuard(PassContext context, InsnList out, GuardPlan plan, FlowGroup group,
                                  boolean tableForm) {
        if (plan.crossHost != null) {
            emitFieldGuard(context, out, plan, tableForm);
            return true;
        }
        if (group != null && group.established) {
            emitAccessorGuard(context, out, group);
            return false;
        }
        emitFieldGuard(context, out, plan, tableForm);
        return false;
    }

    private static void emitAccessorGuard(PassContext context, InsnList out, FlowGroup group) {
        LabelNode real = new LabelNode();
        int variant = context.random().nextInt(3);
        if (variant == 0) {

            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, group.holder, group.getterName,
                    getterDescriptor(group.fieldType), false));
            out.add(new JumpInsnNode(branchIfSet(group), real));
            out.add(junk(context, false));
            out.add(real);
        } else if (variant == 1) {

            LabelNode skip = new LabelNode();
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, group.holder, group.getterName,
                    getterDescriptor(group.fieldType), false));
            out.add(new JumpInsnNode(branchIfUnset(group), skip));
            out.add(junk(context, false));
            out.add(skip);
        } else {

            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, group.holder, group.negatedGetterName,
                    "()Z", false));
            out.add(new JumpInsnNode(group.nonZeroValue ? Opcodes.IFEQ : Opcodes.IFNE, real));
            out.add(junk(context, false));
            out.add(real);
        }
        group.predicates++;
    }

    private static int branchIfSet(FlowGroup group) {
        if (isIntType(group.fieldType)) {
            return group.nonZeroValue ? Opcodes.IFNE : Opcodes.IFEQ;
        }
        return group.nonZeroValue ? Opcodes.IFNONNULL : Opcodes.IFNULL;
    }

    private static int branchIfUnset(FlowGroup group) {
        if (isIntType(group.fieldType)) {
            return group.nonZeroValue ? Opcodes.IFEQ : Opcodes.IFNE;
        }
        return group.nonZeroValue ? Opcodes.IFNULL : Opcodes.IFNONNULL;
    }

    private static boolean isIntType(String type) {
        return "I".equals(type) || "Z".equals(type);
    }

    private static String getterDescriptor(String type) {
        return "()" + type;
    }

    private static String setterDescriptor(String type) {
        return "(" + type + ")V";
    }

    private static boolean materializeGroup(ClassNode node, FlowGroup group) {
        if (group == null || !group.established || !group.holder.equals(node.name)) {
            return false;
        }
        if (hasField(node, group.fieldName)) {
            return false;
        }
        node.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                group.fieldName, group.fieldType, null, null));
        node.methods.add(groupGetter(group));
        node.methods.add(groupSetter(group));
        node.methods.add(groupNegatedGetter(group));
        MethodNode clinit = ensureClinit(node);
        InsnList init = new InsnList();
        emitGroupInit(init, group);
        clinit.instructions.insert(init);
        clinit.maxStack = Math.max(clinit.maxStack, 4);
        return true;
    }

    private static void emitGroupInit(InsnList out, FlowGroup group) {
        String type = group.fieldType;
        if ("Z".equals(type)) {
            out.add(new InsnNode(group.nonZeroValue ? Opcodes.ICONST_1 : Opcodes.ICONST_0));
        } else if ("I".equals(type)) {
            AsmUtil.pushInt(out, group.nonZeroValue ? group.intValue : 0);
        } else if ("Ljava/lang/String;".equals(type)) {
            if (group.nonZeroValue) {
                AsmUtil.pushInt(out, group.intValue);
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                        "toHexString", "(I)Ljava/lang/String;", false));
            } else {
                out.add(new InsnNode(Opcodes.ACONST_NULL));
            }
        } else if (group.nonZeroValue) {
            AsmUtil.pushInt(out, 2);
            out.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
            out.add(new InsnNode(Opcodes.DUP));
            out.add(new InsnNode(Opcodes.ICONST_0));
            AsmUtil.pushInt(out, group.intValue);
            out.add(new InsnNode(Opcodes.IASTORE));
        } else {
            out.add(new InsnNode(Opcodes.ACONST_NULL));
        }
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, group.holder, group.setterName,
                setterDescriptor(type), false));
    }

    private static MethodNode groupGetter(FlowGroup group) {
        MethodNode getter = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                group.getterName, getterDescriptor(group.fieldType), null, null);
        getter.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, group.holder,
                group.fieldName, group.fieldType));
        getter.instructions.add(new InsnNode(AsmUtil.returnOpcode(Type.getType(group.fieldType))));
        getter.maxStack = 1;
        getter.maxLocals = 0;
        return getter;
    }

    private static MethodNode groupSetter(FlowGroup group) {
        MethodNode setter = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                group.setterName, setterDescriptor(group.fieldType), null, null);
        setter.instructions.add(new VarInsnNode(AsmUtil.loadOpcode(Type.getType(group.fieldType)), 0));
        setter.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, group.holder,
                group.fieldName, group.fieldType));
        setter.instructions.add(new InsnNode(Opcodes.RETURN));
        setter.maxStack = 1;
        setter.maxLocals = 1;
        return setter;
    }

    private static MethodNode groupNegatedGetter(FlowGroup group) {
        MethodNode negated = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                group.negatedGetterName, "()Z", null, null);
        LabelNode isSet = new LabelNode();
        negated.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, group.holder,
                group.fieldName, group.fieldType));
        negated.instructions.add(new JumpInsnNode(
                isIntType(group.fieldType) ? Opcodes.IFNE : Opcodes.IFNONNULL, isSet));
        negated.instructions.add(new InsnNode(Opcodes.ICONST_1));
        negated.instructions.add(new InsnNode(Opcodes.IRETURN));
        negated.instructions.add(isSet);
        negated.instructions.add(new InsnNode(Opcodes.ICONST_0));
        negated.instructions.add(new InsnNode(Opcodes.IRETURN));
        negated.maxStack = 1;
        negated.maxLocals = 0;
        return negated;
    }

    private static MethodNode ensureClinit(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        clinit.maxStack = 1;
        node.methods.add(clinit);
        return clinit;
    }

    private static boolean hasField(ClassNode node, String name) {
        for (FieldNode field : node.fields) {
            if (field.name.equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasMethod(ClassNode node, String name) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static int countAccessors(ClassNode node, FlowGroup group) {
        int count = 0;
        if (hasMethod(node, group.getterName)) {
            count++;
        }
        if (hasMethod(node, group.setterName)) {
            count++;
        }
        if (hasMethod(node, group.negatedGetterName)) {
            count++;
        }
        return count;
    }

    private static String typeLabel(String type) {
        if ("Z".equals(type)) {
            return "boolean";
        }
        if ("I".equals(type)) {
            return "int";
        }
        if ("Ljava/lang/String;".equals(type)) {
            return "String";
        }
        return "array";
    }

    private static String uniqueName(Set<String> names, String prefix, int index) {
        String candidate = prefix + Integer.toHexString(index);
        int suffix = 0;
        while (names.contains(candidate)) {
            candidate = prefix + Integer.toHexString(index) + "$" + Integer.toHexString(suffix++);
        }
        names.add(candidate);
        return candidate;
    }

    private static final class FlowGroup {
        private static final String[] FIELD_TYPES = {
            "Z", "I", "Ljava/lang/String;", "[I",
        };

        final String key;
        final String holder;
        final String fieldName;
        final String getterName;
        final String setterName;
        final String negatedGetterName;
        final String fieldType;
        final boolean nonZeroValue;
        final int intValue;
        boolean established;
        int predicates;

        FlowGroup(PassContext context, String key, ClassNode holder) {
            this.key = key;
            this.holder = holder.name;
            this.fieldType = FIELD_TYPES[context.random().nextInt(FIELD_TYPES.length)];
            this.nonZeroValue = context.random().nextBoolean();
            this.intValue = nonZero(context.random().nextInt());
            Set<String> names = new HashSet<String>();
            for (FieldNode field : holder.fields) {
                names.add(field.name);
            }
            for (MethodNode method : holder.methods) {
                names.add(method.name);
            }
            this.fieldName = uniqueName(names, "z$g", 0);
            this.getterName = uniqueName(names, "z$g", 1);
            this.setterName = uniqueName(names, "z$g", 2);
            this.negatedGetterName = uniqueName(names, "z$g", 3);
        }
    }

    private static final class GuardPlan {
        final PassContext context;
        final RuntimeTable table;
        final String owner;
        final String fieldName;
        final int expected;
        String crossHost;
        String crossSecond;
        int crossFirstConstant;
        final RuntimeTable.Pair field0;
        final RuntimeTable.Pair field1;
        final RuntimeTable.Pair expectedMask;
        final RuntimeTable.Pair relationA;
        final RuntimeTable.Pair relationB;
        final RuntimeTable.Pair mask;
        final RuntimeTable.Pair deadRelation;
        final int deadRelationValue;
        int fallbacks;

        GuardPlan(PassContext context, RuntimeTable table, String owner, String fieldName,
                  int expected) {
            this.context = context;
            this.table = table;
            this.owner = owner;
            this.fieldName = fieldName;
            this.expected = expected;
            int firstValue = nonZero(context.random().nextInt());
            this.field0 = table.pair(firstValue);
            this.field1 = table.pair(firstValue ^ expected);
            this.expectedMask = table.pair(expected);
            int relationValue = context.random().nextInt();
            this.relationA = table.pair(relationValue);
            this.relationB = table.pair(relationValue);
            this.mask = table.pair(nonZero(context.random().nextInt()));
            int deadValue = nonZero(context.random().nextInt());
            this.deadRelationValue = deadValue;
            this.deadRelation = table.pair(deadValue);
            if (field0 == null || field1 == null) {
                fallbacks++;
            }
            if (expectedMask == null) {
                fallbacks++;
            }
            if (relationA == null || relationB == null) {
                fallbacks++;
            }
        }

        void materialize(ClassNode node) {
            table.materialize(node);
        }

        int randomSeed(int index) {
            return context.random().nextInt();
        }
    }

    private static final class CrossClassHosts {

        private final PassContext context;
        private final boolean enabled;
        private final List<ClassNode> candidates = new ArrayList<ClassNode>();
        private final Map<String, CrossClass> assigned = new LinkedHashMap<String, CrossClass>();
        private final Map<String, Integer> nextIds = new LinkedHashMap<String, Integer>();
        private final Set<String> hosts = new LinkedHashSet<String>();

        CrossClassHosts(PassContext context, boolean enabled) {
            this.context = context;
            this.enabled = enabled;
            if (!enabled) {
                return;
            }
            List<String> names = new ArrayList<String>();
            for (ClassNode node : context.classes().classes().values()) {
                if (transformable(context, node)) {
                    names.add(node.name);
                }
            }
            Collections.sort(names);
            for (String name : names) {
                ClassNode node = context.classes().getClass(name);
                if (node != null) {
                    candidates.add(node);
                }
            }
        }

        boolean isEnabled() {
            return enabled;
        }

        int hostCount() {
            return hosts.size();
        }

        int pairCount() {
            return assigned.size();
        }

        void prepare(ClassNode owner) {
            crossClassFor(owner, 0);
        }

        int[] crossClassFieldIds(ClassNode owner) {
            CrossClass fields = crossClassFor(owner, 0);
            return fields == null ? null : new int[] { fields.firstId, fields.secondId };
        }

        CrossClass crossClassFor(ClassNode owner, int secondValue) {
            if (!enabled || owner == null || candidates.size() < 2) {
                return null;
            }
            CrossClass cached = assigned.get(owner.name);
            if (cached != null) {
                return cached;
            }
            int size = candidates.size();
            int index = -1;
            for (int i = 0; i < size; i++) {
                if (candidates.get(i).name.equals(owner.name)) {
                    index = i;
                    break;
                }
            }
            int salt = (owner.name.hashCode() ^ (int) context.config().seed()) & 0x7FFFFFFF;
            int start = index < 0 ? salt % size : (index + 1 + salt % size) % size;
            ClassNode host = null;
            for (int i = 0; i < size; i++) {
                ClassNode candidate = candidates.get((start + i) % size);
                if (!candidate.name.equals(owner.name)) {
                    host = candidate;
                    break;
                }
            }
            if (host == null) {
                return null;
            }
            CrossClass created = materialize(host, secondValue);
            assigned.put(owner.name, created);
            hosts.add(host.name);
            context.log().debug("flow-obfuscation: %s reads its cross-class guard from %s.%s/"
                    + "%s", owner.name, host.name, created.first, created.second);
            return created;
        }

        private CrossClass materialize(ClassNode host, int secondValue) {
            int firstId = allocate(host);
            int secondId = allocate(host);
            String first = fieldName(firstId);
            String second = fieldName(secondId);
            MethodNode clinit = ensureClinit(host);
            int slot = nextFreeLocal(clinit);
            clinit.maxLocals = Math.max(clinit.maxLocals, slot + 1);
            InsnList init = new InsnList();
            emitScrambledSample(init, slot, nonZero(context.random().nextInt()));
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, host.name, first, "I"));
            AsmUtil.pushInt(init, secondValue);
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, host.name, second, "I"));
            clinit.instructions.insert(init);
            clinit.maxStack = Math.max(clinit.maxStack, 4);
            return new CrossClass(host.name, first, second, firstId, secondId);
        }

        CrossClass valueSlot(ClassNode owner, int value) {
            if (!enabled || owner == null || candidates.size() < 2) {
                return null;
            }
            ClassNode host = hostFor(owner);
            if (host == null) {
                return null;
            }
            int id = allocate(host);
            String name = fieldName(id);
            MethodNode clinit = ensureClinit(host);
            InsnList init = new InsnList();
            AsmUtil.pushInt(init, value);
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, host.name, name, "I"));
            clinit.instructions.insert(init);
            clinit.maxStack = Math.max(clinit.maxStack, 2);
            hosts.add(host.name);
            return new CrossClass(host.name, name, name, id, id);
        }

        private ClassNode hostFor(ClassNode owner) {
            int size = candidates.size();
            int index = -1;
            for (int i = 0; i < size; i++) {
                if (candidates.get(i).name.equals(owner.name)) {
                    index = i;
                    break;
                }
            }
            int salt = (owner.name.hashCode() ^ (int) context.config().seed()) & 0x7FFFFFFF;
            int start = index < 0 ? salt % size : (index + 1 + salt % size) % size;
            for (int i = 0; i < size; i++) {
                ClassNode candidate = candidates.get((start + i) % size);
                if (!candidate.name.equals(owner.name)) {
                    return candidate;
                }
            }
            return null;
        }

        private int allocate(ClassNode host) {
            Integer next = nextIds.get(host.name);
            int id = next == null ? 0 : next.intValue();
            String name;
            do {
                name = fieldName(id);
                id++;
            } while (hasField(host, name) || hasMethod(host, name));
            nextIds.put(host.name, Integer.valueOf(id));
            host.fields.add(new FieldNode(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    name, "I", null, null));
            return id - 1;
        }

        private static String fieldName(int id) {
            return "z$x" + Integer.toHexString(id);
        }
    }

    static final class CrossClass {
        final String host;
        final String first;
        final String second;
        final int firstId;
        final int secondId;

        CrossClass(String host, String first, String second, int firstId, int secondId) {
            this.host = host;
            this.first = first;
            this.second = second;
            this.firstId = firstId;
            this.secondId = secondId;
        }
    }

    private static final class Result {
        boolean transformed;
        int predicates;
        int inverted;
        int deadBlocks;
        int junkBlocks;
        int transposed;
        int reordered;
        int bogusRanges;
        int intervalPredicates;
        int tablePredicates;
        int mbaPredicates;
        int bogusPops;
        int entryShuffles;
        int crossClassPredicates;
        int differentialBranches;
        int irreducible;
        int analyzerSites;
        int analyzerLoops;
        int maxStack;
    }
}

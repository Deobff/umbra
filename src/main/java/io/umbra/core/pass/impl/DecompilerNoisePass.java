package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.noise.ClassNoise;
import io.umbra.core.pass.impl.noise.NoiseAttribute;
import io.umbra.core.pass.impl.noise.NoiseBudget;
import io.umbra.core.pass.impl.noise.NoiseGenerator;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InnerClassNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.ParameterNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Decompiler-noise pass: adds JVM-legal metadata that the JVM verifier ignores
 * but decompilers/analysers may mishandle (unknown attributes, inconsistent
 * debug tables, deliberately unusual generic signatures). Kept opt-out and
 * verifier-safe: classes must still load and run on JDK 8/21/26.
 *
 * <p>Levels are cumulative and controlled by
 * {@code decompilerNoise.level} (1..4, default 1). Levels 1..3 are exactly the
 * profile implemented by {@link ClassNoise} (see {@code docs/NOISE.md}); level 4
 * is the new hostile profile implemented here on top of level 3:</p>
 * <ul>
 *   <li>bigger bounded junk budgets and oversized truncated
 *       {@code SourceDebugExtension} tables;</li>
 *   <li>a bogus {@code EnclosingMethod} attribute so the class looks like a
 *       local/anonymous class to CFR/Procyon/FernFlower/JD;</li>
 *   <li>a self {@code InnerClasses} entry that makes the class look anonymous,
 *       on top of the phantom entries added at level 2;</li>
 *   <li>phantom declared exceptions (JVM does not resolve them at load/link,
 *       only {@code getExceptionTypes()} does) and duplicate/invalid
 *       {@code MethodParameters} names;</li>
 *   <li>code-only attribute names placed at method/field level with garbage
 *       payloads ({@code LocalVariableTypeTable}, {@code LineNumberTable},
 *       {@code StackMapTable}, {@code Code}, ...), additional contradictory
 *       local-variable and line-number rows, and larger junk blobs.</li>
 * </ul>
 *
 * <p>Every addition is metadata the JVM ignores at its location; known
 * attributes are never given a wrong-length payload at their legal location.
 * Output is bounded per class and for the whole archive and is deterministic
 * for a seed.</p>
 */
public final class DecompilerNoisePass implements Pass {

    private static final int LEVEL_V4 = 4;

    /** Level-4 per-class payload budget in bytes. */
    private static final int V4_PER_CLASS_BUDGET = 40960;
    /** Level-4 global payload budget in bytes. */
    private static final int V4_GLOBAL_BUDGET = 8 * 1024 * 1024;

    /** Attribute names that are code-only; unknown at class/method/field level. */
    private static final String[] CODE_ONLY_NAMES = {
            "LocalVariableTypeTable", "LineNumberTable", "LocalVariableTable", "StackMapTable",
            "Code", "MethodParameters", "AnnotationDefault"
    };
    /** Attribute names that are class-only; unknown at method/field level. */
    private static final String[] CLASS_ONLY_NAMES = {
            "SourceDebugExtension", "BootstrapMethods", "InnerClasses", "NestHost", "NestMembers",
            "EnclosingMethod", "SourceFile", "PermittedSubclasses", "Record"
    };
    /** Attribute names that are field-only; unknown at class/method level. */
    private static final String[] FIELD_ONLY_NAMES = { "ConstantValue" };

    @Override
    public String name() {
        return "decompiler-noise";
    }

    @Override
    public int order() {
        return 35;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("decompilerNoise.enabled", true);
    }

    @Override
    public void run(PassContext context) {
        int level = clampLevel(context.config().optionInt("decompilerNoise.level", 1));
        int baseLevel = Math.min(level, ClassNoise.LEVEL_HOSTILE);
        // Anti-LLM moves bodies into wrappers and skips methods that carry custom
        // attributes. If it is enabled, leave wrappable methods' attribute list
        // empty so the two features do not cancel each other.
        boolean preserveAntiLlm = context.config().antiLlm().enabled();

        // Level 1..3 keep the exact v2 profile (same budgets, same random
        // sequence). Level 4 first applies the level-3 profile with its own
        // budget and then the hostile additions with a separate budget, so the
        // stronger profile does not starve the classic one.
        NoiseBudget baseBudget = level >= LEVEL_V4
                ? new NoiseBudget(ClassNoise.perClassBudget(ClassNoise.LEVEL_HOSTILE),
                        ClassNoise.globalBudget(ClassNoise.LEVEL_HOSTILE))
                : new NoiseBudget(ClassNoise.perClassBudget(baseLevel),
                        ClassNoise.globalBudget(baseLevel));
        NoiseBudget level4Budget = level >= LEVEL_V4
                ? new NoiseBudget(V4_PER_CLASS_BUDGET, V4_GLOBAL_BUDGET) : null;

        int classes = 0;
        int attributes = 0;
        int bytes = 0;
        int level4Attributes = 0;
        int level4Bytes = 0;
        for (ClassNode node : context.classes().classes().values()) {
            if (skip(context, node)) {
                continue;
            }
            ClassNoise.Result result = ClassNoise.apply(node, baseLevel, context.random(),
                    baseBudget, preserveAntiLlm);
            boolean classTouched = result.attributes > 0;
            attributes += result.attributes;
            bytes += result.bytes;
            if (level4Budget != null) {
                V4Result extra = applyLevel4(node, context.random(), level4Budget, preserveAntiLlm);
                if (extra.attributes > 0) {
                    classTouched = true;
                    attributes += extra.attributes;
                    bytes += extra.bytes;
                    level4Attributes += extra.attributes;
                    level4Bytes += extra.bytes;
                }
            }
            if (classTouched) {
                classes++;
            }
        }

        context.stats().add("noise.level", level);
        context.stats().add("noise.classes", classes);
        context.stats().add("noise.attributes", attributes);
        context.stats().add("noise.bytes", bytes);
        if (level >= LEVEL_V4) {
            context.stats().add("noise.level4.attributes", level4Attributes);
            context.stats().add("noise.level4.bytes", level4Bytes);
        }
        context.log().info("decompiler-noise: level=%d, %d classes, %d attributes, %d bytes"
                        + (level >= LEVEL_V4 ? " (level-4: %d attributes, %d bytes)" : ""),
                level, classes, attributes, bytes, level4Attributes, level4Bytes);
    }

    /** Clamps the configured level to the supported 1..4 range. */
    static int clampLevel(int level) {
        return Math.max(1, Math.min(LEVEL_V4, level));
    }

    /** Mirrors the pass opt-out rules used by every other metadata pass. */
    private static boolean skip(PassContext context, ClassNode node) {
        if (node == null || node.name == null) {
            return true;
        }
        if ("module-info".equals(node.name) || node.name.endsWith("/module-info")) {
            // module-info has a rigid attribute set; unknown attributes are legal
            // but there is no benefit and module frameworks are picky.
            return true;
        }
        if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
            return true;
        }
        if (context.rules().skipBodyTransform(node.name)) {
            // Mixin classes and their targets must keep their exact bytecode shape.
            return true;
        }
        return !context.rules().transformClass(node);
    }

    // ------------------------------------------------------------------
    // Level 4
    // ------------------------------------------------------------------

    private static final class V4Result {
        private int attributes;
        private int bytes;
    }

    /** Applies the level-4 hostile metadata profile on top of level 3. */
    private static V4Result applyLevel4(ClassNode node, Random random, NoiseBudget budget,
                                        boolean preserveAntiLlm) {
        V4Result result = new V4Result();
        V4 v4 = new V4(node, new NoiseGenerator(random), budget, V4_PER_CLASS_BUDGET,
                preserveAntiLlm, result);
        v4.run();
        return result;
    }

    /** Picks an attribute name that is unknown at the current location. */
    private static String wrongLocationName(NoiseGenerator gen, String[]... groups) {
        int total = 0;
        for (String[] group : groups) {
            total += group.length;
        }
        if (total == 0) {
            return "Noise" + gen.tag(3, 6);
        }
        int selection = gen.nextInt(total);
        for (String[] group : groups) {
            if (selection < group.length) {
                return group[selection];
            }
            selection -= group.length;
        }
        return groups[0][0];
    }

    private static final class V4 {

        private static final int HEADER = 6;

        private final ClassNode node;
        private final NoiseGenerator gen;
        private final NoiseBudget budget;
        private final int limit;
        private final boolean preserveAntiLlm;
        private final V4Result result;
        private int used;

        V4(ClassNode node, NoiseGenerator gen, NoiseBudget budget, int limit,
           boolean preserveAntiLlm, V4Result result) {
            this.node = node;
            this.gen = gen;
            this.budget = budget;
            this.limit = limit;
            this.preserveAntiLlm = preserveAntiLlm;
            this.result = result;
        }

        void run() {
            // Structural traps first so they are never starved by the budget.
            bogusEnclosingMethod();
            innerClassDecoys();
            oversizedSourceDebug();
            classLevelTraps();
            for (FieldNode field : fields()) {
                fieldNoise(field);
            }
            for (MethodNode method : methods()) {
                methodNoise(method);
            }
            classJunk();
        }

        private List<FieldNode> fields() {
            return node.fields == null ? java.util.Collections.<FieldNode>emptyList() : node.fields;
        }

        private List<MethodNode> methods() {
            return node.methods == null ? java.util.Collections.<MethodNode>emptyList() : node.methods;
        }

        private boolean charge(int cost) {
            if (used + cost > limit) {
                return false;
            }
            if (!budget.charge(cost)) {
                return false;
            }
            used += cost;
            return true;
        }

        private List<Attribute> classAttributes() {
            if (node.attrs == null) {
                node.attrs = new ArrayList<Attribute>();
            }
            return node.attrs;
        }

        /** JVM ignores the attribute; decompilers treat the class as local/anonymous. */
        private void bogusEnclosingMethod() {
            if (node.version < Opcodes.V1_5 || node.outerClass != null) {
                return;
            }
            // The enclosing class must be resolvable: reflection and some tools
            // resolve it, and a phantom name would raise NoClassDefFoundError.
            // Using the superclass keeps the attribute loadable while still
            // making decompilers display the class as a local/anonymous class.
            String owner = node.superName == null ? "java/lang/Object" : node.superName;
            String method = gen.tag(3, 8);
            if (!charge(HEADER + owner.length() + method.length() + 4)) {
                return;
            }
            node.outerClass = owner;
            node.outerMethod = method;
            node.outerMethodDesc = "()V";
            result.attributes++;
            result.bytes += HEADER + owner.length() + method.length() + 4;
        }

        /**
         * Phantom InnerClasses rows with contradictory flags and duplicated
         * names. Deliberately no row whose inner class is this class: HotSpot's
         * {@code Class.getModifiers()} takes an inner class' flags from that row,
         * which would drop ACC_ENUM/ACC_INTERFACE and break enums at run time.
         */
        private void innerClassDecoys() {
            if (node.version < Opcodes.V1_5) {
                return;
            }
            if (node.innerClasses == null) {
                node.innerClasses = new ArrayList<InnerClassNode>();
            }
            int phantom = 2 + gen.nextInt(2);
            for (int i = 0; i < phantom; i++) {
                String inner = gen.phantomClass();
                String outer = gen.phantomClass();
                String simple = gen.chance(50) ? gen.phantomSimpleName() : null;
                int cost = HEADER + inner.length() + outer.length()
                        + (simple == null ? 0 : simple.length());
                if (!charge(cost)) {
                    return;
                }
                node.innerClasses.add(new InnerClassNode(inner, outer, simple,
                        randomInnerAccess()));
                result.attributes++;
                result.bytes += cost;
            }
            // A duplicate row for the same phantom pair with different flags is
            // legal class-file data that decompilers disagree about.
            int duplicates = gen.nextInt(2);
            for (int i = 0; i < duplicates; i++) {
                String inner = gen.phantomClass();
                String outer = gen.phantomClass();
                int cost = HEADER + inner.length() + outer.length();
                if (!charge(cost)) {
                    return;
                }
                node.innerClasses.add(new InnerClassNode(inner, outer, gen.phantomSimpleName(),
                        randomInnerAccess()));
                node.innerClasses.add(new InnerClassNode(inner, outer, null,
                        randomInnerAccess()));
                result.attributes += 2;
                result.bytes += cost * 2;
            }
        }

        private int randomInnerAccess() {
            switch (gen.nextInt(6)) {
                case 0:
                    return Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT;
                case 1:
                    return Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC;
                case 2:
                    return Opcodes.ACC_PROTECTED | Opcodes.ACC_FINAL;
                case 3:
                    return Opcodes.ACC_STATIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT;
                case 4:
                    return Opcodes.ACC_ENUM;
                default:
                    return Opcodes.ACC_SYNTHETIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL;
            }
        }

        private void oversizedSourceDebug() {
            int size = 24576 + gen.nextInt(32768);
            String debug = gen.sourceDebugExtension(size);
            if (!charge(HEADER + debug.length())) {
                return;
            }
            node.sourceDebug = debug;
            result.attributes++;
            result.bytes += HEADER + debug.length();
            String source = gen.sourceFile();
            if (charge(HEADER + source.length())) {
                node.sourceFile = source;
                result.attributes++;
                result.bytes += HEADER + source.length();
            }
        }

        private void classLevelTraps() {
            // A second class-level Code attribute plus code-only / field-only
            // attribute names at class level (unknown there, so the JVM skips them).
            namedAttribute(classAttributes(), "Code", new byte[] { 0, 0, 0, 0 });
            for (int i = 0; i < 3; i++) {
                namedAttribute(classAttributes(),
                        wrongLocationName(gen, CODE_ONLY_NAMES, FIELD_ONLY_NAMES),
                        new byte[] { 0, 0 });
            }
            int random = 2 + gen.nextInt(3);
            for (int i = 0; i < random; i++) {
                randomAttribute(classAttributes(), 64 + gen.nextInt(384));
            }
        }

        private void classJunk() {
            int remaining = limit - used;
            if (remaining <= HEADER + 64) {
                return;
            }
            randomAttribute(classAttributes(), Math.min(remaining - HEADER - 32, 8192
                    + gen.nextInt(8192)));
        }

        private void randomAttribute(List<Attribute> target, int payloadLength) {
            String name = gen.attributeName();
            int cost = HEADER + name.length() + payloadLength;
            if (!charge(cost)) {
                return;
            }
            target.add(new NoiseAttribute(name, gen.bytes(payloadLength)));
            result.attributes++;
            result.bytes += cost;
        }

        private void namedAttribute(List<Attribute> target, String name, byte[] payload) {
            int cost = HEADER + name.length() + payload.length;
            if (!charge(cost)) {
                return;
            }
            target.add(new NoiseAttribute(name, payload));
            result.attributes++;
            result.bytes += cost;
        }

        private List<Attribute> fieldAttributes(FieldNode field) {
            if (field.attrs == null) {
                field.attrs = new ArrayList<Attribute>();
            }
            return field.attrs;
        }

        private void fieldNoise(FieldNode field) {
            // Code-only / class-only attribute names on a field are unknown at
            // this location, so the JVM ignores them while parsers do not.
            for (int i = 0; i < 2; i++) {
                namedAttribute(fieldAttributes(field),
                        wrongLocationName(gen, CODE_ONLY_NAMES, CLASS_ONLY_NAMES),
                        new byte[] { 0, 0, 0, 0 });
            }
            int count = 2 + gen.nextInt(2);
            for (int i = 0; i < count; i++) {
                randomAttribute(fieldAttributes(field), 24 + gen.nextInt(96));
            }
        }

        private List<Attribute> methodAttributes(MethodNode method) {
            if (method.attrs == null) {
                method.attrs = new ArrayList<Attribute>();
            }
            return method.attrs;
        }

        private void methodNoise(MethodNode method) {
            if (method.instructions == null || method.instructions.size() == 0) {
                return;
            }
            if (method.name.startsWith("<") && method.name.contains("init")) {
                // Constructors still get metadata noise, but no phantom checked
                // exceptions: some tools inspect constructor throws aggressively.
                fakeExceptions(method, 1);
            } else {
                fakeExceptions(method, 1 + gen.nextInt(2));
            }
            duplicateParameterNames(method);
            boolean attachAttributes = !preserveAntiLlm || !antiLlmWrappable(method);
            if (attachAttributes) {
                for (int i = 0; i < 2; i++) {
                    namedAttribute(methodAttributes(method),
                            wrongLocationName(gen, CLASS_ONLY_NAMES, FIELD_ONLY_NAMES),
                            new byte[] { 0, 0, 0, 0 });
                }
                int count = 2 + gen.nextInt(2);
                for (int i = 0; i < count; i++) {
                    randomAttribute(methodAttributes(method), 32 + gen.nextInt(160));
                }
            }
            extraDebugRows(method);
        }

        private void fakeExceptions(MethodNode method, int count) {
            // Only real, resolvable JDK exception classes: reflection and the
            // launcher resolve declared exception types, so phantom names
            // would break `getExceptionTypes` and main-class validation.
            List<String> exceptions = method.exceptions == null
                    ? new ArrayList<String>() : new ArrayList<String>(method.exceptions);
            for (int i = 0; i < count; i++) {
                String exception = gen.existingException();
                if (exceptions.contains(exception)) {
                    continue;
                }
                if (!charge(HEADER + 2 + exception.length())) {
                    return;
                }
                exceptions.add(exception);
                result.attributes++;
                result.bytes += HEADER + 2 + exception.length();
            }
            method.exceptions = exceptions;
        }

        private void duplicateParameterNames(MethodNode method) {
            if (node.version < Opcodes.V1_8 || method.parameters == null
                    || method.parameters.isEmpty()) {
                return;
            }
            List<ParameterNode> parameters = new ArrayList<ParameterNode>(method.parameters);
            for (int i = 0; i < parameters.size(); i++) {
                String name = i == 0
                        ? "\u200B" + gen.tag(1, 3) + " " + gen.tag(1, 3)
                        : parameters.get(0).name;
                parameters.set(i, new ParameterNode(name, i == 0 ? 0 : 0x0010));
            }
            int cost = HEADER + 4 * parameters.size();
            if (!charge(cost)) {
                return;
            }
            method.parameters = parameters;
            result.attributes += parameters.size();
            result.bytes += cost;
        }

        private void extraDebugRows(MethodNode method) {
            List<AbstractInsnNode> real = new ArrayList<AbstractInsnNode>();
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (insn.getOpcode() >= 0) {
                    real.add(insn);
                }
            }
            if (real.isEmpty()) {
                return;
            }
            LabelNode start = new LabelNode();
            method.instructions.insert(start);
            LabelNode end = new LabelNode();
            method.instructions.add(end);
            int labelsWanted = Math.min(16, real.size());
            List<LabelNode> lineLabels = new ArrayList<LabelNode>(labelsWanted);
            int step = Math.max(1, real.size() / Math.max(1, labelsWanted));
            for (int i = 0; i < labelsWanted; i++) {
                LabelNode label = new LabelNode();
                method.instructions.insertBefore(real.get(Math.min(real.size() - 1, i * step)), label);
                lineLabels.add(label);
            }
            int lines = 48 + gen.nextInt(64);
            for (int i = 0; i < lines; i++) {
                if (!charge(4)) {
                    return;
                }
                method.instructions.add(new LineNumberNode(gen.lineNumber(),
                        lineLabels.get(gen.nextInt(lineLabels.size()))));
                result.attributes++;
            }
            if (method.maxLocals <= 0) {
                return;
            }
            List<LocalVariableNode> rows = method.localVariables == null
                    ? new ArrayList<LocalVariableNode>()
                    : new ArrayList<LocalVariableNode>(method.localVariables);
            int variables = 8 + gen.nextInt(8);
            for (int i = 0; i < variables; i++) {
                String name = gen.junkName();
                String descriptor = gen.localDescriptor();
                if (!charge(HEADER + name.length() + descriptor.length())) {
                    break;
                }
                rows.add(new LocalVariableNode(name, descriptor, null, start, end,
                        gen.nextInt(method.maxLocals)));
                result.attributes++;
            }
            method.localVariables = rows;
        }

        /** Mirrors {@code ClassNoise}'s anti-LLM eligibility check. */
        private boolean antiLlmWrappable(MethodNode method) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE
                    | Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC)) != 0) {
                return false;
            }
            if (method.name.startsWith("<")) {
                return false;
            }
            if (method.instructions == null || method.instructions.size() < 2) {
                return false;
            }
            if (method.visibleAnnotations != null && !method.visibleAnnotations.isEmpty()) {
                return false;
            }
            if (method.invisibleAnnotations != null && !method.invisibleAnnotations.isEmpty()) {
                return false;
            }
            return method.attrs == null || method.attrs.isEmpty();
        }
    }
}

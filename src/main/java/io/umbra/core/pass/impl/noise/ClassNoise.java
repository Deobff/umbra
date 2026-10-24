package io.umbra.core.pass.impl.noise;

import org.objectweb.asm.Attribute;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
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
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Applies decompiler-hostile but JVM-legal metadata to one {@link ClassNode}.
 *
 * <p>Three levels, cumulative:</p>
 * <ul>
 *   <li><b>1 - safe</b> (default): unknown class/field/method attributes,
 *       oversized truncated {@code SourceDebugExtension}, contradictory
 *       {@code LineNumberTable} rows, rewritten/confused
 *       {@code LocalVariableTable} rows and odd {@code MethodParameters}. The
 *       JVM verifier ignores all of these; class loading, verification, linking
 *       and execution are unaffected.</li>
 *   <li><b>2 - strong</b>: additionally replaces generic {@code Signature}
 *       attributes with syntactically valid signatures that reference missing
 *       classes/type variables, and adds phantom {@code InnerClasses} rows.
 *       Generic reflection on the affected members throws
 *       {@code TypeNotPresentException}/{@code GenericSignatureFormatError};
 *       the JVM itself does not resolve these attributes at load time.</li>
 *   <li><b>3 - hostile</b>: additionally adds a class-level attribute named
 *       {@code Code} (unknown at class level, ignored by the JVM, but it makes
 *       CFR silently skip the class), wrong-location method attributes, large
 *       bounded junk blobs and fake declared exceptions from the JDK (which are
 *       resolvable, so the JVM links fine).</li>
 * </ul>
 *
 * <p>Everything is bounded ({@link NoiseBudget}) and seeded through the pass'
 * {@link Random}. Attributes are never parsed back by Umbra, so malformed
 * payloads are free.</p>
 */
public final class ClassNoise {

    public static final int LEVEL_SAFE = 1;
    public static final int LEVEL_STRONG = 2;
    public static final int LEVEL_HOSTILE = 3;

    /** Per-class payload budget in bytes, indexed by level. */
    private static final int[] PER_CLASS_BUDGET = { 0, 1024, 8192, 24576 };
    /** Global payload budget in bytes, indexed by level. */
    private static final int[] GLOBAL_BUDGET = { 0, 512 * 1024, 1024 * 1024, 4 * 1024 * 1024 };

    /** Approximate bytes of an attribute header: name index, length and CP entry. */
    private static final int ATTRIBUTE_HEADER = 6;

    private static final String[] WRONG_LOCATION_METHOD_ATTRIBUTES = {
            "LineNumberTable", "StackMapTable", "LocalVariableTable", "ConstantValue", "SourceFile"
    };

    private ClassNoise() {
    }

    public static int clampLevel(int level) {
        return Math.max(LEVEL_SAFE, Math.min(LEVEL_HOSTILE, level));
    }

    public static int perClassBudget(int level) {
        return PER_CLASS_BUDGET[clampLevel(level)];
    }

    public static int globalBudget(int level) {
        return GLOBAL_BUDGET[clampLevel(level)];
    }

    /**
     * Applies metadata noise to {@code node}.
     *
     * @param preserveAntiLlm when true, methods that Umbra's anti-LLM wrapper
     *                        would be able to wrap must not receive method
     *                        attributes (the wrapper skips methods with custom
     *                        attributes); debug-table noise is still added
     */
    public static Result apply(ClassNode node, int level, Random random, NoiseBudget budget,
                               boolean preserveAntiLlm) {
        if (node == null || budget == null) {
            return new Result();
        }
        Applier applier = new Applier(node, clampLevel(level),
                new NoiseGenerator(random), budget, preserveAntiLlm);
        applier.run();
        return applier.result;
    }

    /** Per-class outcome. */
    public static final class Result {
        /** Class-file attributes added (including line-number/local/method-parameter rows). */
        public int attributes;
        /** Payload bytes charged to the budget. */
        public int bytes;
    }

    private static final class Applier {

        private final ClassNode node;
        private final int level;
        private final NoiseGenerator gen;
        private final NoiseBudget budget;
        private final int classLimit;
        private final boolean preserveAntiLlm;
        private final Result result = new Result();

        private int classUsed;

        Applier(ClassNode node, int level, NoiseGenerator gen, NoiseBudget budget,
                boolean preserveAntiLlm) {
            this.node = node;
            this.level = level;
            this.gen = gen;
            this.budget = budget;
            this.classLimit = budget.perClassLimit();
            this.preserveAntiLlm = preserveAntiLlm;
        }

        void run() {
            if (level >= LEVEL_HOSTILE) {
                // Added first so the (tiny) trap always fits the per-class budget.
                classLevelCodeTrap();
            }
            classAttributes();
            if (level >= LEVEL_STRONG) {
                // Structural noise goes before the large debug/junk blobs so it
                // is never starved by the per-class budget.
                classSignature();
                fakeInnerClasses();
            }
            sourceDebug();
            for (FieldNode field : fields()) {
                fieldNoise(field);
            }
            for (MethodNode method : methods()) {
                methodNoise(method);
            }
            if (level >= LEVEL_HOSTILE) {
                fakeDeclaredExceptions();
                largeClassJunk();
            }
            result.bytes = classUsed;
        }

        private List<FieldNode> fields() {
            return node.fields == null ? Collections.<FieldNode>emptyList() : node.fields;
        }

        private List<MethodNode> methods() {
            return node.methods == null ? Collections.<MethodNode>emptyList() : node.methods;
        }

        // ------------------------------------------------------------ budget

        private boolean charge(int cost) {
            if (classUsed + cost > classLimit) {
                return false;
            }
            if (!budget.charge(cost)) {
                return false;
            }
            classUsed += cost;
            return true;
        }

        /** Adds one random-named unknown attribute with an exact payload length. */
        private void randomAttribute(List<Attribute> target, int payloadLength) {
            String name = gen.attributeName();
            int cost = ATTRIBUTE_HEADER + name.length() + payloadLength;
            if (!charge(cost)) {
                return;
            }
            target.add(new NoiseAttribute(name, gen.bytes(payloadLength)));
            result.attributes++;
        }

        /** Adds an unknown attribute with an explicit name and payload. */
        private boolean namedAttribute(List<Attribute> target, String name,
                                       byte[] payload) {
            int cost = ATTRIBUTE_HEADER + name.length() + payload.length;
            if (!charge(cost)) {
                return false;
            }
            target.add(new NoiseAttribute(name, payload));
            result.attributes++;
            return true;
        }

        // ------------------------------------------------------- class level

        private List<Attribute> classAttributesList() {
            if (node.attrs == null) {
                node.attrs = new ArrayList<Attribute>();
            }
            return node.attrs;
        }

        private void classAttributes() {
            int count = 2 + gen.nextInt(3);
            for (int i = 0; i < count; i++) {
                randomAttribute(classAttributesList(), gen.nextInt(level >= LEVEL_STRONG ? 32 : 48));
            }
            // Guarantee at least one zero-length synthetic attribute.
            randomAttribute(classAttributesList(), 0);
        }

        private void sourceDebug() {
            int size;
            if (level >= LEVEL_HOSTILE) {
                size = 8192 + gen.nextInt(8192);
            } else if (level >= LEVEL_STRONG) {
                size = 2048 + gen.nextInt(2048);
            } else {
                size = 256 + gen.nextInt(512);
            }
            String debug = gen.sourceDebugExtension(size);
            if (charge(ATTRIBUTE_HEADER + debug.length())) {
                node.sourceDebug = debug;
                result.attributes++;
            }
            if (level >= LEVEL_HOSTILE) {
                // Replace the file name too: stack traces and decompilers show it.
                String sourceFile = gen.sourceFile();
                if (charge(ATTRIBUTE_HEADER + sourceFile.length())) {
                    node.sourceFile = sourceFile;
                    result.attributes++;
                }
            }
        }

        private void classSignature() {
            if (node.version < Opcodes.V1_5) {
                return;
            }
            String signature = gen.classSignature();
            if (charge(ATTRIBUTE_HEADER + signature.length())) {
                node.signature = signature;
                result.attributes++;
            }
        }

        private void fakeInnerClasses() {
            if (node.innerClasses == null) {
                node.innerClasses = new ArrayList<InnerClassNode>();
            }
            int count = 1 + gen.nextInt(3);
            for (int i = 0; i < count; i++) {
                String inner = gen.phantomClass();
                String outer = gen.phantomClass();
                String simple = gen.chance(60) ? gen.phantomSimpleName() : null;
                int cost = ATTRIBUTE_HEADER + inner.length() + outer.length()
                        + (simple == null ? 0 : simple.length());
                if (!charge(cost)) {
                    return;
                }
                node.innerClasses.add(new InnerClassNode(inner, outer, simple, randomClassAccess()));
                result.attributes++;
            }
        }

        private int randomClassAccess() {
            switch (gen.nextInt(6)) {
                case 0:
                    return 0;
                case 1:
                    return Opcodes.ACC_STATIC;
                case 2:
                    return Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC;
                case 3:
                    return Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC;
                case 4:
                    return Opcodes.ACC_FINAL;
                default:
                    return Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT | Opcodes.ACC_STATIC;
            }
        }

        /**
         * A class-level attribute named {@code Code}. The JVM only recognises
         * {@code Code} inside a method, so it is silently skipped there; CFR
         * (0.152) drops the whole class when it sees it.
         */
        private void classLevelCodeTrap() {
            namedAttribute(classAttributesList(), "Code", new byte[] { 0, 0, 0, 0 });
        }

        private void largeClassJunk() {
            int remaining = classLimit - classUsed;
            if (remaining <= ATTRIBUTE_HEADER + 32) {
                return;
            }
            int payload = Math.min(remaining - ATTRIBUTE_HEADER - 32, 6144 + gen.nextInt(6144));
            if (payload > 0) {
                randomAttribute(classAttributesList(), payload);
            }
        }

        private void fakeDeclaredExceptions() {
            for (MethodNode method : methods()) {
                if (method.instructions == null || method.instructions.size() == 0) {
                    continue;
                }
                List<String> exceptions = method.exceptions == null
                        ? new ArrayList<String>() : new ArrayList<String>(method.exceptions);
                int count = 1 + gen.nextInt(2);
                for (int i = 0; i < count; i++) {
                    String exception = gen.existingException();
                    if (exceptions.contains(exception)) {
                        continue;
                    }
                    if (!charge(ATTRIBUTE_HEADER + 2 + exception.length())) {
                        break;
                    }
                    exceptions.add(exception);
                    result.attributes++;
                }
                if (!exceptions.isEmpty()) {
                    method.exceptions = exceptions;
                }
            }
        }

        // ------------------------------------------------------ field level

        private List<Attribute> fieldAttributes(FieldNode field) {
            if (field.attrs == null) {
                field.attrs = new ArrayList<Attribute>();
            }
            return field.attrs;
        }

        private void fieldNoise(FieldNode field) {
            int count = level >= LEVEL_HOSTILE ? 2 + gen.nextInt(2) : gen.nextInt(2);
            for (int i = 0; i < count; i++) {
                randomAttribute(fieldAttributes(field),
                        gen.nextInt(level >= LEVEL_HOSTILE ? 24 : 12));
            }
            if (level >= LEVEL_STRONG && node.version >= Opcodes.V1_5) {
                String signature = gen.fieldSignature();
                if (charge(ATTRIBUTE_HEADER + signature.length())) {
                    field.signature = signature;
                    result.attributes++;
                }
            }
        }

        // ----------------------------------------------------- method level

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
            List<AbstractInsnNode> real = realInstructions(method);
            if (real.isEmpty()) {
                return;
            }
            boolean attachAttributes = !preserveAntiLlm || !antiLlmWrappable(method);
            if (attachAttributes) {
                int count = level >= LEVEL_HOSTILE ? 2 + gen.nextInt(2) : 1 + gen.nextInt(2);
                for (int i = 0; i < count; i++) {
                    randomAttribute(methodAttributes(method),
                            gen.nextInt(level >= LEVEL_HOSTILE ? 32 : 20));
                }
            }
            if (level >= LEVEL_STRONG && node.version >= Opcodes.V1_5) {
                // Structural noise before the cheap-but-numerous debug rows.
                String signature = gen.methodSignature();
                if (charge(ATTRIBUTE_HEADER + signature.length())) {
                    method.signature = signature;
                    result.attributes++;
                }
            }
            int labelCount = level >= LEVEL_HOSTILE ? 4 : level >= LEVEL_STRONG ? 3 : 2;
            List<LabelNode> lineLabels = insertLabelsBefore(method, real,
                    Math.min(labelCount, real.size()));
            lineNumberNoise(method, lineLabels);
            localVariableNoise(method);
            parameterNoise(method);
            if (level >= LEVEL_HOSTILE) {
                wrongLocationMethodAttributes(method);
                if (attachAttributes) {
                    largeMethodJunk(method);
                }
            }
        }

        /** Real opcode instructions of a method (labels/line numbers/frames skipped). */
        private List<AbstractInsnNode> realInstructions(MethodNode method) {
            List<AbstractInsnNode> real = new ArrayList<AbstractInsnNode>();
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn.getOpcode() >= 0) {
                    real.add(insn);
                }
            }
            return real;
        }

        /**
         * Inserts labels before existing opcodes. A {@code LineNumberTable}
         * start_pc must point at an opcode (HotSpot rejects {@code code_length}),
         * so never reference the trailing end label.
         */
        private List<LabelNode> insertLabelsBefore(MethodNode method, List<AbstractInsnNode> real,
                                                   int count) {
            List<LabelNode> labels = new ArrayList<LabelNode>(count);
            int step = Math.max(1, real.size() / Math.max(1, count));
            for (int i = 0; i < count; i++) {
                int index = Math.min(real.size() - 1, i * step);
                LabelNode label = new LabelNode();
                method.instructions.insertBefore(real.get(index), label);
                labels.add(label);
            }
            return labels;
        }

        private void lineNumberNoise(MethodNode method, List<LabelNode> labels) {
            int count;
            if (level >= LEVEL_HOSTILE) {
                count = 64 + gen.nextInt(48);
            } else if (level >= LEVEL_STRONG) {
                count = 12 + gen.nextInt(12);
            } else {
                count = 4 + gen.nextInt(5);
            }
            for (int i = 0; i < count; i++) {
                if (!charge(4)) {
                    return;
                }
                method.instructions.add(
                        new LineNumberNode(gen.lineNumber(), labels.get(gen.nextInt(labels.size()))));
                result.attributes++;
            }
        }

        /**
         * Replaces the local-variable table with contradictory rows. Descriptors
         * stay single-slot and legal, indices stay below {@code max_locals}
         * because HotSpot validates both; the JVM never matches them against the
         * actual types.
         */
        private void localVariableNoise(MethodNode method) {
            if (method.maxLocals <= 0) {
                return;
            }
            LabelNode start = new LabelNode();
            method.instructions.insert(start);
            LabelNode end = new LabelNode();
            method.instructions.add(end);
            int wanted;
            if (level >= LEVEL_HOSTILE) {
                wanted = 8 + gen.nextInt(6);
            } else if (level >= LEVEL_STRONG) {
                wanted = 3 + gen.nextInt(4);
            } else {
                wanted = 1 + gen.nextInt(3);
            }
            int count = Math.min(wanted, Math.max(1, method.maxLocals));
            List<LocalVariableNode> rows = new ArrayList<LocalVariableNode>();
            for (int i = 0; i < count; i++) {
                String name = gen.junkName();
                String descriptor = gen.localDescriptor();
                if (!charge(ATTRIBUTE_HEADER + name.length() + descriptor.length())) {
                    break;
                }
                rows.add(new LocalVariableNode(name, descriptor, null, start, end,
                        gen.nextInt(method.maxLocals)));
                result.attributes++;
            }
            if (!rows.isEmpty()) {
                method.localVariables = rows;
            }
        }

        /** Adds odd {@code MethodParameters} rows for class-file version 52+. */
        private void parameterNoise(MethodNode method) {
            if (node.version < Opcodes.V1_8) {
                return;
            }
            int argumentCount = Type.getArgumentTypes(method.desc).length;
            if (argumentCount <= 0) {
                return;
            }
            List<ParameterNode> parameters = new ArrayList<ParameterNode>();
            for (int i = 0; i < argumentCount; i++) {
                String name = level >= LEVEL_HOSTILE ? gen.weirdParameterName() : gen.junkName();
                if (!charge(ATTRIBUTE_HEADER + name.length() + 1)) {
                    break;
                }
                parameters.add(new ParameterNode(name, 0));
                result.attributes++;
            }
            if (!parameters.isEmpty()) {
                method.parameters = parameters;
            }
        }

        /**
         * Attributes that are valid only inside {@code Code} or on fields, but
         * placed on the method: the JVM ignores them at this location, parsers
         * that dispatch on the name do not.
         */
        private void wrongLocationMethodAttributes(MethodNode method) {
            int count = 2 + gen.nextInt(3);
            int[] used = new int[WRONG_LOCATION_METHOD_ATTRIBUTES.length];
            for (int i = 0; i < count; i++) {
                int index = gen.nextInt(WRONG_LOCATION_METHOD_ATTRIBUTES.length);
                if (used[index] > 0) {
                    continue;
                }
                used[index]++;
                namedAttribute(methodAttributes(method), WRONG_LOCATION_METHOD_ATTRIBUTES[index],
                        new byte[] { 0, 0, 0, 0 });
            }
        }

        private void largeMethodJunk(MethodNode method) {
            int remaining = classLimit - classUsed;
            if (remaining <= ATTRIBUTE_HEADER + 16) {
                return;
            }
            int payload = Math.min(remaining - ATTRIBUTE_HEADER - 16, 96 + gen.nextInt(320));
            if (payload > 0) {
                randomAttribute(methodAttributes(method), payload);
            }
        }

        /**
         * Mirrors the eligibility rule of {@code AntiLlmPass.wrapEligible} so
         * adding method attributes never disables an anti-LLM wrapper.
         */
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

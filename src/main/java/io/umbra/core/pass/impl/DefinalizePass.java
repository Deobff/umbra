package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.MethodGate;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.RecordComponentNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Removes {@code ACC_FINAL} from classes, methods and fields.
 *
 * <h3>Source and the gap being filled</h3>
 *
 * <p>the reference implementation ships two {@code the definalizer} transformers
 * ({@code transform/impl/misc/} and {@code transform/impl/string/}) that are
 * byte-for-byte the same file and whose body is an empty {@code InsnList} plus a
 * TODO ({@code docs/port/SPEC-skid.md} section 20.1): neither one ever clears a
 * flag, and neither is registered. What survives is their design note, which
 * this pass implements:</p>
 *
 * <blockquote>a {@code static final} primitive field that is a compile-time
 * constant never gets assigned in {@code <clinit>}, so drop the final flag, drop
 * the {@code ConstantValue} attribute and assign the value from
 * {@code <clinit>} instead.</blockquote>
 *
 * <p>That last part is not cosmetic. The JVM seeds a field from its
 * {@code ConstantValue} attribute before {@code <clinit>} runs; clearing the
 * attribute without emitting the store would silently turn every
 * {@code static final int LIMIT = 4096} into {@code 0}. So a field whose
 * constant is moved has exactly one of two outcomes: the migrated
 * {@code <clinit>} verifies and the value is emitted there, or nothing about
 * that class is touched at all.</p>
 *
 * <h3>What is deliberately left final</h3>
 *
 * <ul>
 *   <li>records and sealed classes (a record's components are its ABI; a sealed
 *       class's {@code PermittedSubclasses} attribute enumerates its children and
 *       a definalised hierarchy is not worth the risk) - whole class skipped;</li>
 *   <li>enum constants and anything else carrying {@code ACC_ENUM};</li>
 *   <li>interfaces and annotations (their fields are constants by definition);</li>
 *   <li>module descriptors, generated runtime helpers, frozen classes and
 *       anything a rule or {@code @Keep} protects.</li>
 * </ul>
 *
 * <p>The pass runs at order 39, before member shuffling, so the field order it
 * reads for the migrated {@code <clinit>} is still the declaration order and the
 * output stays byte-identical for a given seed.</p>
 */
public final class DefinalizePass implements Pass {

    private static final String KEEP_DESC = "Lio/umbra/annotations/Keep;";

    @Override
    public String name() {
        return "definalize";
    }

    @Override
    public int order() {
        return 39;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().optionBool("definalize.enabled", false);
    }

    @Override
    public void run(PassContext context) {
        boolean doClass = context.config().optionBool("definalize.class", true);
        boolean doMethod = context.config().optionBool("definalize.method", true);
        boolean doField = context.config().optionBool("definalize.field", true);

        long classesFinal = 0L;
        long methodsFinal = 0L;
        long fieldsFinal = 0L;
        long skippedRecord = 0L;
        long skippedEnum = 0L;
        long skippedKeep = 0L;
        long skippedInterface = 0L;
        long skippedModule = 0L;
        long skippedSealed = 0L;
        long skippedRule = 0L;
        long skippedVerify = 0L;
        long skipRollback = 0L;
        MethodGate gate = new MethodGate(context);

        List<ClassNode> candidates = new ArrayList<ClassNode>(context.classes().classes().values());
        for (ClassNode node : candidates) {
            if (context.classes().isGenerated(node.name) || context.classes().isFrozen(node.name)) {
                skippedRule++;
                continue;
            }
            if ("module-info".equals(node.name) || node.name.endsWith("/module-info")
                    || (node.access & Opcodes.ACC_MODULE) != 0) {
                // A module descriptor is the one class file whose access flags the
                // engine itself rewrites; nothing here may touch it.
                skippedModule++;
                continue;
            }
            if (context.rules().skipBodyTransform(node.name) || !context.rules().transformClass(node)) {
                skippedRule++;
                continue;
            }
            if ((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) {
                skippedInterface++;
                continue;
            }
            if (isRecord(node)) {
                skippedRecord++;
                continue;
            }
            if (node.permittedSubclasses != null) {
                skippedSealed++;
                continue;
            }
            if (AsmUtil.hasAnnotation(node, KEEP_DESC) || context.rules().hasKeepAnnotation(node)) {
                skippedKeep++;
                continue;
            }

            boolean enumType = "java/lang/Enum".equals(node.name)
                    || "java/lang/Enum".equals(node.superName);

            List<FieldNode> fieldsToClear = new ArrayList<FieldNode>();
            List<FieldNode> movedConstants = new ArrayList<FieldNode>();
            if (doField) {
                for (FieldNode field : node.fields) {
                    if ((field.access & Opcodes.ACC_FINAL) == 0) {
                        continue;
                    }
                    if (enumType || (field.access & Opcodes.ACC_ENUM) != 0) {
                        skippedEnum++;
                        continue;
                    }
                    if (isRecordComponent(node, field)) {
                        skippedRecord++;
                        continue;
                    }
                    if (AsmUtil.hasAnnotation(field, KEEP_DESC)
                            || context.rules().hasKeepAnnotation(field)
                            || context.rules().keepField(node.name, field)) {
                        skippedKeep++;
                        continue;
                    }
                    if (field.value != null && (field.access & Opcodes.ACC_STATIC) != 0) {
                        movedConstants.add(field);
                    }
                    fieldsToClear.add(field);
                }
            }

            List<MethodNode> methodsToClear = new ArrayList<MethodNode>();
            if (doMethod) {
                for (MethodNode method : node.methods) {
                    if ((method.access & Opcodes.ACC_FINAL) == 0) {
                        continue;
                    }
                    if (method.name.startsWith("<")) {
                        continue;
                    }
                    if (AsmUtil.hasAnnotation(method, KEEP_DESC)
                            || context.rules().hasKeepAnnotation(method)
                            || context.rules().keepMethod(node.name, method)) {
                        skippedKeep++;
                        continue;
                    }
                    methodsToClear.add(method);
                }
            }

            // Stage the migrated <clinit> and prove it verifies before any flag is
            // touched: a half-applied definalise would drop the ConstantValue and
            // leave the field at its type default.
            MethodNode stagedClinit = null;
            MethodNode existingClinit = null;
            boolean brokenClinit = false;
            if (!movedConstants.isEmpty()) {
                for (MethodNode method : node.methods) {
                    if (!"<clinit>".equals(method.name)) {
                        continue;
                    }
                    if ("()V".equals(method.desc)) {
                        existingClinit = method;
                    } else {
                        // A <clinit> with any other descriptor is already malformed;
                        // adding a second one would make the class unloadable.
                        brokenClinit = true;
                    }
                    break;
                }
                if (brokenClinit) {
                    skippedVerify++;
                    continue;
                }
                stagedClinit = existingClinit == null
                        ? emptyClinit() : MethodGate.copy(existingClinit);
                InsnList head = new InsnList();
                for (FieldNode field : movedConstants) {
                    AsmUtil.push(head, field.value);
                    head.add(new FieldInsnNode(Opcodes.PUTSTATIC, node.name, field.name,
                            field.desc));
                }
                stagedClinit.instructions.insert(head);
                stagedClinit.maxStack = Math.max(stagedClinit.maxStack, 2);
                if (!gate.verify(node, stagedClinit)) {
                    skippedVerify++;
                    context.log().debug("definalize: skipped %s: migrated <clinit> does not verify",
                            node.name);
                    continue;
                }
            }

            try {
                for (FieldNode field : fieldsToClear) {
                    field.access &= ~Opcodes.ACC_FINAL;
                    fieldsFinal++;
                }
                for (FieldNode field : movedConstants) {
                    field.value = null;
                }
                for (MethodNode method : methodsToClear) {
                    method.access &= ~Opcodes.ACC_FINAL;
                    methodsFinal++;
                }
                if (doClass && (node.access & Opcodes.ACC_FINAL) != 0) {
                    node.access &= ~Opcodes.ACC_FINAL;
                    classesFinal++;
                }
                if (stagedClinit != null) {
                    if (existingClinit == null) {
                        node.methods.add(stagedClinit);
                    } else {
                        // Same reason as everywhere else a gate-verified body is
                        // installed: the verified copy's ASM Label objects belong to
                        // the writer that verified them, so the final serialisation
                        // gets a fresh copy instead.
                        MethodGate.commit(existingClinit, MethodGate.copy(stagedClinit));
                    }
                }
            } catch (RuntimeException failure) {
                skipRollback++;
                context.log().debug("definalize: rolled back class %s: %s", node.name, failure);
            }
        }

        long skipped = skippedRecord + skippedEnum + skippedKeep + skippedInterface
                + skippedModule + skippedSealed + skippedRule + skippedVerify + skipRollback;
        context.stats().add("definalize.classes", classesFinal);
        context.stats().add("definalize.methods", methodsFinal);
        context.stats().add("definalize.fields", fieldsFinal);
        context.stats().add("definalize.sites", classesFinal + methodsFinal + fieldsFinal);
        context.stats().add("definalize.skipped", skipped);
        context.stats().add("definalize.skipped.record", skippedRecord);
        context.stats().add("definalize.skipped.enum", skippedEnum);
        context.stats().add("definalize.skipped.keep", skippedKeep);
        context.stats().add("definalize.skipped.interface", skippedInterface);
        context.stats().add("definalize.skipped.module", skippedModule);
        context.stats().add("definalize.skipped.sealed", skippedSealed);
        context.stats().add("definalize.skipped.rule", skippedRule);
        context.stats().add("definalize.skipped.verify", skippedVerify);
        context.stats().add("definalize.skip.rollback", skipRollback);
        context.log().info("definalize: cleared final on %d classes, %d methods, %d fields "
                        + "(class=%s method=%s field=%s); skipped %d (%d record, %d enum, "
                        + "%d keep, %d interface, %d module, %d sealed, %d rule, %d verify)",
                classesFinal, methodsFinal, fieldsFinal, Boolean.valueOf(doClass),
                Boolean.valueOf(doMethod), Boolean.valueOf(doField), skipped, skippedRecord,
                skippedEnum, skippedKeep, skippedInterface, skippedModule, skippedSealed,
                skippedRule, skippedVerify);
    }

    private static MethodNode emptyClinit() {
        MethodNode method = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 1;
        method.maxLocals = 0;
        return method;
    }

    private static boolean isRecord(ClassNode node) {
        if (node.recordComponents != null) {
            return true;
        }
        if ((node.access & Opcodes.ACC_RECORD) != 0) {
            return true;
        }
        return (node.version & 0xFFFF) >= Opcodes.V16
                && "java/lang/Record".equals(node.superName);
    }

    private static boolean isRecordComponent(ClassNode node, FieldNode field) {
        if (node.recordComponents == null) {
            return false;
        }
        for (RecordComponentNode component : node.recordComponents) {
            if (field.name.equals(component.name) && field.desc.equals(component.descriptor)) {
                return true;
            }
        }
        return false;
    }
}

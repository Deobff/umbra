package io.umbra.core.modern;

import io.umbra.core.engine.MappingSet;
import io.umbra.core.model.ClassPool;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.RecordComponentNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Keeps the class-file structures that ASM's {@code ClassRemapper} does not fully
 * own consistent with a rename: record components, {@code PermittedSubclasses},
 * {@code NestHost}/{@code NestMembers} and {@code invokedynamic} bootstrap data.
 *
 * <p>The algorithms handle (RecordComponent.resolveReferences
 * + applyFieldRenames, PermittedSubclassesAttribute.removeTrimmedSubclasses,
 * BootstrapMethodEntry.updateObjectMethodsNames, ResolvedInvokeDynamic lambda
 * following) and the default name exclusions of ZKM's NameExclusionSet.</p>
 *
 * <p>Anything this class cannot prove consistent is left untouched and counted in
 * {@link Report#skipped}: a half-renamed record or bootstrap table is worse than a
 * name that keeps its original spelling.</p>
 */
public final class ModernBytecodeSupport {

    /** ZKM NameExclusionSet: {@code *.* $deserializeLambda$(java.lang.invoke.SerializedLambda)}. */
    public static final String DESERIALIZE_LAMBDA = "$deserializeLambda$";
    /** ZKM NameExclusionSet: {@code *.* lambda$*(*)}. */
    public static final String LAMBDA_BODY_PREFIX = "lambda$";
    /** Descriptor the JVM looks {@code $deserializeLambda$} up with. */
    public static final String SERIALIZED_LAMBDA_DESCRIPTOR =
            "(Ljava/lang/invoke/SerializedLambda;)Ljava/lang/Object;";

    private static final String LAMBDA_METAFACTORY = "java/lang/invoke/LambdaMetafactory";
    private static final String STRING_CONCAT_FACTORY = "java/lang/invoke/StringConcatFactory";
    private static final String OBJECT_METHODS = "java/lang/runtime/ObjectMethods";
    private static final String MAKE_CONCAT = "makeConcat";
    private static final String MAKE_CONCAT_WITH_CONSTANTS = "makeConcatWithConstants";
    private static final String OBJECT_HASH_CODE = "hashCode";
    private static final String OBJECT_TO_STRING = "toString";

    private ModernBytecodeSupport() {
    }

    /**
     * True for the methods ZKM keeps stable by default because the JDK resolves them
     * by name at run time: {@code $deserializeLambda$(SerializedLambda)} (called by
     * {@code SerializedLambda.readResolve}) and the synthetic {@code lambda$*} bodies
     * (named inside the serialized form).
     */
    public static boolean isLambdaSerializationHook(String methodName) {
        if (methodName == null) {
            return false;
        }
        return DESERIALIZE_LAMBDA.equals(methodName) || methodName.startsWith(LAMBDA_BODY_PREFIX);
    }

    /** Counters handed back to the pass and published as {@code modern.*} statistics. */
    public static final class Report {
        /** Record components whose field and accessor were linked to one name. */
        public int records;
        /** Permitted-subclass entries dropped because the subclass is gone. */
        public int sealed;
        /** Nest entries remapped or dropped. */
        public int nest;
        /** invokedynamic call sites validated or rewritten. */
        public int indy;
        /** Structures left untouched because the mapping could not be proven safe. */
        public int skipped;
    }

    /**
     * Phase 1 (before the remap): make the backing field, the accessor and therefore
     * the record component share one name.
     *
     * <p>A record component must name a field <em>and</em> an accessor with the same
     * spelling, but Umbra maps fields and methods under different keys, so without
     * this step the two halves drift apart and {@code Class.getRecordComponents()}
     * throws {@code ClassFormatError}. The direction follows ZKM: the accessor is
     * pulled onto the field's mapped name.</p>
     */
    public static void linkRecordComponents(ClassNode node, MappingSet mappings, Report report) {
        if (node == null || node.recordComponents == null || node.recordComponents.isEmpty()) {
            return;
        }
        for (RecordComponentNode component : node.recordComponents) {
            FieldNode field = findField(node, component.name, component.descriptor);
            if (field == null) {
                report.skipped++;
                continue;
            }
            String mappedField = mappings.mappedField(field.name, field.desc);
            if (mappedField.equals(field.name)) {
                continue;
            }
            MethodNode accessor = findAccessor(node, component.name, component.descriptor);
            if (accessor == null) {
                report.skipped++;
                continue;
            }
            String mappedAccessor = mappings.mappedMethod(accessor.name, accessor.desc);
            if (!mappedAccessor.equals(mappedField)) {
                mappings.mapMethod(node.name, accessor.name, accessor.desc, mappedField);
            }
            report.records++;
        }
    }

    /**
     * Phase 2 (before the remap, while the names are still the originals): validate
     * and rewrite {@code invokedynamic} call sites.
     */
    public static void rewriteInvokeDynamic(ClassNode node, ClassPool pool, MappingSet mappings,
                                            Set<String> memberRenamable, Report report) {
        if (node == null || node.methods == null) {
            return;
        }
        for (MethodNode method : node.methods) {
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof InvokeDynamicInsnNode)) {
                    continue;
                }
                InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                Handle bootstrap = indy.bsm;
                if (bootstrap == null) {
                    report.skipped++;
                    continue;
                }
                if (LAMBDA_METAFACTORY.equals(bootstrap.getOwner())) {
                    rewriteLambdaName(indy, pool, mappings, memberRenamable, report);
                } else if (STRING_CONCAT_FACTORY.equals(bootstrap.getOwner())) {
                    // The call-site name is the bootstrap method, never a member name:
                    // only the two factory entry points are legal here, and the recipe
                    // and the appended constants must keep their exact spelling.
                    if (MAKE_CONCAT.equals(indy.name) || MAKE_CONCAT_WITH_CONSTANTS.equals(indy.name)) {
                        report.indy++;
                    } else {
                        report.skipped++;
                    }
                } else if (OBJECT_METHODS.equals(bootstrap.getOwner())) {
                    rewriteObjectMethodsRecipe(node, indy, mappings, report);
                }
            }
        }
    }

    /**
     * Phase 1b (before the remap): count the sealed/nest entries whose class name
     * actually moves. The remap itself is done by ASM; this is the observable half
     * of the statistics, the drop half is counted in {@link #rewriteAttributes}.
     */
    public static void countRemappedAttributes(ClassNode node, MappingSet mappings, Report report) {
        if (node == null) {
            return;
        }
        if (node.permittedSubclasses != null) {
            for (String subclass : node.permittedSubclasses) {
                if (!mappings.mappedClass(subclass).equals(subclass)) {
                    report.sealed++;
                }
            }
        }
        if (node.nestHostClass != null
                && !mappings.mappedClass(node.nestHostClass).equals(node.nestHostClass)) {
            report.nest++;
        }
        if (node.nestMembers != null) {
            for (String member : node.nestMembers) {
                if (!mappings.mappedClass(member).equals(member)) {
                    report.nest++;
                }
            }
        }
    }

    /**
     * Phase 2b: the compiler-generated {@code $deserializeLambda$} compares the
     * capturing class name against a string constant. ZKM follows those arguments
     * (MethodFlowAnalyzer.traceDeserializeLambdaArguments); without the same step a
     * renamed class decrypts its own old name and every deserialization ends in
     * {@code IllegalArgumentException: Invalid lambda deserialization}.
     */
    public static void rewriteDeserializeLambda(ClassNode node, MappingSet mappings, Report report) {
        if (node == null || node.methods == null) {
            return;
        }
        String mappedName = mappings.mappedClass(node.name);
        if (mappedName.equals(node.name)) {
            return;
        }
        String mappedBinary = mappedName.replace('/', '.');
        String internalBinary = node.name.replace('/', '.');
        for (MethodNode method : node.methods) {
            if (!DESERIALIZE_LAMBDA.equals(method.name) || method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof LdcInsnNode)) {
                    continue;
                }
                Object constant = ((LdcInsnNode) insn).cst;
                if (!(constant instanceof String)) {
                    continue;
                }
                String text = (String) constant;
                if (text.equals(node.name)) {
                    ((LdcInsnNode) insn).cst = mappedName;
                    report.indy++;
                } else if (text.equals(internalBinary)) {
                    ((LdcInsnNode) insn).cst = mappedBinary;
                    report.indy++;
                }
            }
        }
    }

    /**
     * Phase 3 (after the remap): drop references to classes that no longer exist.
     *
     * <p>A {@code NestHost} pointing at a removed class is a load-time failure, and a
     * {@code PermittedSubclasses} entry for a removed class makes the sealed
     * hierarchy disagree with the archive, so both are cleaned here.</p>
     */
    public static void rewriteAttributes(ClassNode node, Set<String> removedClasses, Report report) {
        if (node == null || removedClasses == null || removedClasses.isEmpty()) {
            return;
        }
        if (node.permittedSubclasses != null && !node.permittedSubclasses.isEmpty()) {
            List<String> kept = new ArrayList<String>(node.permittedSubclasses.size());
            for (String subclass : node.permittedSubclasses) {
                if (removedClasses.contains(subclass)) {
                    report.sealed++;
                } else {
                    kept.add(subclass);
                }
            }
            node.permittedSubclasses = kept.isEmpty() ? null : kept;
        }
        if (node.nestHostClass != null && removedClasses.contains(node.nestHostClass)) {
            node.nestHostClass = null;
            report.nest++;
        }
        if (node.nestMembers != null && !node.nestMembers.isEmpty()) {
            List<String> kept = new ArrayList<String>(node.nestMembers.size());
            for (String member : node.nestMembers) {
                if (removedClasses.contains(member)) {
                    report.nest++;
                } else {
                    kept.add(member);
                }
            }
            node.nestMembers = kept.isEmpty() ? null : kept;
        }
    }

    private static void rewriteLambdaName(InvokeDynamicInsnNode indy, ClassPool pool,
                                          MappingSet mappings, Set<String> memberRenamable,
                                          Report report) {
        Type returned = Type.getReturnType(indy.desc);
        if (returned.getSort() != Type.OBJECT) {
            report.skipped++;
            return;
        }
        ClassNode functionalInterface = pool.getClass(returned.getInternalName());
        if (functionalInterface == null || !memberRenamable.contains(functionalInterface.name)) {
            // JDK or kept interface: its method names never move, so the call-site
            // name must keep its original spelling.
            report.indy++;
            return;
        }
        String mapped = null;
        int matches = 0;
        for (MethodNode candidate : functionalInterface.methods) {
            if (!candidate.name.equals(indy.name)) {
                continue;
            }
            matches++;
            mapped = mappings.mappedMethod(candidate.name, candidate.desc);
        }
        if (matches != 1 || mapped == null) {
            report.skipped++;
            return;
        }
        if (!mapped.equals(indy.name)) {
            indy.name = mapped;
        }
        report.indy++;
    }

    private static void rewriteObjectMethodsRecipe(ClassNode node, InvokeDynamicInsnNode indy,
                                                   MappingSet mappings, Report report) {
        // ObjectMethods.bootstrap(Lookup, String, Type, Class<?> recordClass, String names, MethodHandle...)
        // reaches the class file as {Class, String, MethodHandle...}: the names live at index 1
        // (ZKM BootstrapMethodEntry.updateObjectMethodsNames starts at the same index).
        if (indy.bsmArgs == null || indy.bsmArgs.length < 2 || !(indy.bsmArgs[1] instanceof String)) {
            report.skipped++;
            return;
        }
        String recipe = (String) indy.bsmArgs[1];
        String[] components = recipe.split(";", -1);
        StringBuilder rebuilt = new StringBuilder(recipe.length() + 8);
        boolean changed = false;
        for (int i = 0; i < components.length; i++) {
            if (i > 0) {
                rebuilt.append(';');
            }
            String mapped = mappedComponentName(node, components[i], mappings);
            if (!mapped.equals(components[i])) {
                changed = true;
            }
            rebuilt.append(mapped);
        }
        if (changed) {
            indy.bsmArgs[1] = rebuilt.toString();
            report.records++;
        }
        report.indy++;
    }

    private static String mappedComponentName(ClassNode node, String componentName, MappingSet mappings) {
        if (node.recordComponents == null) {
            return componentName;
        }
        for (RecordComponentNode component : node.recordComponents) {
            if (!component.name.equals(componentName)) {
                continue;
            }
            FieldNode field = findField(node, component.name, component.descriptor);
            return field == null ? componentName : mappings.mappedField(field.name, field.desc);
        }
        return componentName;
    }

    private static FieldNode findField(ClassNode node, String name, String descriptor) {
        for (FieldNode field : node.fields) {
            if (field.name.equals(name) && field.desc.equals(descriptor)) {
                return field;
            }
        }
        FieldNode unique = null;
        for (FieldNode field : node.fields) {
            if (!field.desc.equals(descriptor)) {
                continue;
            }
            if (unique != null) {
                return null;
            }
            unique = field;
        }
        return unique;
    }

    private static MethodNode findAccessor(ClassNode node, String name, String descriptor) {
        String accessorDescriptor = "()" + descriptor;
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(accessorDescriptor)) {
                return method;
            }
        }
        MethodNode unique = null;
        for (MethodNode method : node.methods) {
            if (!method.desc.equals(accessorDescriptor)) {
                continue;
            }
            if (OBJECT_HASH_CODE.equals(method.name) && "()I".equals(method.desc)) {
                continue;
            }
            if (OBJECT_TO_STRING.equals(method.name) && "()Ljava/lang/String;".equals(method.desc)) {
                continue;
            }
            if (unique != null) {
                return null;
            }
            unique = method;
        }
        return unique;
    }
}

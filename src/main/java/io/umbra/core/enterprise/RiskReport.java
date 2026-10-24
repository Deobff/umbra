package io.umbra.core.enterprise;

import io.umbra.core.model.ClassPool;
import io.umbra.core.model.Hierarchy;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pre-transform risk scan used by the enterprise audit report.
 *
 * <p>The scan is deliberately conservative: it highlights constructs that
 * commonly require keep rules, but it does not claim to prove safety.</p>
 */
public final class RiskReport {

    private final int serializableClasses;
    private final int nativeMethods;
    private final int reflectionCallSites;
    private final int serviceLoaderCallSites;
    private final int moduleDescriptors;
    private final Map<String, Integer> frameworkAnnotations;
    private final List<String> suggestions;

    private RiskReport(int serializableClasses, int nativeMethods, int reflectionCallSites,
                       int serviceLoaderCallSites, int moduleDescriptors,
                       Map<String, Integer> frameworkAnnotations, List<String> suggestions) {
        this.serializableClasses = serializableClasses;
        this.nativeMethods = nativeMethods;
        this.reflectionCallSites = reflectionCallSites;
        this.serviceLoaderCallSites = serviceLoaderCallSites;
        this.moduleDescriptors = moduleDescriptors;
        this.frameworkAnnotations = frameworkAnnotations;
        this.suggestions = suggestions;
    }

    public int serializableClasses() { return serializableClasses; }
    public int nativeMethods() { return nativeMethods; }
    public int reflectionCallSites() { return reflectionCallSites; }
    public int serviceLoaderCallSites() { return serviceLoaderCallSites; }
    public int moduleDescriptors() { return moduleDescriptors; }
    public Map<String, Integer> frameworkAnnotations() { return frameworkAnnotations; }
    public List<String> suggestions() { return suggestions; }

    /** Scans the loaded program. */
    public static RiskReport scan(ClassPool pool, Hierarchy hierarchy) {
        int serializable = 0;
        int natives = 0;
        int reflection = 0;
        int serviceLoaders = 0;
        int modules = 0;
        Map<String, Integer> frameworks = new LinkedHashMap<String, Integer>();

        for (ClassNode node : pool.classes().values()) {
            if ("module-info".equals(node.name) || (node.access & Opcodes.ACC_MODULE) != 0) {
                modules++;
            }
            if (hierarchy.isAssignableFrom("java/io/Serializable", node.name)
                    || hierarchy.isAssignableFrom("java/io/Externalizable", node.name)) {
                serializable++;
            }
            collectAnnotations(node.visibleAnnotations, frameworks);
            collectAnnotations(node.invisibleAnnotations, frameworks);
            for (FieldNode field : node.fields) {
                collectAnnotations(field.visibleAnnotations, frameworks);
                collectAnnotations(field.invisibleAnnotations, frameworks);
            }
            for (MethodNode method : node.methods) {
                if ((method.access & Opcodes.ACC_NATIVE) != 0) {
                    natives++;
                }
                collectAnnotations(method.visibleAnnotations, frameworks);
                collectAnnotations(method.invisibleAnnotations, frameworks);
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode)) {
                        continue;
                    }
                    MethodInsnNode call = (MethodInsnNode) insn;
                    if ("java/lang/Class".equals(call.owner)
                            && ("forName".equals(call.name)
                            || "getDeclaredMethod".equals(call.name)
                            || "getMethod".equals(call.name)
                            || "getDeclaredField".equals(call.name)
                            || "getField".equals(call.name)
                            || "getDeclaredConstructor".equals(call.name))) {
                        reflection++;
                    } else if ("java/util/ServiceLoader".equals(call.owner) && "load".equals(call.name)) {
                        serviceLoaders++;
                    }
                }
            }
        }

        List<String> suggestions = new ArrayList<String>();
        if (serializable > 0) {
            suggestions.add("Keep serialVersionUID and Java serialization hooks; consider the "
                    + "persistence/jackson preset and explicit keep rules for serialized classes.");
        }
        if (natives > 0) {
            suggestions.add("Native methods are pinned by name; ensure JNI libraries match the output.");
        }
        if (reflection > 0) {
            suggestions.add("Add keep rules for reflectively accessed classes and members; "
                    + "review the reflection call sites listed by the audit.");
        }
        if (serviceLoaders > 0) {
            suggestions.add("Service descriptors are rewritten automatically; keep service "
                    + "interfaces that are loaded by third-party code.");
        }
        if (modules > 0) {
            suggestions.add("module-info is preserved; package names are not repackaged by default.");
        }
        if (!frameworks.isEmpty()) {
            suggestions.add("Framework annotations detected (" + frameworks.keySet()
                    + "); use the matching preset or explicit keep rules.");
        }
        if (suggestions.isEmpty()) {
            suggestions.add("No high-risk constructs detected by the heuristic scan.");
        }
        return new RiskReport(serializable, natives, reflection, serviceLoaders, modules,
                Collections.unmodifiableMap(frameworks), Collections.unmodifiableList(suggestions));
    }

    private static void collectAnnotations(List<AnnotationNode> annotations, Map<String, Integer> out) {
        if (annotations == null) {
            return;
        }
        for (AnnotationNode annotation : annotations) {
            String desc = annotation.desc;
            if (isFramework(desc)) {
                Integer count = out.get(desc);
                out.put(desc, Integer.valueOf(count == null ? 1 : count.intValue() + 1));
            }
        }
    }

    private static boolean isFramework(String desc) {
        return desc.startsWith("Lorg/springframework/")
                || desc.startsWith("Lcom/fasterxml/jackson/")
                || desc.startsWith("Ljavax/persistence/")
                || desc.startsWith("Ljakarta/persistence/")
                || desc.startsWith("Lorg/hibernate/")
                || desc.startsWith("Lio/micronaut/")
                || desc.startsWith("Lkotlin/");
    }
}

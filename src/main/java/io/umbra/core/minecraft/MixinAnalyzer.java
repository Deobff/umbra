package io.umbra.core.minecraft;

import io.umbra.core.minecraft.mixin.InjectionTargets;
import io.umbra.core.minecraft.mixin.MixinAnnotations;
import io.umbra.core.minecraft.mixin.MixinCollector;
import io.umbra.core.minecraft.mixin.MixinMemberRef;
import io.umbra.core.model.ClassPool;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Scans {@code org.spongepowered/asm/mixin} annotations across the class pool.
 *
 * <p>Implemented by the mixin-analysis owner; the detector consumes the result
 * to keep mixin classes, target classes and referenced target members, and to
 * exempt both sides from method-body rewrites. The analyzer is read-only and
 * must never throw on malformed annotation values.</p>
 *
 * <p>Rules emitted:</p>
 * <ul>
 *   <li>the mixin class itself and every {@code @Mixin} target class: exact keep
 *       glob plus a body-skip glob (Mixin patches them by name and bytecode
 *       shape);</li>
 *   <li>{@code @Shadow} fields/methods on each target, also for the de-prefixed
 *       name when the member is written as {@code shadow$name}; methods use
 *       {@code owner#name(desc)}, fields use {@code owner#name} because a field
 *       descriptor cannot be expressed in a keep rule and field names are
 *       unique within a class;</li>
 *   <li>{@code @Accessor("field")} / {@code @Invoker("method")}:
 *       {@code owner#name} (descriptor-less, so any descriptor matches);</li>
 *   <li>injection annotations ({@code @Inject}, {@code @Redirect},
 *       {@code @Modify*}, MixinExtras {@code @Wrap*},
 *       {@code @ModifyExpressionValue}, ...): {@code owner#name(desc)} for an
 *       explicit owner, otherwise one rule per mixin target. Explicit owners are
 *       also kept as classes because the annotation string names them
 *       literally;</li>
 *   <li>{@code @Overwrite}: the annotated mixin method's own name/descriptor on
 *       each target.</li>
 * </ul>
 *
 * <p>Everything is de-duplicated and sorted by {@link MixinCollector}. Known
 * blind spots: {@code refmap} remapping is not consulted, and {@code @At}
 * targets are not parsed (they reference invoked methods/fields, not the
 * injected member).</p>
 */
public final class MixinAnalyzer {

    /** Prefix Mixin accepts on shadow members ("shadow$name" shadows "name"). */
    private static final String SHADOW_PREFIX = "shadow$";

    private MixinAnalyzer() {
    }

    /** Scans every class in {@code pool}; never returns {@code null}. */
    public static MixinAnalysis analyze(ClassPool pool) {
        if (pool == null) {
            return MixinAnalysis.EMPTY;
        }
        MixinCollector collector = new MixinCollector();
        for (ClassNode node : pool.classes().values()) {
            if (node == null || node.name == null) {
                continue;
            }
            try {
                analyzeClass(node, collector);
            } catch (RuntimeException e) {
                // A corrupt annotation tree must never abort the scan.
                collector.note("skipped class " + node.name
                        + " after malformed mixin annotation data ("
                        + e.getClass().getSimpleName() + ")");
            }
        }
        return collector.build();
    }

    private static void analyzeClass(ClassNode node, MixinCollector collector) {
        AnnotationNode mixin = MixinAnnotations.find(node.visibleAnnotations,
                node.invisibleAnnotations, MixinAnnotations.MIXIN);
        if (mixin == null) {
            return;
        }

        collector.addMixin(node.name);
        collector.keepClass(node.name);
        collector.bodySkip(node.name);

        List<String> targets = new ArrayList<String>();
        targets.addAll(MixinAnnotations.classNames(mixin, "value", collector, "@Mixin(" + node.name + ")"));
        targets.addAll(MixinAnnotations.classNames(mixin, "targets", collector, "@Mixin(" + node.name + ")"));
        targets = dedupe(targets);

        for (String target : targets) {
            collector.addTarget(target);
            collector.keepClass(target);
            collector.bodySkip(target);
        }
        if (targets.isEmpty()) {
            collector.note("@Mixin without resolvable targets: " + node.name);
        }

        boolean aliasUsed = scanFields(node, targets, collector);
        aliasUsed |= scanMethods(node, targets, collector);
        if (aliasUsed) {
            collector.note("shadow$ prefix treated as shadow alias in: " + node.name);
        }
    }

    // ------------------------------------------------------------------ fields

    private static boolean scanFields(ClassNode node, List<String> targets, MixinCollector collector) {
        boolean aliasUsed = false;
        for (FieldNode field : safeFields(node)) {
            if (!MixinAnnotations.has(field.visibleAnnotations, field.invisibleAnnotations,
                    MixinAnnotations.SHADOW)) {
                continue;
            }
            if (targets.isEmpty()) {
                collector.note("@Shadow field without resolvable @Mixin targets: "
                        + node.name + "#" + field.name);
                continue;
            }
            for (String owner : targets) {
                // Field descriptors are not expressible in a keep rule
                // (DefaultRuleSet matches "name(desc)" only) and field names are
                // unique per class, so a descriptor-less rule is equivalent.
                collector.keepMember(owner, field.name, null);
                String alias = shadowAlias(field.name);
                if (alias != null) {
                    collector.keepMember(owner, alias, null);
                    aliasUsed = true;
                }
            }
        }
        return aliasUsed;
    }

    // ----------------------------------------------------------------- methods

    private static boolean scanMethods(ClassNode node, List<String> targets, MixinCollector collector) {
        boolean aliasUsed = false;
        for (MethodNode method : safeMethods(node)) {
            List<AnnotationNode> visible = method.visibleAnnotations;
            List<AnnotationNode> invisible = method.invisibleAnnotations;

            if (MixinAnnotations.has(visible, invisible, MixinAnnotations.SHADOW)) {
                if (targets.isEmpty()) {
                    collector.note("@Shadow method without resolvable @Mixin targets: "
                            + node.name + "#" + method.name);
                } else {
                    for (String owner : targets) {
                        collector.keepMember(owner, method.name, method.desc);
                        String alias = shadowAlias(method.name);
                        if (alias != null) {
                            collector.keepMember(owner, alias, method.desc);
                            aliasUsed = true;
                        }
                    }
                }
            }

            if (MixinAnnotations.has(visible, invisible, MixinAnnotations.OVERWRITE)) {
                keepMemberOnTargets(node, method.name, method.desc, targets, collector,
                        "@Overwrite");
            }

            AnnotationNode accessor = MixinAnnotations.find(visible, invisible,
                    MixinAnnotations.ACCESSOR);
            if (accessor != null) {
                handleGeneratedAccess(node, method, accessor, targets, collector, false);
            }
            AnnotationNode invoker = MixinAnnotations.find(visible, invisible,
                    MixinAnnotations.INVOKER);
            if (invoker != null) {
                handleGeneratedAccess(node, method, invoker, targets, collector, true);
            }

            for (String injectionDesc : MixinAnnotations.INJECTIONS) {
                AnnotationNode injection = MixinAnnotations.find(visible, invisible, injectionDesc);
                if (injection == null) {
                    continue;
                }
                handleInjection(node, method, injection, injectionDesc, targets, collector);
            }
        }
        return aliasUsed;
    }

    private static void handleInjection(ClassNode node, MethodNode method, AnnotationNode annotation,
                                        String annotationDesc, List<String> targets,
                                        MixinCollector collector) {
        String where = annotationName(annotationDesc) + " on " + node.name + "#" + method.name;
        Object raw = MixinAnnotations.value(annotation, "method");
        if (raw == null) {
            collector.note("injection without method target: " + where);
            return;
        }
        List<MixinMemberRef> refs = InjectionTargets.parse(raw, collector, where);
        if (refs.isEmpty()) {
            collector.note("no usable method target in " + where);
            return;
        }
        for (MixinMemberRef ref : refs) {
            if (ref.hasOwner()) {
                String owner = ref.owner();
                collector.keepMember(owner, ref.name(), ref.desc());
                // The annotation string spells the owner out, so its class name
                // and bytecode shape have to survive as well.
                collector.keepClass(owner);
                collector.bodySkip(owner);
                if (!targets.contains(owner)) {
                    collector.note("kept explicit injection owner outside @Mixin targets: " + owner);
                }
            } else if (targets.isEmpty()) {
                collector.note("injection target without owner and without @Mixin targets: " + where);
            } else {
                for (String owner : targets) {
                    collector.keepMember(owner, ref.name(), ref.desc());
                }
            }
        }
    }

    private static void handleGeneratedAccess(ClassNode node, MethodNode method,
                                              AnnotationNode annotation, List<String> targets,
                                              MixinCollector collector, boolean invoker) {
        String annotationName = invoker ? "@Invoker" : "@Accessor";
        List<String> names = MixinAnnotations.strings(annotation, "value");
        String where = node.name + "#" + method.name;
        if (names.isEmpty()) {
            String derived = invoker ? deriveInvokerTarget(method.name) : deriveAccessorTarget(method.name);
            if (derived == null) {
                collector.note(annotationName + " without value or derivable target: " + where);
                return;
            }
            names = Collections.singletonList(derived);
            collector.note(annotationName + " target derived from method name: "
                    + where + " -> " + derived);
        }
        if (targets.isEmpty()) {
            collector.note(annotationName + " without resolvable @Mixin targets: " + where);
            return;
        }
        for (String name : names) {
            if (!looksLikeMemberName(name)) {
                collector.note(annotationName + " ignores malformed target name '" + name
                        + "' in " + where);
                continue;
            }
            for (String owner : targets) {
                collector.keepMember(owner, name, null);
            }
        }
    }

    // ------------------------------------------------------------------ shared

    private static void keepMemberOnTargets(ClassNode node, String memberName, String memberDesc,
                                            List<String> targets, MixinCollector collector,
                                            String annotationName) {
        if (targets.isEmpty()) {
            collector.note(annotationName + " without resolvable @Mixin targets: "
                    + node.name + "#" + memberName);
            return;
        }
        for (String owner : targets) {
            collector.keepMember(owner, memberName, memberDesc);
        }
    }

    /** Returns the de-prefixed name for {@code shadow$foo}, else {@code null}. */
    private static String shadowAlias(String memberName) {
        if (memberName == null || !memberName.startsWith(SHADOW_PREFIX)) {
            return null;
        }
        String alias = memberName.substring(SHADOW_PREFIX.length());
        return alias.isEmpty() ? null : alias;
    }

    /** Mixin derives {@code @Accessor} targets from get/set/is method names. */
    private static String deriveAccessorTarget(String methodName) {
        String[] prefixes = { "get", "set", "is" };
        for (String prefix : prefixes) {
            if (methodName.length() > prefix.length() && methodName.startsWith(prefix)) {
                String candidate = decapitalize(methodName.substring(prefix.length()));
                if (looksLikeMemberName(candidate)) {
                    return candidate;
                }
            }
        }
        return null;
    }

    /** Mixin derives {@code @Invoker} targets by stripping the {@code call} prefix. */
    private static String deriveInvokerTarget(String methodName) {
        if (methodName.length() > 4 && methodName.startsWith("call")) {
            String candidate = decapitalize(methodName.substring(4));
            if (looksLikeMemberName(candidate)) {
                return candidate;
            }
        }
        return looksLikeMemberName(methodName) ? methodName : null;
    }

    private static String decapitalize(String name) {
        if (name.isEmpty()) {
            return name;
        }
        char first = name.charAt(0);
        if (Character.isUpperCase(first)) {
            return Character.toLowerCase(first) + name.substring(1);
        }
        return name;
    }

    private static boolean looksLikeMemberName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isJavaIdentifierPart(c) || c == '<' || c == '>') {
                continue;
            }
            return false;
        }
        return true;
    }

    private static String annotationName(String desc) {
        if (desc == null) {
            return "@?";
        }
        int slash = desc.lastIndexOf('/');
        int end = desc.endsWith(";") ? desc.length() - 1 : desc.length();
        return "@" + desc.substring(slash < 0 ? 0 : slash + 1, end);
    }

    private static List<FieldNode> safeFields(ClassNode node) {
        return node.fields == null ? Collections.<FieldNode>emptyList() : node.fields;
    }

    private static List<MethodNode> safeMethods(ClassNode node) {
        return node.methods == null ? Collections.<MethodNode>emptyList() : node.methods;
    }

    private static List<String> dedupe(List<String> values) {
        if (values.isEmpty()) {
            return values;
        }
        LinkedHashSet<String> unique = new LinkedHashSet<String>(values);
        return new ArrayList<String>(unique);
    }
}

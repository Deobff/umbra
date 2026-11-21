package io.umbra.core.minecraft;

import io.umbra.core.minecraft.mixin.InjectionTargets;
import io.umbra.core.minecraft.mixin.MixinAnnotations;
import io.umbra.core.minecraft.mixin.MixinCollector;
import io.umbra.core.minecraft.mixin.MixinMemberRef;
import io.umbra.core.minecraft.refmap.Refmap;
import io.umbra.core.model.ClassPool;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodInsnNode;
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
 * <p><strong>Refmaps (Forge 1.12-1.16 and legacy Fabric).</strong> In those
 * versions the annotation strings name a member in the pre-obfuscation
 * (MCP/SRG-source) namespace while the shipped bytecode carries the production
 * name; the refmap resource translates one into the other. Keeping only the
 * literal annotation name would therefore miss the member that actually has to
 * survive renaming. Every parsed refmap ({@link RefmapReader}) is consulted and
 * the production name is kept in addition to the literal one - never instead of
 * it - so archives without a refmap are unaffected. {@code remap = false} on
 * {@code @Mixin} or on the individual annotation suppresses the translation,
 * exactly like Mixin itself does it. Rules derived from a refmap are
 * descriptor-less on purpose: the annotation descriptor is written in the
 * pre-obfuscation namespace and may name types Umbra renames.</p>
 *
 * <p>Still not covered: {@code refmap} entries for members of classes that are
 * not in the archive (vanilla classes are never renamed by Umbra, so keeping
 * them changes nothing), and the descriptor types inside annotation strings
 * (L8 in the compatibility notes).</p>
 */
public final class MixinAnalyzer {

    private static final String SHADOW_PREFIX = "shadow$";

    private MixinAnalyzer() {
    }

    public static MixinAnalysis analyze(ClassPool pool) {
        return analyze(pool, true);
    }

    /**
     * @param useRefmap consult Mixin refmaps ({@code minecraft.refmap}, default
     *                  true); when false only the literal annotation names are
     *                  kept, which is the pre-refmap behaviour
     */
    public static MixinAnalysis analyze(ClassPool pool, boolean useRefmap) {
        if (pool == null) {
            return MixinAnalysis.EMPTY;
        }
        MixinCollector collector = new MixinCollector();
        // The refmaps are only read once the pool is known to contain mixins: a
        // normal jar (or a mod jar without mixin classes) must not pay for a
        // resource scan it cannot use.
        Refmap refmap = Refmap.EMPTY;
        boolean refmapLoaded = !useRefmap;
        if (!useRefmap) {
            collector.note("mixin refmap mapping disabled by minecraft.refmap=false");
        }
        for (ClassNode node : pool.classes().values()) {
            if (node == null || node.name == null) {
                continue;
            }
            try {
                AnnotationNode mixin = MixinAnnotations.find(node.visibleAnnotations,
                        node.invisibleAnnotations, MixinAnnotations.MIXIN);
                if (mixin == null) {
                    continue;
                }
                if (!refmapLoaded) {
                    refmap = RefmapReader.read(pool, collector);
                    refmapLoaded = true;
                }
                analyzeClass(node, mixin, refmap, collector);
            } catch (RuntimeException e) {

                collector.note("skipped class " + node.name
                        + " after malformed mixin annotation data ("
                        + e.getClass().getSimpleName() + ")");
            }
        }
        if (!refmap.isEmpty()) {
            for (String file : refmap.files()) {
                collector.refmapFile(file);
            }
            collector.note("mixin refmap: " + refmap.describe() + ", "
                    + collector.refmapHitCount()
                    + " reference(s) kept under their production name");
        }
        return collector.build();
    }

    private static void analyzeClass(ClassNode node, AnnotationNode mixin, Refmap refmap,
                                     MixinCollector collector) {
        collector.addMixin(node.name);
        collector.keepClass(node.name);
        collector.bodySkip(node.name);

        List<String> targets = new ArrayList<String>();
        targets.addAll(MixinAnnotations.classNames(mixin, "value", collector, "@Mixin(" + node.name + ")"));
        targets.addAll(MixinAnnotations.classNames(mixin, "targets", collector, "@Mixin(" + node.name + ")"));
        targets = dedupe(targets);
        boolean remap = booleanValue(MixinAnnotations.value(mixin, "remap"), true);

        for (String target : targets) {
            collector.addTarget(target);
            collector.keepClass(target);
            collector.bodySkip(target);
        }
        if (targets.isEmpty()) {
            collector.note("@Mixin without resolvable targets: " + node.name);
        }
        // The refmap data section may spell the target class in a different
        // namespace than the annotation does. The alias is the class that really
        // carries the member at runtime, so it becomes a target as well.
        if (!refmap.isEmpty()) {
            for (String target : targets) {
                String classAlias = refmap.classAlias(target);
                if (classAlias == null || classAlias.equals(target)) {
                    continue;
                }
                collector.addTarget(classAlias);
                collector.keepClass(classAlias);
                collector.bodySkip(classAlias);
                collector.note("mixin target " + target + " is aliased to " + classAlias
                        + " by the refmap data section");
            }
        }

        boolean aliasUsed = scanFields(node, targets, remap, refmap, collector);
        aliasUsed |= scanMethods(node, targets, remap, refmap, collector);
        if (aliasUsed) {
            collector.note("shadow$ prefix treated as shadow alias in: " + node.name);
        }
    }

    private static boolean scanFields(ClassNode node, List<String> targets, boolean mixinRemap,
                                      Refmap refmap, MixinCollector collector) {
        boolean aliasUsed = false;
        for (FieldNode field : safeFields(node)) {
            AnnotationNode shadow = MixinAnnotations.find(field.visibleAnnotations,
                    field.invisibleAnnotations, MixinAnnotations.SHADOW);
            if (shadow == null) {
                continue;
            }
            if (targets.isEmpty()) {
                collector.note("@Shadow field without resolvable @Mixin targets: "
                        + node.name + "#" + field.name);
                continue;
            }
            boolean remap = remapOf(shadow, mixinRemap);
            for (String owner : targets) {

                keepMember(owner, field.name, null, remap, refmap, collector);
                String alias = shadowAlias(field.name);
                if (alias != null) {
                    keepMember(owner, alias, null, remap, refmap, collector);
                    aliasUsed = true;
                }
            }
        }
        return aliasUsed;
    }

    private static boolean scanMethods(ClassNode node, List<String> targets, boolean mixinRemap,
                                       Refmap refmap, MixinCollector collector) {
        boolean aliasUsed = false;
        for (MethodNode method : safeMethods(node)) {
            List<AnnotationNode> visible = method.visibleAnnotations;
            List<AnnotationNode> invisible = method.invisibleAnnotations;

            AnnotationNode shadow = MixinAnnotations.find(visible, invisible, MixinAnnotations.SHADOW);
            if (shadow != null) {
                if (targets.isEmpty()) {
                    collector.note("@Shadow method without resolvable @Mixin targets: "
                            + node.name + "#" + method.name);
                } else {
                    boolean remap = remapOf(shadow, mixinRemap);
                    for (String owner : targets) {
                        keepMember(owner, method.name, method.desc, remap, refmap, collector);
                        String alias = shadowAlias(method.name);
                        if (alias != null) {
                            keepMember(owner, alias, method.desc, remap, refmap, collector);
                            aliasUsed = true;
                        }
                    }
                }
            }

            AnnotationNode overwrite = MixinAnnotations.find(visible, invisible,
                    MixinAnnotations.OVERWRITE);
            if (overwrite != null) {
                keepMemberOnTargets(node, method.name, method.desc, targets,
                        remapOf(overwrite, mixinRemap), refmap, collector, "@Overwrite");
            }

            AnnotationNode accessor = MixinAnnotations.find(visible, invisible,
                    MixinAnnotations.ACCESSOR);
            if (accessor != null) {
                handleGeneratedAccess(node, method, accessor, targets, mixinRemap, refmap,
                        collector, false);
            }
            AnnotationNode invoker = MixinAnnotations.find(visible, invisible,
                    MixinAnnotations.INVOKER);
            if (invoker != null) {
                handleGeneratedAccess(node, method, invoker, targets, mixinRemap, refmap,
                        collector, true);
            }

            for (String injectionDesc : MixinAnnotations.INJECTIONS) {
                AnnotationNode injection = MixinAnnotations.find(visible, invisible, injectionDesc);
                if (injection == null) {
                    continue;
                }
                handleInjection(node, method, injection, injectionDesc, targets, mixinRemap,
                        refmap, collector);
                // Fourth exclusion layer: the injected body itself references
                // target members and types by name; renaming them silently
                // breaks the injection at load time.
                keepBodyReferences(method, collector);
                break;
            }
        }
        return aliasUsed;
    }

    private static void keepBodyReferences(MethodNode method, MixinCollector collector) {
        if (method.instructions == null) {
            return;
        }
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (isPlatformOwner(call.owner)) {
                    continue;
                }
                collector.keepClass(call.owner);
                collector.keepMember(call.owner, call.name, call.desc);
            } else if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                if (isPlatformOwner(field.owner)) {
                    continue;
                }
                collector.keepClass(field.owner);
                collector.keepMember(field.owner, field.name, null);
            }
        }
    }

    private static boolean isPlatformOwner(String owner) {
        return owner == null || owner.startsWith("java/") || owner.startsWith("javax/")
                || owner.startsWith("org/spongepowered/") || owner.startsWith("io/umbra/")
                || owner.startsWith("[");
    }

    /**
     * Parses {@code @At(target = "Lowner;name()desc")} entries. Mixin resolves
     * those members by their original name after the mixin is applied, so both
     * the owner and the member name have to survive renaming. When the owner
     * carries a refmap entry, the production member name is kept as well.
     */
    private static void keepAtTargets(AnnotationNode annotation, boolean remap,
                                      Refmap refmap, MixinCollector collector) {
        Object raw = MixinAnnotations.value(annotation, "at");
        List<AnnotationNode> ats = new ArrayList<AnnotationNode>();
        if (raw instanceof AnnotationNode) {
            ats.add((AnnotationNode) raw);
        } else if (raw instanceof List) {
            for (Object item : (List<?>) raw) {
                if (item instanceof AnnotationNode) {
                    ats.add((AnnotationNode) item);
                }
            }
        }
        for (AnnotationNode at : ats) {
            Object target = MixinAnnotations.value(at, "target");
            if (!(target instanceof String)) {
                continue;
            }
            String text = ((String) target).trim();
            if (text.length() < 3 || text.charAt(0) != 'L') {
                continue;
            }
            int semi = text.indexOf(';');
            if (semi <= 1) {
                continue;
            }
            String owner = text.substring(1, semi);
            String rest = text.substring(semi + 1);
            collector.keepClass(owner);
            int paren = rest.indexOf('(');
            if (paren > 0) {
                keepMember(owner, rest.substring(0, paren).trim(), rest.substring(paren),
                        remap, refmap, collector);
            } else {
                int colon = rest.indexOf(':');
                if (colon > 0) {
                    keepMember(owner, rest.substring(0, colon).trim(), null, remap, refmap, collector);
                }
            }
        }
    }

    private static void handleInjection(ClassNode node, MethodNode method, AnnotationNode annotation,
                                        String annotationDesc, List<String> targets,
                                        boolean mixinRemap, Refmap refmap, MixinCollector collector) {
        String where = annotationName(annotationDesc) + " on " + node.name + "#" + method.name;
        boolean remap = remapOf(annotation, mixinRemap);
        keepAtTargets(annotation, remap, refmap, collector);
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
                keepMember(owner, ref.name(), ref.desc(), remap, refmap, collector);

                collector.keepClass(owner);
                collector.bodySkip(owner);
                if (!targets.contains(owner)) {
                    collector.note("kept explicit injection owner outside @Mixin targets: " + owner);
                }
            } else if (targets.isEmpty()) {
                collector.note("injection target without owner and without @Mixin targets: " + where);
            } else {
                for (String owner : targets) {
                    keepMember(owner, ref.name(), ref.desc(), remap, refmap, collector);
                }
            }
        }
    }

    private static void handleGeneratedAccess(ClassNode node, MethodNode method,
                                              AnnotationNode annotation, List<String> targets,
                                              boolean mixinRemap, Refmap refmap,
                                              MixinCollector collector, boolean invoker) {
        String annotationName = invoker ? "@Invoker" : "@Accessor";
        List<String> names = MixinAnnotations.strings(annotation, "value");
        String where = node.name + "#" + method.name;
        boolean remap = remapOf(annotation, mixinRemap);
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
                keepMember(owner, name, null, remap, refmap, collector);
            }
        }
    }

    private static void keepMemberOnTargets(ClassNode node, String memberName, String memberDesc,
                                            List<String> targets, boolean remap,
                                            Refmap refmap, MixinCollector collector,
                                            String annotationName) {
        if (targets.isEmpty()) {
            collector.note(annotationName + " without resolvable @Mixin targets: "
                    + node.name + "#" + memberName);
            return;
        }
        for (String owner : targets) {
            keepMember(owner, memberName, memberDesc, remap, refmap, collector);
        }
    }

    /**
     * Keeps one referenced member and, when a refmap applies, also the production
     * name that the refmap translates the reference to.
     *
     * <p>The literal annotation name is always kept, so an archive without a
     * refmap - or a reference the refmap does not know - behaves exactly as
     * before. The refmap-derived rule is descriptor-less (see the class
     * documentation) and the {@code data} section alias owner is kept as a class
     * when it contributes a mapping.</p>
     */
    private static void keepMember(String owner, String name, String desc, boolean remap,
                                   Refmap refmap, MixinCollector collector) {
        collector.keepMember(owner, name, desc);
        if (!remap || refmap == null || refmap.isEmpty()
                || owner == null || owner.isEmpty() || name == null || name.isEmpty()) {
            return;
        }
        for (String candidate : refmap.ownersFor(owner)) {
            int before = collector.refmapHitCount();
            for (String production : refmap.productionNames(candidate, name, desc)) {
                if (production.equals(name)) {
                    continue;
                }
                collector.keepMember(candidate, production, null);
                collector.refmapHit(candidate, name, production);
            }
            if (!candidate.equals(owner) && collector.refmapHitCount() > before) {
                collector.keepClass(candidate);
            }
        }
    }

    private static boolean remapOf(AnnotationNode annotation, boolean fallback) {
        return booleanValue(MixinAnnotations.value(annotation, "remap"), fallback);
    }

    private static boolean booleanValue(Object raw, boolean fallback) {
        return raw instanceof Boolean ? ((Boolean) raw).booleanValue() : fallback;
    }

    private static String shadowAlias(String memberName) {
        if (memberName == null || !memberName.startsWith(SHADOW_PREFIX)) {
            return null;
        }
        String alias = memberName.substring(SHADOW_PREFIX.length());
        return alias.isEmpty() ? null : alias;
    }

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

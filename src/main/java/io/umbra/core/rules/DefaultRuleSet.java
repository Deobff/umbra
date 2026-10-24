package io.umbra.core.rules;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Default {@link RuleSet} implementation.
 *
 * <p>Built-in keeps cover JDK namespaces, module descriptors, Java
 * serialization hooks, JNI natives, enum synthetic methods and the JVM entry
 * point. User patterns are Ant-style globs; {@code @annotation} entries keep
 * elements carrying the annotation.</p>
 */
public final class DefaultRuleSet implements RuleSet {

    private static final String KEEP_DESC = "Lio/umbra/annotations/Keep;";
    private static final String DO_NOT_RENAME_DESC = "Lio/umbra/annotations/DoNotRename;";

    private final List<Glob> keepClasses = new ArrayList<Glob>();
    private final List<Glob> softKeepClasses = new ArrayList<Glob>();
    private final List<String> keepAnnotations = new ArrayList<String>();
    private final List<Glob> keepAnnotationGlobs = new ArrayList<Glob>();
    private final List<MemberRule> keepMembers = new ArrayList<MemberRule>();
    private final List<Glob> bodySkipGlobs = new ArrayList<Glob>();
    private final boolean keepPublicApi;
    private final boolean softKeepPublicApi;

    public DefaultRuleSet(List<String> keep, List<String> softKeep, boolean keepPublicApi,
                          boolean softKeepPublicApi) {
        this.keepPublicApi = keepPublicApi;
        this.softKeepPublicApi = softKeepPublicApi;
        this.keepAnnotations.add(KEEP_DESC);
        for (String pattern : keep) {
            addKeep(pattern);
        }
        for (String pattern : softKeep) {
            addSoftKeep(pattern);
        }
    }

    /** Adds a keep rule discovered at analysis time (reflection, service loading, ...). */
    public void addKeepRule(String raw) {
        addKeep(raw);
    }

    /**
     * Marks classes matching {@code pattern} as body-transform-free (for
     * example Minecraft Mixin target classes). Accepts the same Ant-style globs
     * as keep rules.
     */
    public void addBodySkipGlob(String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) {
            return;
        }
        bodySkipGlobs.add(new Glob(pattern.trim()));
    }

    @Override
    public boolean skipBodyTransform(String owner) {
        for (Glob glob : bodySkipGlobs) {
            if (glob.matches(owner)) {
                return true;
            }
        }
        return false;
    }

    private void addKeep(String raw) {
        if (raw == null) {
            return;
        }
        String pattern = raw.trim();
        if (pattern.isEmpty()) {
            return;
        }
        if (pattern.startsWith("@")) {
            String internal = Glob.normalize(pattern.substring(1));
            keepAnnotations.add("L" + internal + ";");
            if (internal.indexOf('*') >= 0 || internal.indexOf('?') >= 0) {
                keepAnnotationGlobs.add(new Glob(internal));
            }
        } else if (pattern.indexOf('#') > 0) {
            keepMembers.add(MemberRule.parse(pattern));
        } else {
            keepClasses.add(new Glob(pattern));
        }
    }

    private void addSoftKeep(String raw) {
        if (raw == null) {
            return;
        }
        String pattern = raw.trim();
        if (!pattern.isEmpty()) {
            softKeepClasses.add(new Glob(pattern));
        }
    }

    @Override
    public boolean keepClass(ClassNode node) {
        if (isImplicitKeep(node.name)) {
            return true;
        }
        if (keepPublicApi && (node.access & Opcodes.ACC_PUBLIC) != 0) {
            return true;
        }
        if (hasKeepAnnotation(node.visibleAnnotations) || hasKeepAnnotation(node.invisibleAnnotations)) {
            return true;
        }
        for (Glob glob : keepClasses) {
            if (glob.matches(node.name)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean keepClass(String internalName) {
        if (isImplicitKeep(internalName)) {
            return true;
        }
        for (Glob glob : keepClasses) {
            if (glob.matches(internalName)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean softKeepClass(ClassNode node) {
        if (softKeepPublicApi && (node.access & Opcodes.ACC_PUBLIC) != 0) {
            return true;
        }
        for (Glob glob : softKeepClasses) {
            if (glob.matches(node.name)) {
                return true;
            }
        }
        return hasAnnotation(node.invisibleAnnotations, DO_NOT_RENAME_DESC)
                || hasAnnotation(node.visibleAnnotations, DO_NOT_RENAME_DESC);
    }

    @Override
    public boolean transformClass(ClassNode node) {
        return !keepClass(node);
    }

    @Override
    public boolean allowClassRename(ClassNode node) {
        return !keepClass(node) && !softKeepClass(node) && !isImplicitKeep(node.name);
    }

    @Override
    public boolean keepMethod(String owner, MethodNode method) {
        if (keepClass(owner)) {
            return true;
        }
        if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) {
            return true;
        }
        if ("main".equals(method.name) && "([Ljava/lang/String;)V".equals(method.desc)) {
            return true;
        }
        // Java agent entry points are resolved by exact method name from the
        // manifest Premain-Class/Agent-Class, so they must never be renamed
        // (the class itself is remapped and the manifest rewritten later).
        if (("premain".equals(method.name) || "agentmain".equals(method.name))
                && ("(Ljava/lang/String;Ljava/lang/instrument/Instrumentation;)V".equals(method.desc)
                || "(Ljava/lang/String;)V".equals(method.desc))) {
            return true;
        }
        if ("finalize".equals(method.name) && "()V".equals(method.desc)) {
            return true;
        }
        if ((method.access & Opcodes.ACC_NATIVE) != 0) {
            return true;
        }
        if ((keepPublicApi || softKeepPublicApi)
                && (method.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0) {
            return true;
        }
        if (isSerializationHook(method.name)) {
            return true;
        }
        if (hasKeepAnnotation(method.visibleAnnotations) || hasKeepAnnotation(method.invisibleAnnotations)) {
            return true;
        }
        if (hasAnnotation(method.visibleAnnotations, DO_NOT_RENAME_DESC)
                || hasAnnotation(method.invisibleAnnotations, DO_NOT_RENAME_DESC)) {
            return true;
        }
        if (hasForeignAnnotation(method.visibleAnnotations) || hasForeignAnnotation(method.invisibleAnnotations)) {
            // Framework-visible annotations frequently imply reflective lookup.
            return true;
        }
        for (MemberRule rule : keepMembers) {
            if (rule.matches(owner, method.name, method.desc)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean keepField(String owner, FieldNode field) {
        if (keepClass(owner)) {
            return true;
        }
        if ("serialVersionUID".equals(field.name)) {
            return true;
        }
        if ((field.access & Opcodes.ACC_ENUM) != 0) {
            return true;
        }
        if ((keepPublicApi || softKeepPublicApi)
                && (field.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0) {
            return true;
        }
        if (hasKeepAnnotation(field.visibleAnnotations) || hasKeepAnnotation(field.invisibleAnnotations)) {
            return true;
        }
        if (hasAnnotation(field.visibleAnnotations, DO_NOT_RENAME_DESC)
                || hasAnnotation(field.invisibleAnnotations, DO_NOT_RENAME_DESC)) {
            return true;
        }
        if (hasForeignAnnotation(field.visibleAnnotations) || hasForeignAnnotation(field.invisibleAnnotations)) {
            return true;
        }
        for (MemberRule rule : keepMembers) {
            if (rule.matches(owner, field.name, field.desc)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean allowMethodRename(String owner, MethodNode method) {
        return !keepMethod(owner, method);
    }

    @Override
    public boolean allowFieldRename(String owner, FieldNode field) {
        return !keepField(owner, field);
    }

    @Override
    public boolean hasKeepAnnotation(ClassNode node) {
        return hasAnnotation(node.visibleAnnotations, KEEP_DESC)
                || hasAnnotation(node.invisibleAnnotations, KEEP_DESC);
    }

    @Override
    public boolean hasKeepAnnotation(MethodNode method) {
        return hasAnnotation(method.visibleAnnotations, KEEP_DESC)
                || hasAnnotation(method.invisibleAnnotations, KEEP_DESC);
    }

    @Override
    public boolean hasKeepAnnotation(FieldNode field) {
        return hasAnnotation(field.visibleAnnotations, KEEP_DESC)
                || hasAnnotation(field.invisibleAnnotations, KEEP_DESC);
    }

    private static boolean isImplicitKeep(String name) {
        return name.startsWith("java/")
                || name.startsWith("javax/")
                || name.startsWith("jdk/")
                || name.startsWith("sun/")
                || name.startsWith("com/sun/")
                || name.startsWith("org/w3c/")
                || name.startsWith("org/xml/")
                || name.startsWith("io/umbra/annotations/")
                || name.equals("module-info")
                || name.endsWith("/module-info")
                || name.endsWith("/package-info");
    }

    private static boolean isSerializationHook(String name) {
        return "readObject".equals(name)
                || "writeObject".equals(name)
                || "readResolve".equals(name)
                || "writeReplace".equals(name)
                || "readObjectNoData".equals(name);
    }

    private static boolean hasAnnotation(List<AnnotationNode> annotations, String desc) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (desc.equals(annotation.desc)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasKeepAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (keepAnnotations.contains(annotation.desc)) {
                return true;
            }
            String desc = annotation.desc;
            if (desc.length() > 2 && desc.charAt(0) == 'L' && desc.charAt(desc.length() - 1) == ';') {
                String internal = desc.substring(1, desc.length() - 1);
                for (Glob glob : keepAnnotationGlobs) {
                    if (glob.matches(internal)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean hasForeignAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            String desc = annotation.desc;
            if (!desc.startsWith("Lio/umbra/annotations/")) {
                return true;
            }
        }
        return false;
    }

    private static final class MemberRule {
        private final Glob owner;
        private final String name;
        private final String desc;

        private MemberRule(Glob owner, String name, String desc) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
        }

        static MemberRule parse(String pattern) {
            int hash = pattern.indexOf('#');
            Glob owner = new Glob(pattern.substring(0, hash));
            String member = pattern.substring(hash + 1).trim();
            String name = member;
            String desc = null;
            int paren = member.indexOf('(');
            if (paren >= 0) {
                name = member.substring(0, paren).trim();
                desc = member.substring(paren).trim();
            }
            return new MemberRule(owner, name, desc);
        }

        boolean matches(String ownerName, String memberName, String memberDesc) {
            if (!owner.matches(ownerName)) {
                return false;
            }
            if (!"*".equals(name) && !name.equals(memberName)) {
                return false;
            }
            return desc == null || desc.equals(memberDesc);
        }
    }
}

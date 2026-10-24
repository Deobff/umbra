package io.umbra.core.rules;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Keep/transform policy consumed by every pass.
 *
 * <p>Three levels are supported:</p>
 * <ul>
 *   <li><b>keep</b> — no transforms and no renaming</li>
 *   <li><b>soft keep</b> — transforms may run, but names are preserved</li>
 *   <li><b>normal</b> — fully transformable</li>
 * </ul>
 */
public interface RuleSet {

    boolean keepClass(ClassNode node);

    boolean keepClass(String internalName);

    boolean softKeepClass(ClassNode node);

    boolean transformClass(ClassNode node);

    boolean allowClassRename(ClassNode node);

    boolean keepMethod(String owner, MethodNode method);

    boolean keepField(String owner, FieldNode field);

    boolean allowMethodRename(String owner, MethodNode method);

    boolean allowFieldRename(String owner, FieldNode field);

    /**
     * True when method bodies of {@code owner} must not be rewritten.
     *
     * <p>Used by mod-container adaptation (Minecraft Mixin target classes and
     * other classes whose exact bytecode shape is referenced from outside):
     * renaming, metadata cleanup and constant encryption may still run, but
     * control-flow, virtualization, native conversion, reference hiding and
     * other body-shape transforms are skipped.</p>
     */
    default boolean skipBodyTransform(String owner) {
        return false;
    }

    /** True when the class or member carries {@code io.umbra.annotations.Keep}. */
    boolean hasKeepAnnotation(ClassNode node);

    boolean hasKeepAnnotation(MethodNode method);

    boolean hasKeepAnnotation(FieldNode field);
}

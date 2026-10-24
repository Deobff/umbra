package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

/** Removes source/debug metadata according to {@code debugInfo} settings. */
public final class DebugInfoPass implements Pass {

    private static final String KOTLIN_METADATA = "Lkotlin/Metadata;";
    private static final String KOTLIN_DEBUG = "Lkotlin/coroutines/jvm/internal/DebugMetadata;";

    @Override
    public String name() {
        return "debug-info";
    }

    @Override
    public int order() {
        return 30;
    }

    @Override
    public boolean enabled(PassContext context) {
        return context.config().debug().enabled();
    }

    @Override
    public void run(PassContext context) {
        UmbraConfig.DebugOptions options = context.config().debug();
        int classes = 0;
        for (ClassNode node : context.classes().classes().values()) {
            if (!context.rules().transformClass(node) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                // Mod-injection targets keep their debug tables: Mixin injectors
                // may address positions by line number.
                continue;
            }
            classes++;
            if (options.removeKotlin()) {
                AsmUtil.removeAnnotation(node, KOTLIN_METADATA);
                AsmUtil.removeAnnotation(node, KOTLIN_DEBUG);
            }
            if (options.removeSourceFile()) {
                node.sourceFile = null;
                node.sourceDebug = null;
            }
            if (options.removeSignatures()) {
                node.signature = null;
            }
            if (options.removeInnerClasses() && node.innerClasses != null) {
                // ASM's ClassNode.accept assumes a non-null list.
                node.innerClasses.clear();
            }
            for (MethodNode method : node.methods) {
                if (options.removeKotlin()) {
                    AsmUtil.removeAnnotation(method, KOTLIN_METADATA);
                    AsmUtil.removeAnnotation(method, KOTLIN_DEBUG);
                }
                if (options.removeSignatures()) {
                    method.signature = null;
                }
                if (options.removeLocalVariables()) {
                    method.localVariables = null;
                    method.parameters = null;
                }
                if (options.removeLineNumbers()) {
                    for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
                        AbstractInsnNode next = insn.getNext();
                        if (insn instanceof LineNumberNode) {
                            method.instructions.remove(insn);
                        }
                        insn = next;
                    }
                }
            }
        }
        context.stats().add("classes.cleaned", classes);
        context.log().info("debug-info: cleaned %d classes", classes);
    }
}

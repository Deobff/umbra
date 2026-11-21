package io.umbra.core.model;

import io.umbra.core.compat.ClassRenameMap;
import io.umbra.core.util.Log;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Writes a class, restoring method bodies that the obfuscator pushed past the
 * point where ASM can compute their stack map frames.
 *
 * <p>A JVM method may not exceed 65535 bytes of bytecode, and ASM budgets its
 * frame computation relative to the method size. The body passes (flow
 * obfuscation, flattening, exception wrapping, string/constant replacement) grow
 * methods by a factor, and on an artifact that already carries near-limit methods
 * one of them crosses the line. Until now that surfaced only at write time as
 * {@code LimitExceededException: Too many operations} from
 * {@code MethodWriter.computeAllFrames}, which aborted the whole run at 92% - a
 * 1559-class input lost to one generated class.</p>
 *
 * <p>The guard retries the write on a ladder: first with the single biggest
 * method restored to its pre-obfuscation body, then with the biggest 8, 64 and
 * finally every method that has a pre-obfuscation body. Restored bodies are
 * remapped into the current name space, so class and member references stay
 * valid and the class keeps its new name, its fields and every transform that is
 * not a method body. When even that does not fit, the whole class is written as
 * it was before obfuscation (renamed only) with its own stack map frames. Every
 * recovery is logged as a warning, so a weakened method is never silent.</p>
 */
public final class UmbraMethodGuard {

    /** Escalating number of method bodies restored before a retry. */
    private static final int[] LADDER = {1, 8, 64, Integer.MAX_VALUE};

    /** How many restored methods the warning names. */
    private static final int NAME_LIMIT = 3;

    private UmbraMethodGuard() {
    }

    /**
     * Serializes {@code node}, recovering from the per-method size limit.
     *
     * @param node      the class as every pass left it (final names, final descriptors)
     * @param pool      source of the pre-obfuscation bytes
     * @param rename    the renamer mapping, used to remap a restored method body
     * @param hierarchy hierarchy used by the writer's frame computation
     * @param log       run log; every recovery is reported as a warning
     * @return the class bytes
     * @throws RuntimeException the original failure when no recovery fits
     */
    public static byte[] toBytes(ClassNode node, ClassPool pool, ClassRenameMap rename,
                                 Hierarchy hierarchy, Log log) {
        RuntimeException first;
        try {
            return UmbraClassWriter.toBytes(node, hierarchy);
        } catch (RuntimeException failure) {
            first = failure;
        }
        if (node == null || pool == null) {
            throw first;
        }
        log.debug("write: %s could not be serialized as obfuscated (%s); trying body recovery",
                node.name, first.getClass().getName());
        List<MethodNode> candidates = byDescendingSize(node);
        Set<String> restored = new LinkedHashSet<String>();
        for (int step : LADDER) {
            if (!restoreStep(node, pool, rename, candidates, step, restored)) {
                break;
            }
            try {
                byte[] bytes = UmbraClassWriter.toBytes(node, hierarchy);
                warnRestored(log, node, restored);
                return bytes;
            } catch (RuntimeException stillTooLarge) {
                log.debug("write: %s still fails after restoring %d method(s): %s",
                        node.name, Integer.valueOf(restored.size()),
                        stillTooLarge.getClass().getName());
            }
        }
        // Last resort: the class exactly as it was before any pass ran, renamed to
        // its final name and written with its own stack map frames. It is a valid
        // class file by construction because the input archive loaded.
        ClassNode pristine = pristine(node.name, pool, rename);
        if (pristine != null) {
            try {
                byte[] bytes = UmbraClassWriter.toBytesWithoutComputation(pristine, hierarchy);
                log.warn("write: %s carries a method so large that ASM's frame budget gives up on "
                                + "it; kept the class as it was before obfuscation (renamed only) so "
                                + "the archive still builds. Lower the body transforms for this "
                                + "archive to protect it again", node.name);
                return bytes;
            } catch (RuntimeException fallbackFailure) {
                log.debug("write: copy-mode fallback for %s failed: %s", node.name,
                        fallbackFailure.toString());
            }
        }
        throw first;
    }

    private static void warnRestored(Log log, ClassNode node, Set<String> restored) {
        if (restored.isEmpty()) {
            return;
        }
        StringBuilder names = new StringBuilder();
        int named = 0;
        for (String key : restored) {
            if (named++ >= NAME_LIMIT) {
                break;
            }
            if (names.length() > 0) {
                names.append(", ");
            }
            names.append(key);
        }
        log.warn("write: %s exceeded the 64 KB / frame budget limit in %d method(s); kept their "
                        + "original bodies (biggest: %s) so the archive still builds. "
                        + "Lower flow/exception strength for this archive to protect them again",
                node.name, Integer.valueOf(restored.size()), names);
    }

    /**
     * Restores method bodies until {@code target} methods are restored, reading the
     * pre-obfuscation bytes fresh each round so no ASM label is reused across
     * writers.
     *
     * @return true when this round restored at least one more body
     */
    private static boolean restoreStep(ClassNode node, ClassPool pool, ClassRenameMap rename,
                                       List<MethodNode> candidates, int target, Set<String> restored) {
        if (restored.size() >= target) {
            return false;
        }
        ClassNode pristine = pristine(node.name, pool, rename);
        if (pristine == null) {
            return false;
        }
        boolean changed = false;
        for (MethodNode method : candidates) {
            if (restored.size() >= target) {
                break;
            }
            String key = method.name + method.desc;
            if (restored.contains(key)) {
                continue;
            }
            MethodNode source = find(pristine, method.name, method.desc);
            if (source == null || source.instructions.size() == 0) {
                continue;
            }
            restoreBody(method, source);
            restored.add(key);
            changed = true;
        }
        return changed;
    }

    /** The methods that cost the most to serialize, biggest first. */
    private static List<MethodNode> byDescendingSize(ClassNode node) {
        List<MethodNode> methods = new ArrayList<MethodNode>(node.methods);
        Collections.sort(methods, new Comparator<MethodNode>() {
            @Override
            public int compare(MethodNode a, MethodNode b) {
                return Integer.compare(b.instructions.size(), a.instructions.size());
            }
        });
        return methods;
    }

    /** Re-reads the class as it was before any pass ran, in the current name space. */
    private static ClassNode pristine(String className, ClassPool pool, ClassRenameMap rename) {
        byte[] bytes = pool.originalBytes(className);
        if (bytes == null) {
            return null;
        }
        try {
            ClassNode pristine = new ClassNode();
            ClassRenameMap mapping = rename == null ? ClassRenameMap.EMPTY : rename;
            new ClassReader(bytes).accept(new ClassRemapper(pristine, mapping.remapper()), 0);
            return pristine;
        } catch (RuntimeException unreadable) {
            return null;
        }
    }

    private static MethodNode find(ClassNode node, String name, String desc) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) {
                return method;
            }
        }
        return null;
    }

    /**
     * Swaps the body of {@code target} for the one of {@code source}. Frames are not
     * copied because the writer recomputes them; the attributes that describe the
     * instructions travel with the body so the class stays consistent.
     */
    private static void restoreBody(MethodNode target, MethodNode source) {
        target.instructions = source.instructions;
        target.tryCatchBlocks = source.tryCatchBlocks;
        target.localVariables = source.localVariables;
        target.visibleLocalVariableAnnotations = source.visibleLocalVariableAnnotations;
        target.invisibleLocalVariableAnnotations = source.invisibleLocalVariableAnnotations;
        target.maxStack = source.maxStack;
        target.maxLocals = source.maxLocals;
    }
}

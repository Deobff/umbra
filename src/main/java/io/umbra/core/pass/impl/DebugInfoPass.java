package io.umbra.core.pass.impl;

import io.umbra.core.api.OutputPostProcessor;
import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.retrace.LineMap;
import io.umbra.core.util.AsmUtil;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;

/** Removes source/debug metadata according to {@code debugInfo} settings. */
public final class DebugInfoPass implements Pass {

    private static final String KOTLIN_METADATA = "Lkotlin/Metadata;";
    private static final String KOTLIN_DEBUG = "Lkotlin/coroutines/jvm/internal/DebugMetadata;";

    /** Line number handling: {@code keep} (default), {@code scramble} or {@code delete}. */
    public static final String LINE_NUMBERS_OPTION = "lineNumbers";
    public static final String LINE_NUMBERS_KEEP = "keep";
    public static final String LINE_NUMBERS_SCRAMBLE = "scramble";
    public static final String LINE_NUMBERS_DELETE = "delete";

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
        String lineMode = lineNumberMode(context);
        List<LineRecord> records = new ArrayList<LineRecord>();
        LineScrambler scrambler = LINE_NUMBERS_SCRAMBLE.equals(lineMode)
                ? new LineScrambler(new Random(context.random().nextLong())) : null;
        int classes = 0;
        int deletedLines = 0;
        int skippedClasses = 0;
        for (ClassNode node : context.classes().classes().values()) {
            if (!context.rules().transformClass(node) || context.classes().isFrozen(node.name)) {
                continue;
            }
            if (context.rules().skipBodyTransform(node.name)) {
                if (scrambler != null) {
                    skippedClasses++;
                }
                continue;
            }
            classes++;
            if (options.removeKotlin()) {
                AsmUtil.removeAnnotation(node, KOTLIN_METADATA);
                AsmUtil.removeAnnotation(node, KOTLIN_DEBUG);
            }
            // An explicit scramble keeps the source file name: without it the JVM
            // prints "(Unknown Source)" and the line number never reaches the stack,
            // which would make the retrace map useless. keep/delete are unchanged.
            if (options.removeSourceFile() && scrambler == null) {
                node.sourceFile = null;
                node.sourceDebug = null;
            }
            if (options.removeSignatures()) {
                node.signature = null;
            }
            if (options.removeInnerClasses() && node.innerClasses != null) {
                node.innerClasses.clear();
            }
            if (scrambler != null) {
                records.addAll(scrambler.scrambleClass(node));
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
                if (LINE_NUMBERS_DELETE.equals(lineMode)
                        || (scrambler == null && options.removeLineNumbers())) {
                    deletedLines += removeLineNumbers(method);
                }
            }
        }
        context.stats().add("classes.cleaned", classes);
        if (LINE_NUMBERS_DELETE.equals(lineMode)) {
            context.stats().add("lineNumbers.deleted", deletedLines);
            context.log().info("debug-info: removed %d line number entries", deletedLines);
        }
        if (scrambler != null) {
            int entries = 0;
            Set<String> touchedClasses = new LinkedHashSet<String>();
            for (LineRecord record : records) {
                entries += record.newLines.size();
                touchedClasses.add(record.className);
            }
            context.stats().add("lineNumbers.scrambled", entries);
            context.stats().add("lineNumbers.skipped", skippedClasses);
            context.stats().add("lineNumbers.classes", touchedClasses.size());
            context.log().info("debug-info: scrambled %d line number entries across %d classes",
                    entries, touchedClasses.size());
            registerLineMap(context, records);
        } else if (!LINE_NUMBERS_KEEP.equals(lineMode)) {
            context.stats().add("lineNumbers.skipped", 1);
            context.log().warn("debug-info: unknown lineNumbers value '%s'; keeping line numbers",
                    lineMode);
        }
        context.log().info("debug-info: cleaned %d classes", classes);
    }

    /** Reads the new option, falling back to the historical debugInfo key. */
    static String lineNumberMode(PassContext context) {
        String value = context.config().option(LINE_NUMBERS_OPTION,
                context.config().option("debugInfo.lineNumbers", LINE_NUMBERS_KEEP));
        if (value == null) {
            return LINE_NUMBERS_KEEP;
        }
        String normalized = value.trim().toLowerCase(java.util.Locale.ROOT);
        if (LINE_NUMBERS_SCRAMBLE.equals(normalized) || LINE_NUMBERS_DELETE.equals(normalized)) {
            return normalized;
        }
        return LINE_NUMBERS_KEEP;
    }

    private static int removeLineNumbers(MethodNode method) {
        int removed = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof LineNumberNode) {
                method.instructions.remove(insn);
                removed++;
            }
            insn = next;
        }
        return removed;
    }

    /**
     * Writes {@code <output>.linemap} once the archive exists, because only then are
     * the class and member renames final. The records hold original names; the
     * renames are read from the shared mapping set at write time.
     */
    private static void registerLineMap(final PassContext context, final List<LineRecord> records) {
        context.postProcessors().add(new OutputPostProcessor() {
            @Override
            public String name() {
                return "line-map";
            }

            @Override
            public void process(Path output, PassContext running) throws Exception {
                LineMap map = new LineMap();
                for (LineRecord record : records) {
                    String newClass = running.mappings().mappedClass(record.className);
                    String newMethod = running.mappings().mappedMethod(record.methodName,
                            record.descriptor);
                    map.mapClass(record.className, newClass);
                    map.mapMethod(record.className, record.methodName, record.descriptor, newMethod);
                    map.mapLine(record.className, record.methodName, record.descriptor,
                            record.oldLine, record.newLines);
                }
                Path target = Paths.get(output.toString() + ".linemap");
                map.write(target);
                running.stats().add("lineNumbers.map", 1);
                running.log().info("debug-info: line map written to %s (%d classes, %d line pairs)",
                        target.toAbsolutePath(), map.classCount(), map.lineCount());
            }
        });
    }

    /** One scrambled line entry: original coordinates plus the new line numbers. */
    static final class LineRecord {
        final String className;
        final String methodName;
        final String descriptor;
        final int oldLine;
        final List<Integer> newLines;

        LineRecord(String className, String methodName, String descriptor, int oldLine,
                   List<Integer> newLines) {
            this.className = className;
            this.methodName = methodName;
            this.descriptor = descriptor;
            this.oldLine = oldLine;
            this.newLines = newLines;
        }
    }

    /**
     * line scramble.
     *
     * <p>Entries keep their order inside a method; only the absolute numbers move.
     * A source line that was already assigned a number keeps it (one old line may
     * own several new ones), the remaining entries are shuffled and receive the
     * unused numbers below the reserved range first, then fresh ones above it. The
     * shuffled order is what breaks the "line 12 is before line 13" reading.</p>
     */
    static final class LineScrambler {

        private final Random random;
        private final Map<Integer, List<Integer>> assigned =
                new TreeMap<Integer, List<Integer>>();
        private int highest;

        LineScrambler(Random random) {
            this.random = random;
        }

        List<LineRecord> scrambleClass(ClassNode node) {
            List<Object[]> entries = new ArrayList<Object[]>();
            for (MethodNode method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                     insn = insn.getNext()) {
                    if (insn instanceof LineNumberNode) {
                        entries.add(new Object[]{method, insn,
                                Integer.valueOf(((LineNumberNode) insn).line)});
                    }
                }
            }
            List<LineRecord> records = new ArrayList<LineRecord>();
            if (entries.isEmpty()) {
                return records;
            }
            List<Integer> available = new ArrayList<Integer>();
            List<Object[]> pending = new ArrayList<Object[]>();
            if (assigned.isEmpty()) {
                pending.addAll(entries);
            } else {
                Map<Integer, List<Integer>> pool = new LinkedHashMap<Integer, List<Integer>>();
                List<Integer> reservedValues = new ArrayList<Integer>();
                for (Map.Entry<Integer, List<Integer>> entry : assigned.entrySet()) {
                    List<Integer> copy = new ArrayList<Integer>(entry.getValue());
                    pool.put(entry.getKey(), copy);
                    reservedValues.addAll(copy);
                }
                Collections.sort(reservedValues);
                int highestReserved = reservedValues.isEmpty()
                        ? 0 : reservedValues.get(reservedValues.size() - 1).intValue();
                int cursor = 0;
                int current = reservedValues.isEmpty() ? -1 : reservedValues.get(0).intValue();
                for (int line = 0; line < highestReserved; line++) {
                    if (line < current) {
                        available.add(Integer.valueOf(line));
                    } else if (line == current) {
                        cursor++;
                        current = cursor < reservedValues.size()
                                ? reservedValues.get(cursor).intValue() : Integer.MAX_VALUE;
                    }
                }
                for (Object[] entry : entries) {
                    LineNumberNode lineNode = (LineNumberNode) entry[1];
                    Integer oldLine = (Integer) entry[2];
                    List<Integer> known = pool.get(oldLine);
                    if (known != null && !known.isEmpty()) {
                        Integer reused = known.remove(0);
                        lineNode.line = reused.intValue();
                        addAssigned(oldLine, reused);
                        if (reused.intValue() > highest) {
                            highest = reused.intValue();
                        }
                    } else {
                        pending.add(entry);
                    }
                }
                for (List<Integer> leftover : pool.values()) {
                    available.addAll(leftover);
                }
            }
            Collections.shuffle(pending, random);
            int next = 0;
            for (Object[] entry : pending) {
                LineNumberNode lineNode = (LineNumberNode) entry[1];
                Integer oldLine = (Integer) entry[2];
                int newLine;
                if (next < available.size()) {
                    newLine = available.get(next++).intValue();
                } else {
                    newLine = ++highest;
                }
                lineNode.line = newLine;
                addAssigned(oldLine, Integer.valueOf(newLine));
                if (newLine > highest) {
                    highest = newLine;
                }
            }
            Map<String, List<Integer>> grouped = new LinkedHashMap<String, List<Integer>>();
            for (Object[] entry : entries) {
                MethodNode method = (MethodNode) entry[0];
                LineNumberNode lineNode = (LineNumberNode) entry[1];
                Integer oldLine = (Integer) entry[2];
                String key = method.name + '\u0000' + method.desc + '\u0000' + oldLine.intValue();
                List<Integer> lines = grouped.get(key);
                if (lines == null) {
                    lines = new ArrayList<Integer>();
                    grouped.put(key, lines);
                }
                lines.add(Integer.valueOf(lineNode.line));
            }
            for (Map.Entry<String, List<Integer>> entry : grouped.entrySet()) {
                String[] parts = entry.getKey().split("\u0000", 3);
                if (parts.length < 3) {
                    continue;
                }
                records.add(new LineRecord(node.name, parts[0], parts[1],
                        Integer.parseInt(parts[2]), entry.getValue()));
            }
            return records;
        }

        private void addAssigned(Integer oldLine, Integer newLine) {
            List<Integer> list = assigned.get(oldLine);
            if (list == null) {
                list = new ArrayList<Integer>();
                assigned.put(oldLine, list);
            }
            list.add(newLine);
        }
    }
}

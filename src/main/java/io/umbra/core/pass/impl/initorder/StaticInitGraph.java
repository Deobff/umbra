package io.umbra.core.pass.impl.initorder;

import io.umbra.core.api.PassContext;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Static-initialisation dependency graph of the program.
 *
 * <p>An edge {@code A -> B} means "B must be initialised before A": A's class
 * initialiser reaches a {@code GETSTATIC}/{@code PUTSTATIC} on B or an
 * {@code INVOKESTATIC} into B, so running A first would observe B's fields in
 * their pre-initialisation state. The walk starts at {@code <clinit>} (which is
 * where static field initialisers live) and follows same-class
 * {@code INVOKESTATIC} calls up to {@code maxDepth} levels, because a helper the
 * initialiser calls is part of the same initialisation.</p>
 *
 * <p>Cycles are reported as strongly connected components (Tarjan, iterative so
 * a large archive cannot overflow the stack). The condensation is then ordered
 * dependencies-first with Kahn's algorithm; that order is the report's
 * {@code classInitOrder.order} and the rank the {@code reorderClinit} action
 * sorts statement blocks by.</p>
 *
 * <p>Everything is deterministic: classes are visited in pool order, edges keep
 * discovery order, and the Kahn queue is filled in component order.</p>
 */
public final class StaticInitGraph {

    private final List<String> nodes = new ArrayList<String>();
    private final Map<String, List<String>> dependencies = new LinkedHashMap<String, List<String>>();
    private final List<List<String>> cycles = new ArrayList<List<String>>();
    private final Map<String, Integer> ranks = new LinkedHashMap<String, Integer>();
    private final List<String> order = new ArrayList<String>();
    private int edgeCount;

    private StaticInitGraph() {
    }

    public static StaticInitGraph build(PassContext context, int maxDepth) {
        StaticInitGraph graph = new StaticInitGraph();
        Map<String, ClassNode> pool = context.classes().classes();
        Set<String> names = new LinkedHashSet<String>(pool.keySet());
        graph.nodes.addAll(names);
        for (String name : graph.nodes) {
            ClassNode node = pool.get(name);
            Set<String> refs = new LinkedHashSet<String>();
            if (node != null) {
                collect(node, refs, names, maxDepth);
            }
            refs.remove(name);
            graph.dependencies.put(name, new ArrayList<String>(refs));
            graph.edgeCount += refs.size();
        }
        graph.computeComponents();
        graph.computeOrder();
        return graph;
    }

    private static void collect(ClassNode node, Set<String> refs, Set<String> pool, int maxDepth) {
        MethodNode clinit = find(node, "<clinit>", "()V");
        if (clinit == null) {
            return;
        }
        Set<MethodNode> visited = Collections.newSetFromMap(
                new IdentityHashMap<MethodNode, Boolean>());
        scan(node, clinit, refs, pool, visited, 0, Math.max(1, maxDepth));
    }

    private static void scan(ClassNode owner, MethodNode method, Set<String> refs,
                             Set<String> pool, Set<MethodNode> visited, int depth, int maxDepth) {
        if (method == null || depth > maxDepth || !visited.add(method)) {
            return;
        }
        if (method.instructions == null) {
            return;
        }
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
             insn = insn.getNext()) {
            if (insn instanceof FieldInsnNode) {
                FieldInsnNode field = (FieldInsnNode) insn;
                int opcode = field.getOpcode();
                if (opcode != Opcodes.GETSTATIC && opcode != Opcodes.PUTSTATIC) {
                    continue;
                }
                if (!field.owner.equals(owner.name) && pool.contains(field.owner)) {
                    refs.add(field.owner);
                }
                continue;
            }
            if (!(insn instanceof MethodInsnNode)) {
                continue;
            }
            MethodInsnNode call = (MethodInsnNode) insn;
            if (call.getOpcode() != Opcodes.INVOKESTATIC) {
                continue;
            }
            if (pool.contains(call.owner) && !call.owner.equals(owner.name)) {
                refs.add(call.owner);
                continue;
            }
            if (!call.owner.equals(owner.name)) {
                continue;
            }
            MethodNode callee = find(owner, call.name, call.desc);
            if (callee != null && (callee.access & Opcodes.ACC_STATIC) != 0) {
                scan(owner, callee, refs, pool, visited, depth + 1, maxDepth);
            }
        }
    }

    private static MethodNode find(ClassNode node, String name, String desc) {
        for (int i = 0; i < node.methods.size(); i++) {
            MethodNode method = node.methods.get(i);
            if (method.name.equals(name) && method.desc.equals(desc)) {
                return method;
            }
        }
        return null;
    }

    /** Iterative Tarjan; fills {@link #cycles} and the component list. */
    private void computeComponents() {
        Map<String, Integer> index = new LinkedHashMap<String, Integer>();
        Map<String, Integer> low = new LinkedHashMap<String, Integer>();
        Map<String, Boolean> onStack = new LinkedHashMap<String, Boolean>();
        List<String> stack = new ArrayList<String>();
        int counter = 0;
        for (int start = 0; start < nodes.size(); start++) {
            String root = nodes.get(start);
            if (index.containsKey(root)) {
                continue;
            }
            List<String[]> frames = new ArrayList<String[]>();
            frames.add(new String[] { root, "0" });
            index.put(root, Integer.valueOf(counter));
            low.put(root, Integer.valueOf(counter));
            counter++;
            stack.add(root);
            onStack.put(root, Boolean.TRUE);
            while (!frames.isEmpty()) {
                String[] frame = frames.get(frames.size() - 1);
                String current = frame[0];
                int cursor = Integer.parseInt(frame[1]);
                List<String> deps = dependencies.get(current);
                if (deps == null) {
                    deps = Collections.emptyList();
                }
                if (cursor < deps.size()) {
                    frame[1] = Integer.toString(cursor + 1);
                    String next = deps.get(cursor);
                    if (!index.containsKey(next)) {
                        index.put(next, Integer.valueOf(counter));
                        low.put(next, Integer.valueOf(counter));
                        counter++;
                        stack.add(next);
                        onStack.put(next, Boolean.TRUE);
                        frames.add(new String[] { next, "0" });
                    } else if (Boolean.TRUE.equals(onStack.get(next))) {
                        low.put(current, Integer.valueOf(Math.min(low.get(current).intValue(),
                                index.get(next).intValue())));
                    }
                    continue;
                }
                frames.remove(frames.size() - 1);
                int currentLow = low.get(current).intValue();
                if (!frames.isEmpty()) {
                    String parent = frames.get(frames.size() - 1)[0];
                    low.put(parent, Integer.valueOf(Math.min(low.get(parent).intValue(), currentLow)));
                }
                if (currentLow == index.get(current).intValue()) {
                    List<String> component = new ArrayList<String>();
                    while (!stack.isEmpty()) {
                        String popped = stack.remove(stack.size() - 1);
                        onStack.put(popped, Boolean.FALSE);
                        component.add(popped);
                        if (popped.equals(current)) {
                            break;
                        }
                    }
                    Collections.reverse(component);
                    if (component.size() > 1) {
                        cycles.add(component);
                    }
                }
            }
        }
    }

    /**
     * Kahn over the condensation of the dependency graph, dependencies first.
     * Component numbering follows {@link #cycles} order for determinism.
     */
    private void computeOrder() {
        Map<String, Integer> componentOf = new LinkedHashMap<String, Integer>();
        List<List<String>> components = new ArrayList<List<String>>();
        for (int i = 0; i < cycles.size(); i++) {
            components.add(cycles.get(i));
        }
        for (int i = 0; i < nodes.size(); i++) {
            String node = nodes.get(i);
            if (componentOf.containsKey(node)) {
                continue;
            }
            int id = components.size();
            List<String> single = new ArrayList<String>();
            single.add(node);
            components.add(single);
            componentOf.put(node, Integer.valueOf(id));
        }
        for (int i = 0; i < cycles.size(); i++) {
            List<String> cycle = cycles.get(i);
            for (int c = 0; c < cycle.size(); c++) {
                componentOf.put(cycle.get(c), Integer.valueOf(i));
            }
        }

        int size = components.size();
        List<Set<Integer>> dependsOn = new ArrayList<Set<Integer>>(size);
        List<Set<Integer>> dependents = new ArrayList<Set<Integer>>(size);
        for (int i = 0; i < size; i++) {
            dependsOn.add(new LinkedHashSet<Integer>());
            dependents.add(new LinkedHashSet<Integer>());
        }
        for (int i = 0; i < nodes.size(); i++) {
            String node = nodes.get(i);
            int from = componentOf.get(node).intValue();
            List<String> deps = dependencies.get(node);
            for (int d = 0; d < deps.size(); d++) {
                Integer to = componentOf.get(deps.get(d));
                if (to == null || to.intValue() == from) {
                    continue;
                }
                if (dependsOn.get(from).add(to)) {
                    dependents.get(to.intValue()).add(Integer.valueOf(from));
                }
            }
        }

        int[] remaining = new int[size];
        for (int i = 0; i < size; i++) {
            remaining[i] = dependsOn.get(i).size();
        }
        List<Integer> ready = new ArrayList<Integer>();
        for (int i = 0; i < size; i++) {
            if (remaining[i] == 0) {
                ready.add(Integer.valueOf(i));
            }
        }
        List<Integer> visited = new ArrayList<Integer>();
        int cursor = 0;
        while (cursor < ready.size()) {
            Integer current = ready.get(cursor++);
            visited.add(current);
            for (Integer dependent : dependents.get(current.intValue())) {
                int index = dependent.intValue();
                remaining[index]--;
                if (remaining[index] == 0) {
                    ready.add(dependent);
                }
            }
        }
        for (int i = 0; i < size; i++) {
            if (remaining[i] > 0) {
                visited.add(Integer.valueOf(i));
            }
        }
        int rank = 0;
        for (Integer component : visited) {
            List<String> members = components.get(component.intValue());
            for (int m = 0; m < members.size(); m++) {
                order.add(members.get(m));
                ranks.put(members.get(m), Integer.valueOf(rank++));
            }
        }
    }

    public List<String> nodes() {
        return Collections.unmodifiableList(nodes);
    }

    public List<String> dependenciesOf(String node) {
        List<String> deps = dependencies.get(node);
        return deps == null ? Collections.<String>emptyList() : Collections.unmodifiableList(deps);
    }

    public int edgeCount() {
        return edgeCount;
    }

    public int classCount() {
        return nodes.size();
    }

    public List<List<String>> cycles() {
        return Collections.unmodifiableList(cycles);
    }

    public List<String> order() {
        return Collections.unmodifiableList(order);
    }

    /** Rank of a class in {@link #order}, or {@code Integer.MAX_VALUE} when unknown. */
    public int rank(String node) {
        Integer value = ranks.get(node);
        return value == null ? Integer.MAX_VALUE : value.intValue();
    }

    /** {@code A->B->A;B->C->B} form used for the meta entry and the warn log. */
    public String cyclesText() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < cycles.size(); i++) {
            if (i > 0) {
                builder.append(';');
            }
            List<String> cycle = cycles.get(i);
            for (int c = 0; c < cycle.size(); c++) {
                if (c > 0) {
                    builder.append("->");
                }
                builder.append(cycle.get(c));
            }
            builder.append("->").append(cycle.get(0));
        }
        return builder.toString();
    }

    /** Comma-separated initialisation order, dependencies first. */
    public String orderText() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < order.size(); i++) {
            if (i > 0) {
                builder.append(',');
            }
            builder.append(order.get(i));
        }
        return builder.toString();
    }
}

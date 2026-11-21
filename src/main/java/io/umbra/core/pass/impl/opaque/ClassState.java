package io.umbra.core.pass.impl.opaque;

import io.umbra.core.api.PassContext;
import io.umbra.core.pass.impl.flow.RuntimeTable;
import io.umbra.core.util.AsmUtil;
import io.umbra.core.util.NameGenerator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Per-class bookkeeping for the opaque-predicate pass.
 *
 * <p>Two-phase on purpose (CONTRACT 5): nothing is written into the class until
 * the transform of the whole class is known to be kept. Helper methods, the
 * loader fields and the {@link RuntimeTable} chunks are only recorded here and
 * {@link #materialize()} commits them; a rolled-back class therefore leaves no
 * orphan member behind.</p>
 *
 * <p>Every choice (class seed, helper name, argument order, constants) comes
 * from the per-class stream, so a run stays byte-reproducible for a seed and no
 * value depends on how many numbers the passes before this one drew.</p>
 */
public final class ClassState {

    private final PassContext context;
    private final ClassNode node;
    private final Random random;
    private final RuntimeTable table;
    private SeedLoader loader;
    private final boolean swapped;
    private final int classSeed;

    private final List<MethodNode> helpers = new ArrayList<MethodNode>();
    private final List<FieldNode> pendingFields = new ArrayList<FieldNode>();

    private String helperName;
    private int plainConstants;
    private int runtimePairs;

    public ClassState(PassContext context, ClassNode node, Random random, int pairBudget,
                      io.umbra.core.pass.impl.flow.KeyRootMask mask) {
        this.context = context;
        this.node = node;
        this.random = random;
        this.table = RuntimeTable.create(context, node, pairBudget, mask);
        this.swapped = random.nextBoolean();
        this.classSeed = random.nextInt();
    }

    /** Set once, before {@link #prepare()}: the loader needs this instance for naming. */
    public void setLoader(SeedLoader loader) {
        this.loader = loader;
    }

    public ClassNode node() {
        return node;
    }

    public PassContext context() {
        return context;
    }

    public Random random() {
        return random;
    }

    public SeedLoader loader() {
        return loader;
    }

    public int classSeed() {
        return classSeed;
    }

    /** True when the XOR helper reads its two operands in the other order (donor's {@code swapped}). */
    public boolean swapped() {
        return swapped;
    }

    public int plainConstants() {
        return plainConstants;
    }

    public int runtimePairs() {
        return runtimePairs;
    }

    /** Installs the loader's helper shape, if the loader wants one. */
    public void prepare() {
        if (loader.needsHelper()) {
            loader.install(this);
        }
    }

    public String helperName() {
        if (helperName == null) {
            helperName = uniqueMethodName();
        }
        return helperName;
    }

    public void installHelper(MethodNode helper) {
        helpers.add(helper);
    }

    /**
     * The helper every {@code internal} guard calls. When a seed loader already
     * installed one, its body is reused: all five shapes compute {@code a ^ b}.
     */
    public String ensureXorHelper() {
        if (helpers.isEmpty()) {
            XorHelper.install(this, XorHelper.plain(swapped), 2, 2);
        }
        return helperName();
    }

    public void addField(FieldNode field) {
        pendingFields.add(field);
    }

    /**
     * Pushes a build-time constant. It goes through the per-class runtime table
     * whenever one is available, which is the only way the edge mask
     * ({@code successor ^ block}) never appears as an {@code ldc} at a use site;
     * only when the table budget for this class is spent does it degrade to a
     * plain pushed constant, and that degradation is counted.
     */
    public void pushConstant(InsnList out, int value) {
        RuntimeTable.Pair pair = table.pair(value);
        if (pair == null) {
            AsmUtil.pushInt(out, value);
            plainConstants++;
            return;
        }
        table.emitInt(out, pair);
        runtimePairs++;
    }

    /** The donor's method predicate: {@code (private ^ classSeed) ^ classSeed}, i.e. {@code private}. */
    public void pushMethodPrivate(InsnList out, int privateValue) {
        pushConstant(out, privateValue ^ classSeed);
        pushConstant(out, classSeed);
        out.add(new InsnNode(Opcodes.IXOR));
    }

    /** Writes the recorded members; the caller has already decided the class is kept. */
    public void materialize() {
        for (FieldNode field : pendingFields) {
            node.fields.add(field);
        }
        for (MethodNode helper : helpers) {
            node.methods.add(helper);
        }
        table.materialize(node);
    }

    /** A field name that no existing or pending field of this class uses. */
    public String uniqueFieldName(Random random, int length) {
        Set<String> names = new HashSet<String>();
        for (FieldNode field : node.fields) {
            names.add(field.name);
        }
        for (FieldNode field : pendingFields) {
            names.add(field.name);
        }
        NameGenerator generator = new NameGenerator(random, "");
        String candidate = generator.random(length);
        while (names.contains(candidate)) {
            candidate = generator.random(length);
        }
        return candidate;
    }

    private String uniqueMethodName() {
        Set<String> names = new HashSet<String>();
        for (MethodNode method : node.methods) {
            names.add(method.name);
        }
        NameGenerator generator = new NameGenerator(random, "");
        String candidate = generator.random(9);
        while (names.contains(candidate)) {
            candidate = generator.random(9);
        }
        return candidate;
    }
}

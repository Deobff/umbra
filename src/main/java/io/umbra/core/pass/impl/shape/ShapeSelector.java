package io.umbra.core.pass.impl.shape;

import io.umbra.core.api.PassContext;
import io.umbra.core.engine.Stats;
import org.objectweb.asm.tree.ClassNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Shared storage-shape selector for the constant-encryption passes.
 *
 * <p>The five storage kinds are the ones a commercial obfuscator uses for every
 * encrypted constant, whether it is a string, an int, a long or a reference:</p>
 *
 * <ul>
 *   <li>{@link Shape#LOCAL_ARRAY_AND_INDEX} - the payload array is materialised
 *       in a fresh local at method entry and the site carries only an index;</li>
 *   <li>{@link Shape#FIELD_ARRAY_AND_INDEX} - the payload array is a synthetic
 *       static field and the site carries only an index;</li>
 *   <li>{@link Shape#LOOKUP_METHOD_AND_INDEX} - a synthetic static lookup method
 *       maps an index to the value, the key lives in another synthetic field;</li>
 *   <li>{@link Shape#LOOKUP_METHOD_AND_INDEX_DES} - the same lookup method, but
 *       the per-chunk key travels as a call argument instead of a field;</li>
 *   <li>{@link Shape#INDY_ENTRY_AND_INDEX} - the site is an {@code invokedynamic}
 *       whose bootstrap argument is the index.</li>
 * </ul>
 *
 * <p>Selection is opt-in through {@code shape.pool}: an empty value keeps every
 * pass on its historical per-class shape, so existing artifacts are unchanged.
 * When the option is set, each site draws from the intersection of the requested
 * pool and the shapes the pass can actually emit for that class; a site whose
 * draw has no supported kind falls back to the pass default and is counted in
 * {@code shape.fallback} instead of producing a half-built shape.</p>
 */
public final class ShapeSelector {

    public static final String OPTION = "shape.pool";

    public enum Shape {
        LOCAL_ARRAY_AND_INDEX("localArray"),
        FIELD_ARRAY_AND_INDEX("fieldArray"),
        LOOKUP_METHOD_AND_INDEX("lookupMethod"),
        LOOKUP_METHOD_AND_INDEX_DES("lookupMethodDes"),
        INDY_ENTRY_AND_INDEX("indyEntry"),

        LEGACY("legacy");

        private final String key;

        Shape(String key) {
            this.key = key;
        }

        public String key() {
            return key;
        }

        public String statKey() {
            return "shape." + key;
        }
    }

    private final List<Shape> pool;
    private final PassContext context;
    private final Map<Shape, Integer> counts = new LinkedHashMap<Shape, Integer>();
    private int fallbacks;
    private int sites;

    private ShapeSelector(PassContext context, List<Shape> pool) {
        this.context = context;
        this.pool = pool;
    }

    public static ShapeSelector create(PassContext context) {
        String raw = context.config().option(OPTION, "").trim();
        if (raw.isEmpty() || "off".equalsIgnoreCase(raw) || "false".equalsIgnoreCase(raw)) {
            return null;
        }
        List<Shape> pool = parse(raw);
        if (pool.isEmpty()) {
            context.log().warn("shape: %s=%s names no known storage kind; the passes keep their "
                    + "historical shapes", OPTION, raw);
            return null;
        }
        return new ShapeSelector(context, pool);
    }

    public static List<Shape> parse(String raw) {
        List<Shape> pool = new ArrayList<Shape>();
        String[] tokens = raw.split(",");
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i].trim();
            if (token.isEmpty()) {
                continue;
            }
            if ("all".equalsIgnoreCase(token) || "*".equalsIgnoreCase(token)) {
                for (Shape shape : Shape.values()) {
                    if (shape != Shape.LEGACY && !pool.contains(shape)) {
                        pool.add(shape);
                    }
                }
                continue;
            }
            Shape shape = byName(token);
            if (shape != null && !pool.contains(shape)) {
                pool.add(shape);
            }
        }
        return pool;
    }

    public static Shape byName(String token) {
        String normalised = token.replace("-", "").replace("_", "").toLowerCase(Locale.ROOT);
        for (Shape shape : Shape.values()) {
            if (shape.key().toLowerCase(Locale.ROOT).equals(normalised)) {
                return shape;
            }
        }
        if ("local".equals(normalised) || "localarray".equals(normalised)) {
            return Shape.LOCAL_ARRAY_AND_INDEX;
        }
        if ("field".equals(normalised) || "fieldarray".equals(normalised)) {
            return Shape.FIELD_ARRAY_AND_INDEX;
        }
        if ("lookup".equals(normalised)) {
            return Shape.LOOKUP_METHOD_AND_INDEX;
        }
        if ("lookupdes".equals(normalised)) {
            return Shape.LOOKUP_METHOD_AND_INDEX_DES;
        }
        if ("indy".equals(normalised)) {
            return Shape.INDY_ENTRY_AND_INDEX;
        }
        return null;
    }

    public boolean enabled() {
        return true;
    }

    public List<Shape> pool() {
        return new ArrayList<Shape>(pool);
    }

    public Shape pick(ClassNode node, Shape... supported) {
        if (supported == null || supported.length == 0) {
            fallbacks++;
            return Shape.LEGACY;
        }
        List<Shape> candidates = new ArrayList<Shape>();
        for (int i = 0; i < pool.size(); i++) {
            Shape shape = pool.get(i);
            for (int s = 0; s < supported.length; s++) {
                if (supported[s] == shape) {
                    candidates.add(shape);
                    break;
                }
            }
        }
        if (candidates.isEmpty()) {
            fallbacks++;
            return supported[0];
        }
        return candidates.get(context.random().nextInt(candidates.size()));
    }

    public void count(Shape shape) {
        count(shape, 1);
    }

    public void count(Shape shape, int delta) {
        if (shape == null || delta <= 0) {
            return;
        }
        Integer current = counts.get(shape);
        counts.put(shape, Integer.valueOf(current == null ? delta : current.intValue() + delta));
        sites += delta;
    }

    public int sites() {
        return sites;
    }

    public int fallbacks() {
        return fallbacks;
    }

    public void report(Stats stats) {
        for (Shape shape : Shape.values()) {
            Integer value = counts.get(shape);
            stats.add(shape.statKey(), value == null ? 0L : value.longValue());
        }
        stats.add("shape.sites", sites);
        stats.add("shape.fallback", fallbacks);
    }

    public String describe() {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < pool.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append(pool.get(i).key());
        }
        return out.length() == 0 ? "off" : out.toString();
    }
}

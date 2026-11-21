package io.umbra.core.util;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Former per-build domain-label registry, kept as a compatibility shim.
 *
 * <p>Until 3.4.0 every KDF was prefixed with a self-describing ASCII label
 * ({@code "io.umbra.string.site.key.v1"} and friends) that {@link #install(long)}
 * rewrote into a seed-derived 16-hex value. Both forms ended up as readable
 * {@code Utf8} constants inside the injected runtime helpers - the label handed
 * an analyst the whole key schedule, and the rewritten hex was still a plain
 * string constant that a static scan could collect. {@code U1-crypto.md} §4.2
 * used exactly those constants to recover the string layer offline.</p>
 *
 * <p>The separators are now 4-byte int domain words owned by
 * {@code io.umbra.core.runtime.crypto.UmbraCrypto} ({@code D_*}); they are
 * compiled into method bodies as {@code ICONST}/{@code BIPUSH} operands and never
 * reach a constant pool. Nothing about a domain depends on the seed any more, so
 * this class no longer rewrites anything.</p>
 *
 * <p>{@link #install(long)} stays because {@code UmbraEngine} calls it before the
 * pipeline; deleting the call (and then this class) is a separate cleanup that
 * belongs to the engine owner.</p>
 */
public final class DomainTags {

    private DomainTags() {
    }

    /**
     * No-op. Domain words no longer depend on the run seed; the method is kept so
     * the engine's pre-pass hook keeps compiling.
     */
    public static void install(long seed) {
    }

    /**
     * Empty. No injected template carries a string domain label that would have to
     * be rewritten, so template injection has nothing to substitute.
     */
    public static Map<String, String> replacements() {
        return new LinkedHashMap<String, String>();
    }
}

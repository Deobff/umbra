package io.umbra.core.pass.impl.opaque;

import java.util.Random;

/** Registry of the five guard shapes, in the donor's naming. */
public final class Renderers {

    private static final PredicateRenderer[] ALL = {
            new ConditionalGuard(),
            new SwitchGuard(),
            new ExceptionGuard(),
            new UnconditionalGuard(),
            new InternalGuard()
    };

    private Renderers() {
    }

    public static String[] names() {
        String[] names = new String[ALL.length];
        for (int i = 0; i < ALL.length; i++) {
            names[i] = ALL[i].name();
        }
        return names;
    }

    public static PredicateRenderer byName(String name) {
        if (name == null) {
            return null;
        }
        for (PredicateRenderer renderer : ALL) {
            if (renderer.name().equals(name)) {
                return renderer;
            }
        }
        return null;
    }

    /** Resolves {@code opaque.renderer}; {@code mix} draws one shape per block. */
    public static PredicateRenderer pick(String option, Random random) {
        if ("mix".equals(option)) {
            return ALL[random.nextInt(ALL.length)];
        }
        PredicateRenderer named = byName(option);
        return named == null ? ALL[0] : named;
    }
}

package io.umbra.core.pass.impl.opaque;

import java.util.Random;

/** Registry of the five seed loaders, in the donor's naming. */
public final class SeedLoaders {

    private static final String[] NAMES = { "static", "enhanced", "exception", "switch", "internal" };

    private SeedLoaders() {
    }

    public static String[] names() {
        return NAMES.clone();
    }

    public static SeedLoader create(String name, Random random, ClassState state) {
        if ("enhanced".equals(name)) {
            return new EnhancedSeedLoader(random, state);
        }
        if ("exception".equals(name)) {
            return new ExceptionSeedLoader();
        }
        if ("switch".equals(name)) {
            return new SwitchSeedLoader();
        }
        if ("internal".equals(name)) {
            return new InternalSeedLoader();
        }
        return new StaticSeedLoader();
    }

    /**
     * Resolves the {@code opaque.seed} option. {@code mix} draws one loader per
     * class from the class stream, so the choice is reproducible and a class
     * never ends up with two different helper shapes.
     */
    public static String pickName(String option, Random random) {
        if (option == null) {
            return "static";
        }
        if (!"mix".equals(option)) {
            for (String name : NAMES) {
                if (name.equals(option)) {
                    return name;
                }
            }
            return "static";
        }
        return NAMES[random.nextInt(NAMES.length)];
    }
}

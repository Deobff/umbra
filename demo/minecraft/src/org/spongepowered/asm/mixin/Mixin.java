package org.spongepowered.asm.mixin;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Compile-time stub of the Sponge Mixin {@code @Mixin} annotation.
 *
 * <p>The QA fixtures only need the annotation descriptor to be present in the
 * class file (Mixin/Forge keep logic is annotation-driven); the real annotation
 * class is provided by the mod loader at runtime. Retention is CLASS, matching
 * the real annotation.</p>
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
public @interface Mixin {

    Class<?>[] value() default {};

    String[] targets() default {};

    boolean remap() default true;

    int priority() default 1000;
}

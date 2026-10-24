package org.spongepowered.asm.mixin;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Compile-time stub of the Sponge Mixin {@code @Overwrite} annotation. */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface Overwrite {

    String[] aliases() default {};

    boolean remap() default true;
}

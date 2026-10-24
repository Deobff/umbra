package org.spongepowered.asm.mixin.injection;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Compile-time stub of the Sponge Mixin {@code @Inject} annotation. */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface Inject {

    String method();

    At[] at() default {};

    int require() default -1;

    boolean remap() default true;
}

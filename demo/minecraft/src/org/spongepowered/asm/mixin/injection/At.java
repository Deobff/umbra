package org.spongepowered.asm.mixin.injection;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Compile-time stub of the Sponge Mixin {@code @At} injection point. */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
public @interface At {

    String value();

    String target() default "";

    int ordinal() default -1;

    String shift() default "";
}

package io.umbra.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Controls string encryption for a class or method.
 *
 * <p>{@code enabled = false} opts the annotated element out even when string
 * encryption is globally enabled.</p>
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface StringEncryption {
    /** Whether string constants in the annotated element should be encrypted. */
    boolean enabled() default true;
}

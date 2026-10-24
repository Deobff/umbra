package io.umbra.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Controls control-flow obfuscation for a class or method.
 *
 * <p>{@code enabled = false} opts the annotated element out; {@code level}
 * selects the strength for the annotated element.</p>
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface FlowObfuscation {
    /** Whether control-flow obfuscation should run on the annotated element. */
    boolean enabled() default true;

    /** Requested strength: {@code light}, {@code normal}, or {@code aggressive}. */
    String level() default "light";
}

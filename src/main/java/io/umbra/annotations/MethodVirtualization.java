package io.umbra.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Controls method virtualization for a class or method.
 *
 * <p>{@code enabled = false} opts the annotated element out when virtualization
 * is enabled globally. Virtualization is always best-effort: methods containing
 * constructors, exception handlers or invokedynamic are skipped.</p>
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface MethodVirtualization {
    /** Whether method virtualization should run on the annotated element. */
    boolean enabled() default true;
}

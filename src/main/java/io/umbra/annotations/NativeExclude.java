package io.umbra.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Removes its target from the native (java2c) translation set.
 *
 * <p>Like the reference implementation's {@code excludeAnnotation} config entry, this wins over
 * every include rule: an annotated class is skipped entirely, an annotated
 * method keeps its Java body even when {@code native.methods} selects it.
 * {@link Keep} also keeps a Java body, but it additionally stops renaming and
 * every other body transform, which is often more than needed.</p>
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface NativeExclude {
}

package io.umbra.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Forces its target into the native (java2c) translation set.
 *
 * <p>Like the reference implementation's {@code includeAnnotation} config entry, this is an
 * <em>unconditional include</em>: an annotated method is translated even when
 * the {@code native.methods} glob would not select it. It matches whole classes
 * (every method of the class) and single methods.</p>
 *
 * <p>Retained in the class file so the pass can read it with ASM; it is checked
 * in both the visible and the invisible annotation lists.</p>
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface NativeInclude {
}

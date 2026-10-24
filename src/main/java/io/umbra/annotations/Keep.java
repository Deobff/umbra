package io.umbra.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a class or member as kept: Umbra will not rename, remove, or otherwise
 * transform the annotated element.
 *
 * <p>The annotation is retained in the {@code CLASS} file so that the
 * obfuscator can read it without loading the class.</p>
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD, ElementType.CONSTRUCTOR})
public @interface Keep {
}

package io.umbra.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Prevents renaming of the annotated element while still allowing other
 * transforms (string encryption, control-flow obfuscation, ...) to run.
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
public @interface DoNotRename {
}

package net.minecraftforge.fml.common;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Compile-time stub of the Forge legacy {@code @Mod} annotation. */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Mod {

    String modid();

    String name() default "";

    String version() default "";

    String acceptedMinecraftVersions() default "";

    String dependencies() default "";
}

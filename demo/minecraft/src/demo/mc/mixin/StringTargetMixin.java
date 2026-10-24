package demo.mc.mixin;

import org.spongepowered.asm.mixin.Mixin;

/**
 * Mixin declared by string target name (the {@code targets()} path of the
 * annotation, used for game classes that are not on the compile classpath).
 */
@Mixin(targets = "demo.mc.game.Target")
public abstract class StringTargetMixin {

    public String mixinOrigin() {
        return "string-target-mixin";
    }
}

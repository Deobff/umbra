package demo.mc.mixin;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;

import demo.mc.game.Target;

/**
 * Synthetic Mixin: by-name annotation target and shadowed game member.
 *
 * <p>Both the mixin class and {@link Target} must survive with unchanged names
 * and unchanged method bodies, otherwise the real Mixin runtime cannot apply
 * the patch.</p>
 */
@Mixin(Target.class)
public abstract class TargetMixin {

    @Shadow
    private int secretValue;

    @Inject(method = "compute", at = @At("HEAD"))
    private void onCompute(int input) {
        this.secretValue += 1;
    }

    public int mixinOnly(int input) {
        return secretValue + input + 100;
    }
}

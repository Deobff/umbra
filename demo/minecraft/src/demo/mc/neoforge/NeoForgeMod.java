package demo.mc.neoforge;

import net.neoforged.fml.common.Mod;

import demo.mc.Helper;
import demo.mc.game.Target;

/** NeoForge mod class declared in {@code META-INF/neoforge.mods.toml}. */
@Mod("qaneo")
public final class NeoForgeMod {

    public NeoForgeMod() {
        Target target = new Target();
        System.out.println("MC_MARKER neoforge:" + target.compute(11) + ":" + Helper.mix(1, 1));
    }
}

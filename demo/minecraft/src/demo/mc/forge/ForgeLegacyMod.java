package demo.mc.forge;

import net.minecraftforge.fml.common.Mod;

import demo.mc.Helper;
import demo.mc.game.Target;

/** Forge 1.8.9/1.12.2-style mod class discovered through {@code mcmod.info}. */
@Mod(modid = "qalegacy", name = "QA Legacy Mod", version = "1.0",
        acceptedMinecraftVersions = "[1.12.2]")
public final class ForgeLegacyMod {

    public ForgeLegacyMod() {
        Target target = new Target();
        System.out.println("MC_MARKER forge-legacy:" + target.compute(4) + ":" + Helper.describe(7));
    }
}

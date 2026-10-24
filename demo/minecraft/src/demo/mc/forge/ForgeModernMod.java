package demo.mc.forge;

import net.minecraftforge.fml.common.Mod;

import demo.mc.Helper;
import demo.mc.game.Target;

/** Forge modern (1.20.x) mod class declared in {@code META-INF/mods.toml}. */
@Mod(modid = "qaforge", name = "QA Forge Mod", version = "1.0.0")
public final class ForgeModernMod {

    public ForgeModernMod() {
        Target target = new Target();
        System.out.println("MC_MARKER forge-modern:" + target.untouched(21) + ":" + Helper.token());
    }
}

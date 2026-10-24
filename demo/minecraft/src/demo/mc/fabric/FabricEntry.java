package demo.mc.fabric;

import net.fabricmc.api.ModInitializer;

import demo.mc.Helper;
import demo.mc.game.Target;

/**
 * Fabric entrypoint referenced from {@code fabric.mod.json} as
 * {@code demo.mc.fabric.FabricEntry::onInitialize}.
 */
public final class FabricEntry implements ModInitializer {

    /**
     * Mod jars normally have no entry point; the class encryption control case
     * needs one, so the fixture exposes a tiny main that runs the same
     * initialisation as the loader would.
     */
    public static void main(String[] arguments) {
        new FabricEntry().onInitialize();
    }

    @Override
    public void onInitialize() {
        Target target = new Target();
        int value = target.compute(21);
        if (value != 45) {
            throw new IllegalStateException("fabric target value: " + value);
        }
        String token = Helper.token();
        if (!token.endsWith("_42")) {
            throw new IllegalStateException("fabric helper token: " + token);
        }
        System.out.println("MC_MARKER fabric:" + value + ":" + target.message());
    }
}

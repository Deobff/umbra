package demo.mc.quilt;

import demo.mc.Helper;
import demo.mc.game.Target;

/** Quilt entrypoint referenced from {@code quilt.mod.json}. */
public final class QuiltEntry {

    public void onInitialize() {
        Target target = new Target();
        int value = target.untouched(30);
        if (value != 55) {
            throw new IllegalStateException("quilt target value: " + value);
        }
        System.out.println("MC_MARKER quilt:" + value + ":" + Helper.mix(2, 3));
    }
}

package demo.mc.mixin;

/** Class named in {@code demo.mc.mixins.json} as the mixin config plugin. */
public final class DemoMixinPlugin {

    public DemoMixinPlugin() {
    }

    public boolean shouldApplyMixin(String targetClassName, String mixinClassName) {
        return true;
    }
}

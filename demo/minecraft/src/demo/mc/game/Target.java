package demo.mc.game;

/**
 * Synthetic stand-in for a Minecraft game class patched by a Mixin.
 *
 * <p>The mod is not allowed to know the obfuscated name of this class (Mixin
 * matches by name/shape), so Umbra's mod adapter must keep it and must not
 * rewrite its method bodies.</p>
 */
public class Target {

    private int secretValue = 21;

    public int compute(int input) {
        int total = secretValue + input;
        for (int i = 0; i < 3; i++) {
            total += i;
        }
        return total;
    }

    public String message() {
        return "target-original";
    }

    public int untouched(int input) {
        int result = input * 2;
        if (result > 40) {
            result -= 5;
        } else {
            result += 7;
        }
        return result;
    }
}

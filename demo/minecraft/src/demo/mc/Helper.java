package demo.mc;

/**
 * Ordinary mod class that is NOT referenced from loader metadata, mixins or
 * reflection. Umbra must still protect it (positive control: renaming, string
 * and integer encryption keep running on non-adapted classes).
 */
public final class Helper {

    private static final int SEED = 0x5EED;
    private static final long MAGIC = 0x1122334455667788L;

    private Helper() {
    }

    /** Distinctive literal: the protected output must not contain it in clear. */
    public static String token() {
        return "MC_HELPER_SECRET_TOKEN_42";
    }

    public static int mix(int left, int right) {
        int result = left * 31 + right + SEED;
        for (int i = 0; i < 5; i++) {
            result ^= (result << 3);
        }
        return result + (int) (MAGIC & 0x7FL);
    }

    public static String describe(int value) {
        return "helper:" + value + ":" + token();
    }
}

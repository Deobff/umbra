/**
 * Maps the ControlFlowFlatteningPass state constants of one method back to the
 * dispatch-table index, so a block can be reached from the bytecode dump.
 *
 * <p>The flattened dispatcher is {@code ((state ^ XOR) * MUL) & 0xFFFFFFFF}
 * switched over {@code 0..N-1}; the multiply is odd, hence invertible.</p>
 */
public final class StateMap {
    public static void main(String[] args) {
        int xor = 104300137;
        int mul = 946144367;
        int[] states = {
            -1957392965, -1824672221, -960256794, -1023460702, -900176086,
            -696910570, -769485870, -773969506, 104300137, 26323473,
            223166685, 159045273, 281215745, 1156182468, 1082558336,
            1286740556, 1411073780, 1405672624
        };
        int wanted = args.length > 0 ? Integer.parseInt(args[0]) : 23;
        System.out.println("xor=" + xor + " mul=" + mul + " wanted index=" + wanted);
        for (int i = 0; i < states.length; i++) {
            int index = (states[i] ^ xor) * mul;
            System.out.println(String.format("state %12d -> index %12d %s",
                    Integer.valueOf(states[i]), Integer.valueOf(index),
                    index == wanted ? "  <== target" : ""));
        }
    }
}

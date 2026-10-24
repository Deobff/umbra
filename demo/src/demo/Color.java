package demo;

/** Small enum used by the switch-on-enum coverage in {@link FlowSuite}. */
public enum Color {

    RED(1),
    GREEN(2),
    BLUE(3);

    private final int weight;

    Color(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }
}

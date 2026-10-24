package demo;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Static/instance fields, constants and insertion-ordered collections.
 */
public final class Inventory {

    public static final String STORE_NAME = "umbra-depot";
    public static final int MAX_SLOTS = 8;

    private static int instances;

    private final String owner;
    private final Map<String, Integer> stock = new LinkedHashMap<String, Integer>();

    public Inventory(String owner) {
        this.owner = owner;
        instances++;
    }

    public static int instances() {
        return instances;
    }

    public String owner() {
        return owner;
    }

    public int count(String item) {
        Integer value = stock.get(item);
        return value == null ? 0 : value.intValue();
    }

    public int total() {
        int sum = 0;
        for (int quantity : stock.values()) {
            sum += quantity;
        }
        return sum;
    }

    public String items() {
        return String.join(",", stock.keySet());
    }

    public void add(String item, int quantity) throws DemoException {
        if (quantity <= 0) {
            throw new DemoException(DemoException.CODE_RANGE, "quantity must be positive");
        }
        if (!stock.containsKey(item) && stock.size() >= MAX_SLOTS) {
            throw new DemoException(DemoException.CODE_STATE, "inventory full");
        }
        stock.put(item, Integer.valueOf(count(item) + quantity));
    }

    public int take(String item, int quantity) throws DemoException {
        int current = count(item);
        if (quantity <= 0 || current < quantity) {
            throw new DemoException(DemoException.CODE_RANGE, "insufficient " + item);
        }
        int left = current - quantity;
        if (left == 0) {
            stock.remove(item);
        } else {
            stock.put(item, Integer.valueOf(left));
        }
        return left;
    }
}

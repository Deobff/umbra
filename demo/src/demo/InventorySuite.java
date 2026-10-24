package demo;

/** Static/instance field and collection coverage built around {@link Inventory}. */
public final class InventorySuite {

    private InventorySuite() {
    }

    public static void run() throws DemoException {
        Inventory first = new Inventory("alice");
        Inventory second = new Inventory("bob");
        Checks.eq(Inventory.instances(), 2, "static instance counter");
        Checks.eq(Inventory.STORE_NAME, "umbra-depot", "static final constant");
        Checks.eq(Inventory.MAX_SLOTS, 8, "static final int");
        Checks.eq(first.owner(), "alice", "instance field");
        Checks.eq(second.owner(), "bob", "second instance field");
        Checks.eq(first.total(), 0, "empty total");

        first.add("apple", 3);
        first.add("pear", 5);
        first.add("apple", 2);
        Checks.eq(first.count("apple"), 5, "accumulated count");
        Checks.eq(first.count("pear"), 5, "second item");
        Checks.eq(first.count("missing"), 0, "missing item");
        Checks.eq(first.total(), 10, "total after adds");
        Checks.eq(first.items(), "apple,pear", "insertion order");
        Checks.eq(second.total(), 0, "instance state isolated");

        Checks.eq(first.take("apple", 5), 0, "take all");
        Checks.eq(first.count("apple"), 0, "removed when empty");
        Checks.eq(first.items(), "pear", "items after removal");
        Checks.eq(first.total(), 5, "total after take");

        boolean rejected = false;
        try {
            first.take("pear", 99);
        } catch (DemoException expected) {
            rejected = true;
            Checks.eq(expected.code(), DemoException.CODE_RANGE, "insufficient code");
        }
        Checks.check(rejected, "overdraw rejected");

        rejected = false;
        try {
            first.add("plum", 0);
        } catch (DemoException expected) {
            rejected = true;
            Checks.eq(expected.code(), DemoException.CODE_RANGE, "bad quantity code");
        }
        Checks.check(rejected, "zero quantity rejected");

        Inventory full = new Inventory("carol");
        for (int i = 0; i < Inventory.MAX_SLOTS; i++) {
            full.add("item-" + i, 1);
        }
        Checks.eq(full.items().split(",").length, 8, "all slots used");
        rejected = false;
        try {
            full.add("overflow", 1);
        } catch (DemoException expected) {
            rejected = true;
            Checks.eq(expected.code(), DemoException.CODE_STATE, "full code");
        }
        Checks.check(rejected, "full inventory rejected");
        Checks.eq(Inventory.instances(), 3, "instance counter after third");
    }
}

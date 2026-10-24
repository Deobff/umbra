package demo;

/** Abstract base class for the shapes: shared state, constructor and methods. */
public abstract class BaseShape implements Shape {

    private final int id;

    protected BaseShape(int id) {
        this.id = id;
    }

    public final int id() {
        return id;
    }

    @Override
    public String toString() {
        return describe() + "@" + id;
    }
}

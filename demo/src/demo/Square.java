package demo;

/** Square: a Rectangle subclass, exercising a deeper inheritance chain. */
public final class Square extends Rectangle {

    public Square(int id, double side) {
        super(id, side, side);
    }

    @Override
    public String label() {
        return "square";
    }
}

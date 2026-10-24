package demo;

/** Circle implementation. */
public final class Circle extends BaseShape {

    private final double radius;

    public Circle(int id, double radius) {
        super(id);
        this.radius = radius;
    }

    public double radius() {
        return radius;
    }

    @Override
    public double area() {
        return Math.PI * radius * radius;
    }

    @Override
    public double perimeter() {
        return 2.0 * Math.PI * radius;
    }

    @Override
    public String label() {
        return "circle";
    }
}

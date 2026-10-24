package demo;

/** Rectangle implementation (extended by {@link Square}). */
public class Rectangle extends BaseShape {

    private final double width;
    private final double height;

    public Rectangle(int id, double width, double height) {
        super(id);
        this.width = width;
        this.height = height;
    }

    public double width() {
        return width;
    }

    public double height() {
        return height;
    }

    @Override
    public double area() {
        return width * height;
    }

    @Override
    public double perimeter() {
        return 2.0 * (width + height);
    }

    @Override
    public String label() {
        return "rectangle";
    }
}

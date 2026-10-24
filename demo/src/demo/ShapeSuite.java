package demo;

/**
 * Inheritance, interfaces, default methods and dynamic dispatch coverage.
 */
public final class ShapeSuite {

    private ShapeSuite() {
    }

    public static void run() throws DemoException {
        Shape[] shapes = new Shape[]{
                new Circle(1, 2.0),
                new Rectangle(2, 3.0, 4.0),
                new Square(3, 5.0)
        };

        double area = 0.0;
        double perimeter = 0.0;
        for (Shape shape : shapes) {
            area += shape.area();
            perimeter += shape.perimeter();
        }
        Checks.eq(area, Math.PI * 4.0 + 12.0 + 25.0, 1e-9, "polymorphic area");
        Checks.eq(perimeter, Math.PI * 4.0 + 14.0 + 20.0, 1e-9, "polymorphic perimeter");

        Checks.eq(shapes[0].describe(), "circle:13", "default method circle");
        Checks.eq(shapes[1].describe(), "rectangle:12", "default method rectangle");
        Checks.eq(shapes[2].describe(), "square:25", "default method square");

        int circles = 0;
        int rectangles = 0;
        for (Shape shape : shapes) {
            if (shape instanceof Circle) {
                circles++;
            }
            if (shape instanceof Rectangle) {
                rectangles++;
            }
        }
        Checks.eq(circles, 1, "instanceof circle");
        Checks.eq(rectangles, 2, "instanceof rectangle includes square");

        Shape largest = shapes[0];
        for (Shape shape : shapes) {
            if (shape.area() > largest.area()) {
                largest = shape;
            }
        }
        Checks.check(largest instanceof Square, "virtual dispatch picks largest");
        Checks.eq(((BaseShape) largest).id(), 3, "base class final accessor");

        BaseShape base = new Square(4, 6.0);
        Checks.eq(base.area(), 36.0, 0.0, "base reference square area");
        Checks.eq(base.label(), "square", "base reference label dispatch");
        Checks.eq(base.id(), 4, "base state");
        Checks.eq(((Square) base).width(), 6.0, 0.0, "cast then accessor");
        Checks.eq(((Circle) shapes[0]).radius(), 2.0, 0.0, "circle accessor");
        Checks.eq(new Square(5, 3.0).toString(), "square:9@5", "overridden toString");

        Checks.eq(shapes[1].label(), "rectangle", "rectangle label");
        Checks.eq(shapes[0].label(), "circle", "circle label");
    }
}

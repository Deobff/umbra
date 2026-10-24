package demo;

/** Interface used to exercise virtual dispatch and default methods. */
public interface Shape {

    double area();

    double perimeter();

    String label();

    /** Java 8 default method: calls two abstract methods virtually. */
    default String describe() {
        return label() + ":" + Math.round(area());
    }
}

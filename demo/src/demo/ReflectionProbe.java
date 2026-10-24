package demo;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Reflection coverage: {@code Class.forName}, {@code getDeclaredMethod},
 * {@code getDeclaredField} and {@code setAccessible(true)} on private members.
 *
 * <p>Umbra's reflection analysis has to keep {@code demo.ReflectionProbe} and
 * the member names referenced here; renaming them without updating the lookup
 * strings would break this suite.</p>
 */
public final class ReflectionProbe {

    private int hidden = 7;
    private static final String TAG = "probe";

    private ReflectionProbe() {
    }

    private static int secretNumber(int value) {
        return value * 2 + 1;
    }

    private String tag() {
        return TAG;
    }

    public static void run() throws Exception {
        Class<?> type = Class.forName("demo.ReflectionProbe");
        Checks.eq(type.getName(), "demo.ReflectionProbe", "Class.forName");

        Object instance = type.getDeclaredConstructor().newInstance();
        Checks.notNull(instance, "reflective instance");

        Method secret = type.getDeclaredMethod("secretNumber", int.class);
        secret.setAccessible(true);
        Object result = secret.invoke(null, Integer.valueOf(20));
        Checks.eq(((Integer) result).intValue(), 41, "reflective static method invoke");

        Method tag = type.getDeclaredMethod("tag");
        tag.setAccessible(true);
        Checks.eq((String) tag.invoke(instance), "probe", "reflective instance method invoke");

        Field hidden = type.getDeclaredField("hidden");
        hidden.setAccessible(true);
        Checks.eq(hidden.getInt(instance), 7, "reflective field read");
        hidden.setInt(instance, 99);
        Checks.eq(hidden.getInt(instance), 99, "reflective field write");

        Checks.eq(type.getDeclaredMethods().length >= 3, true, "declared methods visible");
    }
}

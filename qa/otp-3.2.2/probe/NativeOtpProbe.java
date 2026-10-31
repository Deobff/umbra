import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Probe: is the OTP advance really bound to the generated native guard? */
public final class NativeOtpProbe {

    public static void main(String[] args) throws Exception {
        File jar = new File(args[0]);
        URLClassLoader loader = new URLClassLoader(new URL[] {jar.toURI().toURL()}, null);
        List<String> names = new ArrayList<String>();
        try (JarFile file = new JarFile(jar)) {
            Enumeration<JarEntry> entries = file.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
                    names.add(name.substring(0, name.length() - 6).replace('/', '.'));
                }
            }
        }
        Class<?> otp = null;
        Class<?> guard = null;
        for (String name : names) {
            Class<?> type;
            try {
                type = Class.forName(name, false, loader);
            } catch (Throwable ignored) {
                continue;
            }
            boolean carrier = false;
            boolean next = false;
            boolean nativeInit = false;
            for (java.lang.reflect.Method method : type.getDeclaredMethods()) {
                if ("carrier".equals(method.getName())) {
                    carrier = true;
                } else if ("next".equals(method.getName())) {
                    next = true;
                } else if ("nativeInit".equals(method.getName())
                        && java.lang.reflect.Modifier.isNative(method.getModifiers())) {
                    nativeInit = true;
                }
            }
            if (carrier && next && otp == null) {
                otp = type;
            }
            if (nativeInit && guard == null) {
                guard = type;
            }
        }
        System.out.println("otp class   = " + (otp == null ? "<none>" : otp.getName()));
        System.out.println("guard class = " + (guard == null ? "<none>" : guard.getName()));
        if (otp == null) {
            System.out.println("RESULT: no OTP class");
            return;
        }
        java.lang.reflect.Method carrier = otp.getMethod("carrier");
        java.lang.reflect.Method nativeBound = otp.getMethod("nativeBound");
        int before = ((Integer) nativeBound.invoke(null)).intValue();
        carrier.invoke(null);
        int after = ((Integer) nativeBound.invoke(null)).intValue();
        System.out.println("nativeBound before guard check = " + before);
        if (guard != null) {
            try {
                guard.getMethod("check").invoke(null);
                System.out.println("guard.check() returned");
            } catch (Throwable failure) {
                System.out.println("guard.check() threw " + failure.getCause());
            }
        }
        for (int i = 0; i < 4; i++) {
            carrier.invoke(null);
        }
        int bound = ((Integer) nativeBound.invoke(null)).intValue();
        System.out.println("nativeBound after guard check  = " + bound);
        System.out.println(bound == 1 ? "RESULT: native OTP advance is bound"
                : "RESULT: Java fallback only");
    }
}

import java.lang.instrument.Instrumentation;

public final class AttachProbe {
    public static void premain(String args, Instrumentation inst) {
        System.out.println("ATTACHED");
    }

    public static void agentmain(String args, Instrumentation inst) {
        System.out.println("ATTACHED");
    }
}

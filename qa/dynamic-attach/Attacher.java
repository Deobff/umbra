import com.sun.tools.attach.VirtualMachine;

public final class Attacher {
    public static void main(String[] args) throws Exception {
        VirtualMachine vm = VirtualMachine.attach(args[0]);
        try {
            vm.loadAgent(args[1]);
            System.out.println("ATTACH-OK");
        } finally {
            vm.detach();
        }
    }
}

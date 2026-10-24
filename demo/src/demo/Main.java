package demo;

/**
 * Entry point of the Umbra demo application.
 *
 * <p>The demo runs deterministic self-checks that cover the bytecode shapes an
 * obfuscator has to preserve: strings (including Unicode), int/long/double
 * arithmetic, loops/branches/switch, try/catch/finally and custom exceptions,
 * inheritance/interfaces/virtual dispatch, lambdas and method references,
 * 1D/2D arrays, static/instance fields, reflection, threads and resources
 * loaded from the jar.</p>
 *
 * <p>On success it prints exactly {@code OK} and exits with code 0. Any failed
 * check or unexpected exception prints a diagnostic to stderr and exits with
 * code 1. Pass {@code --verbose} to print the executed check count.</p>
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        boolean verbose = args.length > 0 && "--verbose".equals(args[0]);
        try {
            int before = Checks.count();
            StringSuite.run();
            MathSuite.run();
            FlowSuite.run();
            ExceptionSuite.run();
            ShapeSuite.run();
            FunctionalSuite.run();
            ArraySuite.run();
            InventorySuite.run();
            ReflectionProbe.run();
            WorkerSuite.run();
            ResourceSuite.run();
            int performed = Checks.count() - before;
            if (performed < 100) {
                throw new DemoException(DemoException.CODE_STATE,
                        "suite executed too few checks: " + performed);
            }
            if (verbose) {
                System.out.println("checks=" + performed);
            }
            System.out.println("OK");
        } catch (Throwable failure) {
            System.err.println("FAIL: " + failure);
            failure.printStackTrace();
            System.exit(1);
        }
    }
}

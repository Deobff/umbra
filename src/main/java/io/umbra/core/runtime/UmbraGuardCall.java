package io.umbra.core.runtime;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

/**
 * Invokedynamic bootstrap for guard entry-point checks.
 *
 * <p>Program classes used to reach a guard with a plain {@code invokestatic
 * guard.check()}, which put the guard class in the method body and made the
 * instrumentation obvious to {@code javap -c}. The call site is now an
 * {@code invokedynamic}: this bootstrap resolves {@code check()} once while the
 * site is linked and returns a constant call site, so the method body carries no
 * direct reference to the guard.</p>
 *
 * <p>The owning class is passed as the bootstrap argument and resolved with
 * {@code initialize=false}, so linking the call site does not run the guard's
 * static initializer earlier than the call itself would.</p>
 */
public final class UmbraGuardCall {

    private UmbraGuardCall() {
    }

    /**
     * Resolves {@code owner.check()} for one call site.
     *
     * @param caller lookup of the class containing the call site
     * @param name   method name, always {@code check}
     * @param type   call-site type, always {@code ()V}
     * @param owner  internal name of the guard class
     * @return constant call site bound to the guard's check method
     * @throws Throwable when the guard cannot be resolved
     */
    public static CallSite bootstrap(MethodHandles.Lookup caller, String name, MethodType type,
                                     String owner) throws Throwable {
        Class<?> target = Class.forName(owner.replace('/', '.'), false,
                caller.lookupClass().getClassLoader());
        MethodHandle handle = caller.findStatic(target, name, type);
        return new ConstantCallSite(handle);
    }
}

package io.umbra.core.pass.impl;

import io.umbra.core.api.Pass;
import io.umbra.core.api.PassContext;
import io.umbra.core.config.UmbraConfig;
import io.umbra.core.runtime.TemplateInjector;
import io.umbra.core.runtime.crypto.GuardSupport;
import io.umbra.core.runtime.crypto.UmbraWatchdog;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Configurable anti-debug / anti-instrumentation guard.
 *
 * <p>Injects the unified {@code UmbraRuntimeGuard} template and calls
 * {@code check()} at the start of every program entry point:</p>
 *
 * <ul>
 *   <li>{@code antiDebug.level} 0-3 (0 = off; 1 = JVM input arguments + agent
 *       args; 2 = + attach/JDWP/env/platform/timing detection; 3 = + randomized
 *       background watchdog).</li>
 *   <li>{@code antiDebug.thread}/{@code .jvmti}/{@code .attach}/{@code .env}/
 *       {@code .timing} sub-switches.</li>
 *   <li>{@code antiDebug.action} = {@code throw|exit|corrupt|log}.</li>
 *   <li>{@code antiDebug.watchdogMs} = randomized watchdog base interval.</li>
 * </ul>
 *
 * <p>The typed legacy switch {@code protection.antiDebug: true} keeps working
 * and maps to level 2. The guard is shared with the integrity pass and the
 * encrypted-archive loader through
 * {@link GuardSupport#ensureRuntimeGuard(io.umbra.core.model.ClassPool, long, Map)},
 * so all layers consult one injected detector. Without debugger evidence the
 * guard is silent, so a normal {@code java -jar} launch is unaffected (verified
 * on JDK 8/21/26; a clean HotSpot JVM has an "Attach Listener" daemon thread, so
 * that name alone is deliberately not a signal - only JDWP threads/properties,
 * attach-pid artifacts and a real JDWP handshake count).</p>
 */
public final class AntiDebugPass implements Pass {

    @Override
    public String name() {
        return "anti-debug";
    }

    @Override
    public int order() {
        return 115;
    }

    @Override
    public boolean enabled(PassContext context) {
        return resolveLevel(context.config()) > 0;
    }

    @Override
    public void run(PassContext context) {
        UmbraConfig config = context.config();
        int level = resolveLevel(config);
        if (level <= 0) {
            context.log().debug("anti-debug: disabled");
            return;
        }
        boolean thread = config.optionBool("antiDebug.thread", true);
        boolean jvmti = config.optionBool("antiDebug.jvmti", true);
        boolean attach = config.optionBool("antiDebug.attach", true);
        boolean environment = config.optionBool("antiDebug.env", true);
        boolean timing = config.optionBool("antiDebug.timing", true);
        boolean attachWatch = config.optionBool("antiDebug.attachWatch", true);
        boolean portProbe = config.optionBool("antiDebug.portProbe", false);
        long watchdogMs = Math.max(1000L, config.optionLong("antiDebug.watchdogMs", 4000L));
        String action = resolveAction(config);

        String watchdog = "";
        if (level >= 3 && thread) {
            watchdog = TemplateInjector.inject(context.classes(), UmbraWatchdog.class,
                    "umbra/runtime/W", config.seed()).replace('/', '.');
        }
        Map<String, String> replacements = new LinkedHashMap<String, String>();
        replacements.put("@@LEVEL@@", String.valueOf(level));
        replacements.put("@@THREAD@@", String.valueOf(level >= 3 && thread));
        replacements.put("@@JVMTI@@", String.valueOf(jvmti));
        replacements.put("@@ATTACH@@", String.valueOf(attach));
        replacements.put("@@ATTACHWATCH@@", String.valueOf(attachWatch));
        replacements.put("@@PORTPROBE@@", String.valueOf(portProbe));
        replacements.put("@@ENV@@", String.valueOf(environment));
        replacements.put("@@TIMING@@", String.valueOf(timing));
        replacements.put("@@ACTION@@", action);
        replacements.put("@@WATCHDOG@@", watchdog);
        replacements.put("@@WATCHMS@@", String.valueOf(watchdogMs));
        String guard = GuardSupport.ensureRuntimeGuard(context.classes(), config.seed(), replacements);

        String[] entry = GuardSupport.parseEntryPoint(
                config.optionBool("classEncryption.enabled", false)
                        ? config.option("classEncryption.entry", "") : "");
        int instrumented = entry == null
                ? GuardSupport.instrumentMains(context.classes(), guard)
                : GuardSupport.instrumentEntryPoints(context.classes(), guard, entry[0], entry[1]);
        if (instrumented == 0) {
            context.log().warn("anti-debug: no program entry point found; injected guard %s is "
                    + "referenced by the runtime layers only", guard);
        }
        if (instrumented > 0) {
            context.stats().add("protection.antiDebug", instrumented);
        }
        context.stats().add("antiDebug.level", level);
        context.stats().add("antiDebug.entryPoints", instrumented);
        context.stats().add("antiDebug.env", environment ? 1 : 0);
        context.stats().add("antiDebug.timing", timing ? 1 : 0);
        context.stats().add("antiDebug.attachWatch", attachWatch ? 1 : 0);
        context.stats().add("antiDebug.portProbe", portProbe ? 1 : 0);
        if (level >= 3 && thread) {
            context.stats().add("antiDebug.watchdog", watchdogMs);
        }
        context.log().info("anti-debug: level %d unified guard %s called from %d entry point(s) "
                        + "(action=%s, thread=%s, jvmti=%s, attach=%s, attachWatch=%s, portProbe=%s, "
                        + "env=%s, timing=%s, watchdog=%s)",
                level, guard, instrumented, action, Boolean.valueOf(thread), Boolean.valueOf(jvmti),
                Boolean.valueOf(attach), Boolean.valueOf(attachWatch), Boolean.valueOf(portProbe),
                Boolean.valueOf(environment), Boolean.valueOf(timing),
                watchdog.isEmpty() ? "-" : watchdog + " @ " + watchdogMs + "ms");
    }

    /**
     * Resolves the effective level from the advanced options and the legacy
     * typed switch. An explicit {@code antiDebug.level=0} always disables.
     */
    static int resolveLevel(UmbraConfig config) {
        if (config.options().containsKey("antiDebug.level")) {
            return clamp(config.optionInt("antiDebug.level", 0));
        }
        if (config.antiDebug() || config.optionBool("antiDebug.enabled", false)) {
            return 2;
        }
        return 0;
    }

    static String resolveAction(UmbraConfig config) {
        String value = config.option("antiDebug.action", "throw").trim().toLowerCase(java.util.Locale.ROOT);
        if ("exit".equals(value) || "throw".equals(value) || "corrupt".equals(value)
                || "log".equals(value)) {
            return value;
        }
        return "throw";
    }

    private static int clamp(int level) {
        if (level < 0) {
            return 0;
        }
        return Math.min(level, 3);
    }
}

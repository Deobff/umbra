package io.umbra.core.jni.guard;

/**
 * Feature set of the generated native guard.
 *
 * <p>{@code antiDebug.level} selects a safe default profile, individual
 * {@code antiDebug.*} knobs can override every check, and expensive deep checks
 * (thread/module/memory enumeration, external handle scan) are only run from the
 * startup check and the periodic watchdog pass, never from the per-native-method
 * tick. Level 1 keeps the cheap classic checks only; level 2 enables the dynamic
 * protection set; level 3 adds the opt-in handle/dump scan.</p>
 */
public final class GuardFeatures {

    /** {@code antiDebug.level} the features were derived from. */
    public final int level;
    public final boolean frida;
    public final boolean hash;
    /** Deep: threads whose start address is outside every known module. */
    public final boolean remoteThread;
    /** Deep: MEM_PRIVATE + executable memory outside the guard image. */
    public final boolean execMemoryScan;
    /** Quick: guard pages / unexpected protection inside the guard image. */
    public final boolean imageBreakpoints;
    /** Quick: randomized code-section byte sampling (built at protection time). */
    public final boolean codeSampling;
    /** Deep: unbacked / manually mapped module detection. */
    public final boolean moduleIntegrity;
    /** Quick: native check-call timing drift (debugger/suspend pauses). */
    public final boolean timing;
    /** Deep, level 3 opt-in: external process handle with VM_READ access. */
    public final boolean handleDump;
    /** Linux-only: native /proc/self checks, ptrace self-check. */
    public final boolean linuxChecks;
    /** Watchdog interval used for the timing-drift threshold (milliseconds). */
    public final long watchdogMs;
    /** Test-only JNI hooks (never enabled in production output). */
    public final boolean testHooks;
    /** Internal name of the synthetic class declaring the test hooks. */
    public final String testHookClass;

    private GuardFeatures(Builder builder) {
        this.level = builder.level;
        this.frida = builder.frida;
        this.hash = builder.hash;
        this.remoteThread = builder.remoteThread;
        this.execMemoryScan = builder.execMemoryScan;
        this.imageBreakpoints = builder.imageBreakpoints;
        this.codeSampling = builder.codeSampling;
        this.moduleIntegrity = builder.moduleIntegrity;
        this.timing = builder.timing;
        this.handleDump = builder.handleDump;
        this.linuxChecks = builder.linuxChecks;
        this.watchdogMs = builder.watchdogMs;
        this.testHooks = builder.testHooks;
        this.testHookClass = builder.testHookClass;
    }

    /** Classic 3.0 feature set (used by the legacy {@code generate} overload). */
    public static GuardFeatures legacy(boolean frida, boolean hash) {
        return builder(1).frida(frida).hash(hash).build();
    }

    /** Level profile: 1 = cheap classic checks, 2 = dynamic set, 3 = + handle scan. */
    public static Builder forLevel(int level) {
        int normalized = Math.max(1, Math.min(3, level));
        Builder builder = builder(normalized);
        if (normalized >= 2) {
            builder.remoteThread(true)
                    .execMemoryScan(true)
                    .imageBreakpoints(true)
                    .codeSampling(true)
                    .moduleIntegrity(true)
                    .timing(true)
                    .linuxChecks(true);
        }
        if (normalized >= 3) {
            builder.handleDump(true);
        }
        return builder;
    }

    private static Builder builder(int level) {
        Builder builder = new Builder();
        builder.level = level;
        return builder;
    }

    /** Number of independently enabled signal groups (for stats/logging). */
    public int enabledChecks() {
        int count = 0;
        if (frida) {
            count++;
        }
        if (hash) {
            count++;
        }
        if (remoteThread) {
            count++;
        }
        if (execMemoryScan) {
            count++;
        }
        if (imageBreakpoints) {
            count++;
        }
        if (codeSampling) {
            count++;
        }
        if (moduleIntegrity) {
            count++;
        }
        if (timing) {
            count++;
        }
        if (handleDump) {
            count++;
        }
        if (linuxChecks) {
            count++;
        }
        return count;
    }

    /** Short {@code key=value} list for logs and stats. */
    public String describe() {
        return "level=" + level
                + ", frida=" + frida
                + ", hash=" + hash
                + ", remoteThread=" + remoteThread
                + ", execMemoryScan=" + execMemoryScan
                + ", imageBreakpoints=" + imageBreakpoints
                + ", codeSampling=" + codeSampling
                + ", moduleIntegrity=" + moduleIntegrity
                + ", timing=" + timing
                + ", handleDump=" + handleDump
                + ", linuxChecks=" + linuxChecks
                + ", watchdogMs=" + watchdogMs;
    }

    /** Mutable builder (keeps the generated C call sites readable). */
    public static final class Builder {
        private int level = 1;
        private boolean frida = true;
        private boolean hash = true;
        private boolean remoteThread;
        private boolean execMemoryScan;
        private boolean imageBreakpoints;
        private boolean codeSampling;
        private boolean moduleIntegrity;
        private boolean timing;
        private boolean handleDump;
        private boolean linuxChecks;
        private long watchdogMs = 4000L;
        private boolean testHooks;
        private String testHookClass;

        public Builder level(int value) {
            this.level = Math.max(1, Math.min(3, value));
            return this;
        }

        public Builder frida(boolean value) {
            this.frida = value;
            return this;
        }

        public Builder hash(boolean value) {
            this.hash = value;
            return this;
        }

        public Builder remoteThread(boolean value) {
            this.remoteThread = value;
            return this;
        }

        public Builder execMemoryScan(boolean value) {
            this.execMemoryScan = value;
            return this;
        }

        public Builder imageBreakpoints(boolean value) {
            this.imageBreakpoints = value;
            return this;
        }

        public Builder codeSampling(boolean value) {
            this.codeSampling = value;
            return this;
        }

        public Builder moduleIntegrity(boolean value) {
            this.moduleIntegrity = value;
            return this;
        }

        public Builder timing(boolean value) {
            this.timing = value;
            return this;
        }

        public Builder handleDump(boolean value) {
            this.handleDump = value;
            return this;
        }

        public Builder linuxChecks(boolean value) {
            this.linuxChecks = value;
            return this;
        }

        public Builder watchdogMs(long value) {
            this.watchdogMs = Math.max(0L, value);
            return this;
        }

        public Builder testHooks(String hookClass) {
            this.testHooks = hookClass != null && !hookClass.isEmpty();
            this.testHookClass = hookClass;
            return this;
        }

        public GuardFeatures build() {
            return new GuardFeatures(this);
        }
    }
}

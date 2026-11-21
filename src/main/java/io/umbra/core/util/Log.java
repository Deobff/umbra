package io.umbra.core.util;

/** Minimal logging facade shared by the engine, CLI and GUI. */
public final class Log {

    public interface Sink {
        void line(String level, String message);
    }

    /** How many lines are kept for a failure report; the run log is unbounded otherwise. */
    private static final int RECENT = 400;

    private final Sink sink;
    private final boolean verbose;
    private final java.util.ArrayDeque<String> recent = new java.util.ArrayDeque<String>();

    public Log(Sink sink, boolean verbose) {
        this.sink = sink;
        this.verbose = verbose;
    }

    public static Log console(boolean verbose) {
        return new Log(new Sink() {
            @Override
            public void line(String level, String message) {
                if ("ERROR".equals(level)) {
                    System.err.println("[" + level + "] " + message);
                } else {
                    System.out.println("[" + level + "] " + message);
                }
            }
        }, verbose);
    }

    public boolean verbose() {
        return verbose;
    }

    public void info(String format, Object... args) {
        emit("INFO", format, args);
    }

    public void debug(String format, Object... args) {
        if (verbose) {
            emit("DEBUG", format, args);
        }
    }

    public void warn(String format, Object... args) {
        emit("WARN", format, args);
    }

    public void error(String format, Object... args) {
        emit("ERROR", format, args);
    }

    private void emit(String level, String format, Object[] args) {
        String message = args == null || args.length == 0 ? format : String.format(format, args);
        remember(level, message);
        if (sink != null) {
            sink.line(level, message);
        }
    }

    /**
     * Keeps the newest lines so a failure can report what the run was doing.
     * The buffer is bounded and independent of the sink, so it works for the
     * CLI, the desktop console and the build plugins alike.
     */
    private void remember(String level, String message) {
        synchronized (recent) {
            recent.addLast("[" + level + "] " + message);
            while (recent.size() > RECENT) {
                recent.removeFirst();
            }
        }
    }

    /** The newest {@code count} log lines, oldest first. */
    public java.util.List<String> tail(int count) {
        java.util.List<String> out = new java.util.ArrayList<String>();
        synchronized (recent) {
            int skip = Math.max(0, recent.size() - Math.max(0, count));
            int index = 0;
            for (String line : recent) {
                if (index++ >= skip) {
                    out.add(line);
                }
            }
        }
        return out;
    }
}

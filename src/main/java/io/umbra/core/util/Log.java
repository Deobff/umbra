package io.umbra.core.util;

/** Minimal logging facade shared by the engine, CLI and GUI. */
public final class Log {

    /** Receives formatted log lines. */
    public interface Sink {
        void line(String level, String message);
    }

    private final Sink sink;
    private final boolean verbose;

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
        if (sink != null) {
            sink.line(level, message);
        }
    }
}

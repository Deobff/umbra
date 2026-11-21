package io.umbra.core.util;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Publishing a finished archive onto its final path.
 *
 * <p>The output jar is replaced more than once per run (the writer, then the
 * integrity and class-encryption post-processors). On Windows that replace fails
 * while another process holds the destination open: an antivirus scanner that
 * just noticed the new file, the IDE, a decompiler, or a previously protected jar
 * the user launched. That is exactly how a run that worked a minute ago dies with
 * exit code 1 and a {@code FileSystemException} nobody sees.</p>
 *
 * <p>This helper retries the replace for a short window, gives every run its own
 * temporary name (two concurrent runs writing the same -o used to interleave into
 * one {@code .umbra-tmp}), and reports the destination path when the lock is real
 * instead of a bare "Access is denied".</p>
 */
public final class SafeArchive {

    /** How often the replace is retried before the lock is reported as real. */
    private static final int ATTEMPTS = 12;

    /** Linear backoff base, capped per attempt; the total wait is about 5 seconds. */
    private static final long BASE_DELAY_MS = 80L;

    /** Longest single pause, so a real lock still fails promptly. */
    private static final long MAX_DELAY_MS = 800L;

    /** Kept in the name so leftovers are recognisable in the output directory. */
    private static final String TEMP_SUFFIX = ".umbra-tmp";

    private static final AtomicInteger COUNTER = new AtomicInteger();

    private SafeArchive() {
    }

    /**
     * A temporary sibling of {@code target} that no other run can collide with.
     * The file is created by the caller with a truncating stream.
     */
    public static Path temporary(Path target) {
        Path absolute = target.toAbsolutePath();
        String name = absolute.getFileName() == null ? "umbra" : absolute.getFileName().toString();
        String unique = Long.toHexString(System.nanoTime()) + "-" + COUNTER.incrementAndGet();
        Path parent = absolute.getParent();
        String fileName = name + "." + unique + TEMP_SUFFIX;
        return parent == null ? absolute.getFileSystem().getPath(fileName)
                : parent.resolve(fileName);
    }

    /**
     * Moves {@code temp} onto {@code target}, retrying while the destination is
     * held by another process. Throws with the destination path in the message
     * when the lock does not clear.
     */
    public static void publish(Path temp, Path target) throws IOException {
        IOException last = null;
        for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
            try {
                move(temp, target);
                return;
            } catch (IOException failure) {
                last = failure;
                if (!isLock(failure) || attempt == ATTEMPTS) {
                    break;
                }
                if (!pause(Math.min(MAX_DELAY_MS, BASE_DELAY_MS * attempt))) {
                    break;
                }
            }
        }
        deleteQuietly(temp);
        String hint = isLock(last)
                ? " (the file is held by another process: close the running protected jar, the IDE, "
                        + "the decompiler or the antivirus scan, or write to a different path)"
                : "";
        throw new IOException("cannot publish " + target + hint + ": "
                + (last == null ? "unknown failure" : describe(last)), last);
    }

    private static void move(Path temp, Path target) throws IOException {
        try {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException notAtomic) {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** True when the failure is the Windows "file in use" family. */
    public static boolean isLock(Throwable failure) {
        Throwable current = failure;
        int guard = 0;
        while (current != null && guard++ < 8) {
            if (current instanceof AccessDeniedException) {
                return true;
            }
            if (current instanceof FileSystemException) {
                String reason = ((FileSystemException) current).getReason();
                if (reason == null || looksLocked(reason.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
            String message = current.getMessage();
            if (message != null && looksLocked(message.toLowerCase(Locale.ROOT))) {
                return true;
            }
            Throwable next = current.getCause();
            current = next == current ? null : next;
        }
        return false;
    }

    private static boolean looksLocked(String message) {
        return message.contains("being used by another process")
                || message.contains("another process")
                || message.contains("另一个程序")
                || message.contains("cannot access the file")
                || message.contains("access is denied")
                || message.contains("拒绝访问")
                || message.contains("sharing violation");
    }

    private static boolean pause(long millis) {
        try {
            Thread.sleep(millis);
            return true;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * "create-file-exception: E:\a -> E:\b": the IOException toString used to be
     * just the two paths, which read like a message but said nothing.
     */
    private static String describe(Throwable failure) {
        String type = failure.getClass().getSimpleName();
        String message = failure.getMessage();
        if (message != null && !message.trim().isEmpty()) {
            return type + ": " + message;
        }
        if (failure instanceof FileSystemException) {
            FileSystemException system = (FileSystemException) failure;
            String reason = system.getReason();
            return type + ": " + (reason == null || reason.trim().isEmpty() ? "no reason given" : reason);
        }
        return type;
    }

    /** Deletes a temporary file and keeps the failure it caused out of the way. */
    public static void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            
        }
    }
}

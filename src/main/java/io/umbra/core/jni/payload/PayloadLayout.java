package io.umbra.core.jni.payload;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The {@code layout.txt} offset table that turns one payload stream into one
 * platform slice.
 *
 * <p>One line per target, three whitespace-separated columns, offsets measured
 * in the <em>decompressed</em> payload:</p>
 *
 * <pre>
 *   WINDOWS_X86_64 0 7558656
 *   LINUX_X86_64 7558656 13663248
 * </pre>
 *
 * <p>The order of the lines is the concatenation order, so the table and the
 * payload must be produced together.</p>
 */
public final class PayloadLayout {

    private final Map<String, long[]> ranges = new LinkedHashMap<String, long[]>();

    public static PayloadLayout parse(String text) {
        PayloadLayout layout = new PayloadLayout();
        if (text == null) {
            return layout;
        }
        for (String line : text.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            String[] parts = columns(trimmed);
            if (parts.length < 3) {
                continue;
            }
            try {
                long start = Long.parseLong(parts[1]);
                long end = Long.parseLong(parts[2]);
                if (start < 0 || end < start) {
                    continue;
                }
                layout.ranges.put(parts[0], new long[]{start, end});
            } catch (NumberFormatException ignored) {
                // A malformed line must not make the whole payload unreadable.
            }
        }
        return layout;
    }

    public boolean isEmpty() {
        return this.ranges.isEmpty();
    }

    public boolean contains(String target) {
        return this.ranges.containsKey(target);
    }

    /** @return {@code {start, end}} or {@code null} when the target is absent. */
    public long[] range(String target) {
        return this.ranges.get(target);
    }

    public int size() {
        return this.ranges.size();
    }

    /** Splits on runs of whitespace without a regex (Java 8 has no \\s). */
    private static String[] columns(String value) {
        java.util.List<String> parts = new java.util.ArrayList<String>();
        int index = 0;
        while (index < value.length()) {
            while (index < value.length() && Character.isWhitespace(value.charAt(index))) {
                index++;
            }
            int start = index;
            while (index < value.length() && !Character.isWhitespace(value.charAt(index))) {
                index++;
            }
            if (index > start) {
                parts.add(value.substring(start, index));
            }
        }
        return parts.toArray(new String[0]);
    }

    public static String line(String target, long start, long end) {
        return target + " " + start + " " + end + "\n";
    }

    /**
     * Maps the running JVM to one of the six target names.
     *
     * <p>Same normalisation as the reference implementation's {@code platformKey}: the three x86
     * spellings and the two arm spellings are folded together, and the OS is
     * matched by substring so "Windows 11" needs no table.</p>
     */
    public static String targetFor(String osName, String archName) {
        String os = osName == null ? "" : osName.toLowerCase(Locale.ROOT);
        String arch = archName == null ? "" : archName.toLowerCase(Locale.ROOT);
        boolean x86 = arch.contains("x86_64") || arch.contains("amd64") || arch.contains("x64");
        boolean arm = arch.contains("aarch64") || arch.contains("arm64");
        if (os.contains("win")) {
            if (x86) {
                return "WINDOWS_X86_64";
            }
            if (arm) {
                return "WINDOWS_AARCH64";
            }
            return null;
        }
        if (os.contains("mac") || os.contains("darwin")) {
            if (x86) {
                return "MACOS_X86_64";
            }
            if (arm) {
                return "MACOS_AARCH64";
            }
            return null;
        }
        if (os.contains("lin")) {
            if (x86) {
                return "LINUX_X86_64";
            }
            if (arm) {
                return "LINUX_AARCH64";
            }
        }
        return null;
    }

    /** Target name for the compiler triple family used by the build host. */
    public static String targetForHost(String target, String arch) {
        String os = target == null ? "" : target.toLowerCase(Locale.ROOT);
        String cpu = arch == null || arch.isEmpty() || "auto".equalsIgnoreCase(arch)
                ? (isArmHost() ? "aarch64" : "x86_64")
                : arch.toLowerCase(Locale.ROOT);
        String prefix;
        if (os.contains("win")) {
            prefix = "WINDOWS_";
        } else if (os.contains("mac") || os.contains("darwin")) {
            prefix = "MACOS_";
        } else {
            prefix = "LINUX_";
        }
        return prefix + (cpu.contains("arm") || cpu.contains("aarch64") ? "AARCH64" : "X86_64");
    }

    private static boolean isArmHost() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        return arch.contains("aarch64") || arch.contains("arm64");
    }
}

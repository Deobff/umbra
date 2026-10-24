package io.umbra.core.jni.guard;

/**
 * Minimal PE/COFF reader used by the guard pass to compute the expected code
 * prologues of the exported guard functions.
 *
 * <p>The native guard compares the first bytes of its own functions (as loaded
 * in memory) against these file bytes, which detects inline hooks / trampolines
 * placed on the guard's check and token functions. When a symbol cannot be
 * resolved the pass simply skips that check, so a toolchain/linker variation can
 * never produce a false positive.</p>
 */
public final class PeImage {

    private PeImage() {
    }

    /** Returns the file offset of the function exported as {@code symbol}, or -1. */
    public static long exportFileOffset(byte[] image, String symbol) {
        if (image == null || image.length < 0x100 || symbol == null) {
            return -1L;
        }
        try {
            if (u16(image, 0) != 0x5A4D) { // MZ
                return -1L;
            }
            int pe = u32(image, 0x3C);
            if (pe <= 0 || pe + 24 >= image.length || u32(image, pe) != 0x00004550) { // PE\0\0
                return -1L;
            }
            int coff = pe + 4;
            int sections = u16(image, coff + 2);
            int optionalSize = u16(image, coff + 16);
            int optional = coff + 20;
            if (optional + optionalSize > image.length) {
                return -1L;
            }
            int magic = u16(image, optional);
            boolean pe32Plus = magic == 0x20B;
            int directoryOffset = optional + (pe32Plus ? 112 : 96);
            int exportRva = u32(image, directoryOffset);
            int exportSize = u32(image, directoryOffset + 4);
            if (exportRva == 0 || exportSize == 0) {
                return -1L;
            }
            int export = rvaToFileOffset(image, sections, optional + optionalSize, exportRva);
            if (export < 0) {
                return -1L;
            }
            int nameCount = u32(image, export + 24);
            int functionTable = u32(image, export + 28);
            int nameTable = u32(image, export + 32);
            int ordinalTable = u32(image, export + 36);
            int nameTableOffset = rvaToFileOffset(image, sections, optional + optionalSize, nameTable);
            int ordinalTableOffset = rvaToFileOffset(image, sections, optional + optionalSize, ordinalTable);
            int functionTableOffset = rvaToFileOffset(image, sections, optional + optionalSize, functionTable);
            if (nameTableOffset < 0 || ordinalTableOffset < 0 || functionTableOffset < 0) {
                return -1L;
            }
            for (int i = 0; i < nameCount; i++) {
                int nameRva = u32(image, nameTableOffset + i * 4);
                int nameOffset = rvaToFileOffset(image, sections, optional + optionalSize, nameRva);
                if (nameOffset < 0) {
                    continue;
                }
                String name = cString(image, nameOffset);
                if (!symbol.equals(name)) {
                    continue;
                }
                int ordinal = u16(image, ordinalTableOffset + i * 2);
                int functionRva = u32(image, functionTableOffset + ordinal * 4);
                return rvaToFileOffset(image, sections, optional + optionalSize, functionRva);
            }
        } catch (RuntimeException ignored) {
            return -1L;
        }
        return -1L;
    }

    /**
     * Returns the first {@code length} file bytes of an exported function, or an
     * empty array when the symbol cannot be resolved.
     */
    public static byte[] exportPrologue(byte[] image, String symbol, int length) {
        long offset = exportFileOffset(image, symbol);
        if (offset < 0 || offset + length > image.length) {
            return new byte[0];
        }
        byte[] out = new byte[length];
        System.arraycopy(image, (int) offset, out, 0, length);
        return out;
    }

    /** One randomized code-section sample: RVA + the file bytes expected there. */
    public static final class CodeSample {
        public final int rva;
        public final byte[] bytes;

        CodeSample(int rva, byte[] bytes) {
            this.rva = rva;
            this.bytes = bytes;
        }
    }

    /**
     * Picks {@code count} randomized windows inside the image's executable
     * section. The guard compares the loaded bytes at those RVAs against these
     * values, so inline hooks/patching at randomized positions are detected
     * (positions differ per build because the seed differs).
     *
     * @param image  compiled PE image
     * @param seed   protection seed (deterministic per build, unpredictable across builds)
     * @param count  number of samples
     * @param window bytes per sample (1..64)
     * @return samples; empty when the image is not a parseable PE executable
     */
    public static CodeSample[] codeSamples(byte[] image, long seed, int count, int window) {
        int size = Math.max(1, Math.min(64, window));
        int wanted = Math.max(0, count);
        if (image == null || image.length < 0x100 || wanted == 0) {
            return new CodeSample[0];
        }
        try {
            if (u16(image, 0) != 0x5A4D) { // MZ
                return new CodeSample[0];
            }
            int pe = u32(image, 0x3C);
            if (pe <= 0 || pe + 24 >= image.length || u32(image, pe) != 0x00004550) {
                return new CodeSample[0];
            }
            int coff = pe + 4;
            int sections = u16(image, coff + 2);
            int optionalSize = u16(image, coff + 16);
            int sectionTable = coff + 20 + optionalSize;
            int bestRaw = -1;
            int bestRawSize = 0;
            int bestSampleSize = 0;
            int bestVirtualAddress = 0;
            for (int i = 0; i < sections; i++) {
                int section = sectionTable + i * 40;
                if (section + 40 > image.length) {
                    return new CodeSample[0];
                }
                int characteristics = u32(image, section + 36);
                int rawSize = u32(image, section + 16);
                int rawPointer = u32(image, section + 20);
                if ((characteristics & 0x20000000) == 0 // IMAGE_SCN_MEM_EXECUTE
                        || rawSize < size || rawPointer <= 0
                        || rawPointer + size > image.length) {
                    continue;
                }
                int virtualSize = u32(image, section + 8);
                int span = Math.max(virtualSize, rawSize);
                if (span > bestRawSize) {
                    bestRaw = rawPointer;
                    bestRawSize = Math.min(rawSize, image.length - rawPointer);
                    bestVirtualAddress = u32(image, section + 12);
                    // Samples must stay inside the bytes the loader actually
                    // maps: file alignment padding past VirtualSize is not part
                    // of the loaded image.
                    int mapped = Math.min(bestRawSize, virtualSize);
                    bestSampleSize = Math.max(0, mapped);
                }
            }
            if (bestRaw < 0 || bestSampleSize <= size) {
                return new CodeSample[0];
            }
            java.util.Random random = new java.util.Random(seed);
            CodeSample[] samples = new CodeSample[wanted];
            int usable = bestSampleSize - size;
            for (int i = 0; i < wanted; i++) {
                int offset = usable <= 0 ? 0 : random.nextInt(usable + 1);
                // keep samples 8-byte aligned so patched-byte values stay stable
                offset &= ~7;
                if (offset + size > bestSampleSize) {
                    offset = Math.max(0, bestSampleSize - size);
                }
                byte[] bytes = new byte[size];
                System.arraycopy(image, bestRaw + offset, bytes, 0, size);
                samples[i] = new CodeSample(bestVirtualAddress + offset, bytes);
            }
            return samples;
        } catch (RuntimeException ignored) {
            return new CodeSample[0];
        }
    }

    /** File offset of the exported code-sample table, or -1. */
    public static long codeSampleTableOffset(byte[] image) {
        return exportFileOffset(image, "umbra_code_sample_table");
    }

    /**
     * Patches the compiled guard image with the randomized code-section samples.
     *
     * <p>The generated guard exports a fixed-size data table
     * ({@code umbra_code_sample_table}: count, window, RVAs, expected bytes) whose
     * compiled placeholder has {@code count = 0}. This method computes the samples
     * from the linked image, writes them into the table in the file, and returns
     * the patched image; the runtime check becomes active exactly when the table
     * count is non-zero, so a failed patch degrades to "no check" instead of a
     * false positive. The guard is therefore compiled only once per protection.</p>
     *
     * @return patched image or {@code null} when the table/table values are absent
     */
    public static byte[] withCodeSamples(byte[] image, long seed) {
        if (image == null) {
            return null;
        }
        long table = codeSampleTableOffset(image);
        if (table < 0 || table + 8 > image.length) {
            return null;
        }
        int slots = 12;
        CodeSample[] samples = codeSamples(image, seed, slots, 8);
        if (samples.length == 0) {
            return null;
        }
        int window = samples[0].bytes.length;
        int required = 8 + slots * 4 + slots * window;
        if (table + required > image.length) {
            return null;
        }
        byte[] patched = image.clone();
        int position = (int) table;
        writeInt(patched, position, samples.length);
        writeInt(patched, position + 4, window);
        int rvaStart = position + 8;
        int bytesStart = rvaStart + slots * 4;
        for (int i = 0; i < samples.length; i++) {
            writeInt(patched, rvaStart + i * 4, samples[i].rva);
            System.arraycopy(samples[i].bytes, 0, patched, bytesStart + i * window, window);
        }
        for (int i = samples.length; i < slots; i++) {
            writeInt(patched, rvaStart + i * 4, 0);
        }
        return patched;
    }

    private static void writeInt(byte[] data, int offset, int value) {
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
        data[offset + 2] = (byte) (value >>> 16);
        data[offset + 3] = (byte) (value >>> 24);
    }
    private static int rvaToFileOffset(byte[] image, int sectionCount, int sectionTable, int rva) {
        for (int i = 0; i < sectionCount; i++) {
            int section = sectionTable + i * 40;
            if (section + 40 > image.length) {
                return -1;
            }
            int virtualSize = u32(image, section + 8);
            int virtualAddress = u32(image, section + 12);
            int rawSize = u32(image, section + 16);
            int rawPointer = u32(image, section + 20);
            long span = Math.max(virtualSize, rawSize);
            if (rva >= virtualAddress && rva < virtualAddress + span) {
                long offset = rawPointer + (rva - virtualAddress);
                return offset >= 0 && offset < image.length ? (int) offset : -1;
            }
        }
        return -1;
    }

    private static String cString(byte[] image, int offset) {
        StringBuilder out = new StringBuilder();
        for (int i = offset; i < image.length && i < offset + 512; i++) {
            int b = image[i] & 0xFF;
            if (b == 0) {
                break;
            }
            out.append((char) b);
        }
        return out.toString();
    }

    private static int u16(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    private static int u32(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }
}

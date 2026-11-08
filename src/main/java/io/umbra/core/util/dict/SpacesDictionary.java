package io.umbra.core.util.dict;

public class SpacesDictionary extends Dictionary {
    private static final char[] CHARSET = new char[0xF + 1];

    static {
        for (int i = 0; i < CHARSET.length; i++) {
            CHARSET[i] = (char) ('\u2000' + i);
        }
    }

    public SpacesDictionary() {
        super("spaces");
    }

    @Override
    public String next() {
        return generate(offset.get() + uniqueIndex.getAndIncrement());
    }

    @Override
    public int size() {
        return 0xF + 1;
    }

    @Override
    public String generate(long index) {
        int totalCharacterCount = size();
        int baseIndex = (int) (index / totalCharacterCount);
        int offset = (int) (index % totalCharacterCount);
        char newChar = CHARSET[offset];
        return baseIndex == 0 ? String.valueOf(newChar) : (generate(baseIndex - 1) + newChar);
    }

    @Override
    public Dictionary copy() {
        SpacesDictionary copy = new SpacesDictionary();
        copy.getOffset().set(this.getOffset().get());
        return copy;
    }
}

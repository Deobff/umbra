package io.umbra.core.util.dict;

import java.util.concurrent.atomic.AtomicLong;

public abstract class Dictionary {
    private String name;
    protected final AtomicLong uniqueIndex = new AtomicLong(0);
    protected final AtomicLong offset = new AtomicLong(0);

    public Dictionary(String name) {
        this.name = name;
    }

    public abstract Dictionary copy();

    public abstract String next();

    public abstract int size();

    public abstract String generate(long index);

    public final String getDictionaryName() {
        return this.name;
    }

    public final void setUniqueIndex(long index) {
        this.uniqueIndex.set(index);
    }

    public final long getUniqueIndex() {
        return this.uniqueIndex.get();
    }

    public AtomicLong getOffset() {
        return offset;
    }

    public final void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}

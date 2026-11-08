package io.umbra.core.util.dict;

import java.util.ArrayList;
import java.util.List;

public class StringSequence {
    private final String[] sequence;

    public StringSequence(CharSequence sequence) {
        this(sequence.toString().toCharArray());
    }

    public StringSequence(char[] sequence) {
        this(new String(sequence).split(""));
    }

    public StringSequence(String[] sequence) {
        this.sequence = sequence;
    }

    public StringSequence(Iterable<? extends CharSequence> collection) {
        List<String> strList = new ArrayList<String>();
        for (CharSequence charSequence : collection) {
            strList.add(charSequence.toString());
        }
        this.sequence = strList.toArray(new String[0]);
    }

    public int size() {
        return sequence.length;
    }

    public String stringAt(int index) {
        return sequence[index];
    }

    public StringSequence subSequence(int start, int end) {
        String[] out = new String[end - start];
        System.arraycopy(sequence, start, out, 0, end - start);
        return new StringSequence(out);
    }

    public String[] getSequence() {
        return sequence;
    }

    @Override
    public String toString() {
        return String.join("", sequence);
    }
}

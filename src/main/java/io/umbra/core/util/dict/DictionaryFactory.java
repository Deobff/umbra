package io.umbra.core.util.dict;

import java.util.List;

public class DictionaryFactory {

    public static Dictionary get(String s) {
        Dictionary[] dictionaries = {
                new SpacesDictionary(),
                new KeywordDictionary(),
        };
        for (Dictionary dictionary : dictionaries) {
            if (dictionary.getDictionaryName().equals(s)) {
                return dictionary;
            }
        }
        if (s.contains(";") || s.contains(">") || s.contains("%") || s.contains("/") || s.contains(".")) {
            throw new RuntimeException("';' '>' '%' '/' '.' is not valid as a dictionary character");
        }
        return new CustomDictionary(s);
    }

    public static Dictionary getCustom(List<String> charset) {
        for (String s : charset) {
            if (s.contains(";") || s.contains(">") || s.contains("%") || s.contains("/") || s.contains(".")) {
                throw new RuntimeException("';' '>' '%' '/' '.' is not valid as a dictionary character");
            }
        }
        return new CustomDictionary(charset);
    }
}

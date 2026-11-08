package io.umbra.core.util.dict;

import java.util.ArrayList;
import java.util.List;

public class KeywordDictionary extends CustomDictionary {
    private static final List<String> KEYWORDS;

    static {
        KEYWORDS = new ArrayList<String>();
        KEYWORDS.add("private");
        KEYWORDS.add("protected");
        KEYWORDS.add("public");
        KEYWORDS.add("abstract");
        KEYWORDS.add("class");
        KEYWORDS.add("extends");
        KEYWORDS.add("final");
        KEYWORDS.add("implements");
        KEYWORDS.add("interface");
        KEYWORDS.add("native");
        KEYWORDS.add("new");
        KEYWORDS.add("static");
        KEYWORDS.add("strictfp");
        KEYWORDS.add("synchronized");
        KEYWORDS.add("transient");
        KEYWORDS.add("volatile");
        KEYWORDS.add("break");
        KEYWORDS.add("case");
        KEYWORDS.add("continue");
        KEYWORDS.add("do");
        KEYWORDS.add("else");
        KEYWORDS.add("for");
        KEYWORDS.add("if");
        KEYWORDS.add("instanceof");
        KEYWORDS.add("return");
        KEYWORDS.add("switch");
        KEYWORDS.add("while");
        KEYWORDS.add("assert");
        KEYWORDS.add("case");
        KEYWORDS.add("finally");
        KEYWORDS.add("throw");
        KEYWORDS.add("throws");
        KEYWORDS.add("try");
        KEYWORDS.add("import");
        KEYWORDS.add("package");
        KEYWORDS.add("boolean");
        KEYWORDS.add("byte");
        KEYWORDS.add("char");
        KEYWORDS.add("double");
        KEYWORDS.add("float");
        KEYWORDS.add("int");
        KEYWORDS.add("long");
        KEYWORDS.add("short");
        KEYWORDS.add("super");
        KEYWORDS.add("this");
        KEYWORDS.add("void");
        KEYWORDS.add("goto");
        KEYWORDS.add("const");
    }

    public KeywordDictionary() {
        super(KEYWORDS);
        setName("keywords");
    }
}

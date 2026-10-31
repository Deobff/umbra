package com.example;

/** Sample entry point: the protected jar must still print OK. */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        System.out.println(Greeter.message());
    }
}

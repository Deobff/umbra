package io.umbra.core.util.mba;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class RandomUtils {
    public static int getRandomInt() {
        return ThreadLocalRandom.current().nextInt();
    }

    public static int getRandomInt(int bounds) {
        return ThreadLocalRandom.current().nextInt(bounds);
    }

    public static int getRandomInt(int origin, int bounds) {
        return ThreadLocalRandom.current().nextInt(origin, bounds);
    }

    public static boolean getRandomBoolean() {
        return getRandomFloat() > 0.5;
    }

    public static <T> T getRandomElement(List<T> list) {
        return list.get(getRandomInt(list.size()));
    }

    public static long getRandomLong() {
        return ThreadLocalRandom.current().nextLong();
    }

    public static long getRandomLong(long bounds) {
        return ThreadLocalRandom.current().nextLong(bounds);
    }

    public static float getRandomFloat() {
        return ThreadLocalRandom.current().nextFloat();
    }

    public static float getRandomFloat(float bounds) {
        return (float) ThreadLocalRandom.current().nextDouble(bounds);
    }

    public static double getRandomDouble() {
        return ThreadLocalRandom.current().nextDouble();
    }

    public static double getRandomDouble(double bounds) {
        return ThreadLocalRandom.current().nextDouble(bounds);
    }

    public static String getRandomLetters(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = ThreadLocalRandom.current().nextInt(str.length());
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }
}

package demo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.IntUnaryOperator;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Lambdas, method references, constructor references and Java 8 streams.
 */
public final class FunctionalSuite {

    private FunctionalSuite() {
    }

    public static void run() throws DemoException {
        IntUnaryOperator square = value -> value * value;
        Checks.eq(square.applyAsInt(9), 81, "lambda square");
        Checks.eq(square.applyAsInt(-4), 16, "lambda square negative");

        Function<String, Integer> length = String::length;
        Checks.eq(length.apply("umbrella"), 8, "method reference length");

        Function<String, Integer> parse = Integer::parseInt;
        Checks.eq(parse.apply("123"), 123, "method reference parseInt");

        Function<String, String> upper = String::toUpperCase;
        Checks.eq(upper.apply("umbra"), "UMBRA", "method reference toUpperCase");

        BiFunction<Integer, Integer, Integer> add = (left, right) -> left + right;
        Checks.eq(add.apply(20, 22), 42, "bifunction lambda");

        Supplier<List<String>> factory = ArrayList::new;
        List<String> created = factory.get();
        created.add("lambda");
        created.add("methodref");
        Checks.eq(created.size(), 2, "constructor reference");

        Comparator<String> comparator =
                Comparator.comparingInt(String::length).thenComparing(Comparator.naturalOrder());
        List<String> words = new ArrayList<String>(Arrays.asList("bb", "a", "ccc", "aa"));
        Collections.sort(words, comparator);
        Checks.eq(String.join(",", words), "a,aa,bb,ccc", "comparator chain");

        Predicate<String> startsWithUmbra = text -> text.startsWith("umbra");
        Checks.eq(startsWithUmbra.test("umbra-demo"), true, "predicate true");
        Checks.eq(startsWithUmbra.test("Umbra-demo"), false, "predicate case sensitive");
        Checks.eq(startsWithUmbra.negate().test("other"), true, "predicate negate");

        int[] counter = new int[]{0};
        Runnable increment = () -> counter[0]++;
        increment.run();
        increment.run();
        Checks.eq(counter[0], 2, "captured local lambda");

        int captured = 7;
        IntUnaryOperator addCaptured = value -> value + captured;
        Checks.eq(addCaptured.applyAsInt(35), 42, "captured primitive lambda");

        Checks.eq(IntStream.rangeClosed(1, 10).filter(value -> value % 2 == 0).sum(),
                30, "int stream filter sum");
        Checks.eq(IntStream.range(0, 5).map(value -> value * 3).sum(),
                30, "int stream map sum");
        List<Integer> mapped = Stream.of("a", "bb", "ccc")
                .map(String::length)
                .collect(Collectors.toList());
        Checks.eq(mapped.toString(), "[1, 2, 3]", "stream map collect");
        String joined = Stream.of("a", "b", "c").collect(Collectors.joining("-"));
        Checks.eq(joined, "a-b-c", "stream joining");
        Checks.eq(Stream.of("x", "y", "z").count(), 3L, "stream count");

        Optional<String> optional = Optional.of("umbra").map(String::toUpperCase);
        Checks.eq(optional.orElse("none"), "UMBRA", "optional map");
        Checks.eq(Optional.<String>empty().orElse("fallback"), "fallback", "optional empty");
        Checks.eq(Optional.of("value").filter(text -> text.length() > 10).isPresent(),
                false, "optional filter");
    }
}

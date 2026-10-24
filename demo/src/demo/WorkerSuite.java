package demo;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Thread coverage: thread creation/start/join, a synchronized counter, and an
 * executor with futures. All workloads are deterministic.
 */
public final class WorkerSuite {

    private WorkerSuite() {
    }

    public static void run() throws Exception {
        Counter counter = new Counter();
        Thread[] threads = new Thread[4];
        for (int index = 0; index < threads.length; index++) {
            final int offset = index;
            threads[index] = new Thread(new Runnable() {
                @Override
                public void run() {
                    for (int value = 0; value <= 100; value++) {
                        counter.add(offset + value);
                    }
                }
            }, "worker-" + index);
        }
        for (Thread thread : threads) {
            thread.start();
        }
        for (Thread thread : threads) {
            thread.join(30000L);
            Checks.eq(thread.isAlive(), false, "thread joined " + thread.getName());
        }
        Checks.eq(counter.get(), 20806L, "thread accumulation");

        ExecutorService pool = Executors.newFixedThreadPool(3);
        try {
            List<Future<Long>> futures = new ArrayList<Future<Long>>();
            for (int index = 1; index <= 5; index++) {
                final long limit = index * 10L;
                futures.add(pool.submit(new Callable<Long>() {
                    @Override
                    public Long call() {
                        long total = 0L;
                        for (long value = 1L; value <= limit; value++) {
                            total += value;
                        }
                        return Long.valueOf(total);
                    }
                }));
            }
            long total = 0L;
            for (Future<Long> future : futures) {
                total += future.get(30L, TimeUnit.SECONDS).longValue();
            }
            Checks.eq(total, 2825L, "executor futures total");
        } finally {
            pool.shutdown();
            Checks.eq(pool.awaitTermination(30L, TimeUnit.SECONDS), true, "executor terminated");
        }

        final int[] shared = new int[1];
        Runnable runnable = () -> shared[0] = 42;
        Thread lambdaThread = new Thread(runnable, "lambda-worker");
        lambdaThread.start();
        lambdaThread.join(30000L);
        Checks.eq(shared[0], 42, "thread with lambda");
    }

    static final class Counter {

        private long value;

        synchronized void add(long delta) {
            value += delta;
        }

        synchronized long get() {
            return value;
        }
    }
}

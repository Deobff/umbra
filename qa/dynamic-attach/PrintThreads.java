public final class PrintThreads {
    public static void main(String[] args) throws Exception {
        Thread.sleep(500L);
        java.util.Set<Thread> threads = Thread.getAllStackTraces().keySet();
        for (Thread t : threads) {
            System.out.println("THREAD:" + t.getName());
        }
        System.out.println("COUNT:" + threads.size());
        Thread.sleep(3000L);
    }
}

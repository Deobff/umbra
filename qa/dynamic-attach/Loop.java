public final class Loop {
    public static void main(String[] args) throws Exception {
        System.out.println("READY");
        System.out.flush();
        for (int i = 0; i < 30; i++) {
            Thread.sleep(500L);
        }
        System.out.println("DONE");
    }
}

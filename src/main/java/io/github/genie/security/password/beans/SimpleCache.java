package io.github.genie.security.password.beans;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SimpleCache implements ExpiredCache {

    private static final ScheduledExecutorService scheduler = Executors
            .newSingleThreadScheduledExecutor(r -> {
                Thread thread = new Thread(r);
                thread.setDaemon(true);
                return thread;
            });

    private static final Map<String, Long> CACHE = new ConcurrentHashMap<>();

    public SimpleCache() {
        int period = 1;
        scheduler.scheduleAtFixedRate(this::clear, period, period, TimeUnit.SECONDS);
    }


    private void clear() {
        CACHE.entrySet().removeIf(e -> isExpired(e.getValue()));
    }

    private static boolean isExpired(Long value) {
        return value == null || System.currentTimeMillis() > value;
    }

    @Override
    public void put(String key, long expiryAt) {
        CACHE.put(key, expiryAt);
    }

    @Override
    public boolean exist(String encodedPassword) {
        return CACHE.compute(encodedPassword, (key, time) -> isExpired(time) ? null : time) != null;
    }

}

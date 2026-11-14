package dev.sanyam.cg.security;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fixed-window counter per key, e.g. "login:alice@example.com".
 * ponytail: in memory, so limits reset on restart and aren't shared between instances; move to Redis or a
 * database table if CG ever runs more than one instance.
 */
public class RateLimiter {

    private record Window(long startMillis, int count) {
    }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Clock clock;

    public RateLimiter(Clock clock) {
        this.clock = clock;
    }

    /** Seconds until the key may act again, or 0 if it is under the limit. Does not count as an attempt. */
    public long retryAfter(String key, int limit, Duration window) {
        Window w = windows.get(key);
        long now = clock.millis();
        if (w == null || now - w.startMillis() >= window.toMillis() || w.count() < limit) {
            return 0;
        }
        return Math.max(1, (w.startMillis() + window.toMillis() - now + 999) / 1000);
    }

    /** Counts one attempt for the key. */
    public void record(String key, Duration window) {
        long now = clock.millis();
        windows.compute(key, (k, w) -> w == null || now - w.startMillis() >= window.toMillis()
                ? new Window(now, 1) : new Window(w.startMillis(), w.count() + 1));
        if (windows.size() > 10_000) {  // drop expired windows so memory can't grow forever
            windows.values().removeIf(w -> now - w.startMillis() >= window.toMillis());
        }
    }

    public void reset(String key) {
        windows.remove(key);
    }
}

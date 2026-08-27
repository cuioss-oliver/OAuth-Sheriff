/*
 * Copyright © 2025-present CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.sheriff.token.validation.dpop;

import de.cuioss.tools.logging.CuiLogger;

import java.io.Closeable;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe jti replay protection for DPoP proofs per RFC 9449 Section 11.1.
 * <p>
 * Tracks previously seen {@code jti} values to prevent replay attacks. Each jti
 * is stored with its insertion timestamp and evicted after the configured TTL.
 * </p>
 * <p>
 * This instance is shared across all issuers since jti values must be globally
 * unique per RFC 9449.
 * </p>
 * <p>
 * A daemon thread periodically evicts expired entries to prevent unbounded memory growth.
 * Call {@link #close()} to shut down the eviction scheduler.
 * </p>
 *
 * @since 1.0
 */
public class DpopReplayProtection implements Closeable {

    private static final CuiLogger LOGGER = new CuiLogger(DpopReplayProtection.class);
    private static final long EVICTION_INTERVAL_SECONDS = 60;

    private record Entry(long insertionOrder, long timestampMillis) {
    }

    private final ConcurrentHashMap<String, Entry> seenJti = new ConcurrentHashMap<>();
    private final AtomicLong insertionCounter = new AtomicLong(0);
    private final long ttlMillis;
    private final int maxSize;
    private final ScheduledExecutorService scheduler;

    /**
     * Creates a new DpopReplayProtection with the given configuration.
     *
     * @param ttlSeconds maximum time in seconds to retain jti entries
     * @param maxSize    maximum number of jti entries to store
     */
    public DpopReplayProtection(long ttlSeconds, int maxSize) {
        this.ttlMillis = ttlSeconds * 1000;
        this.maxSize = maxSize;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dpop-replay-eviction");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::evictExpired,
                EVICTION_INTERVAL_SECONDS, EVICTION_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * Checks if the given jti has been seen before and stores it if new.
     *
     * @param jti the unique identifier from the DPoP proof
     * @return {@code true} if the jti is new (not a replay), {@code false} if already seen
     */
    public boolean checkAndStore(String jti) {
        long now = System.currentTimeMillis();

        Entry newEntry = new Entry(insertionCounter.getAndIncrement(), now);

        // Atomically store only if absent, preventing race conditions
        Entry existing = seenJti.putIfAbsent(jti, newEntry);

        if (existing != null) {
            // Entry exists - check if it has expired and try atomic replacement
            return (now - existing.timestampMillis()) >= ttlMillis
                    && seenJti.replace(jti, existing, newEntry);
        }

        // Successfully stored new jti - evict oldest if needed
        if (seenJti.size() > maxSize) {
            evictOldest();
        }

        return true; // New jti, not a replay
    }

    private void evictExpired() {
        long now = System.currentTimeMillis();
        int removed = 0;
        var iterator = seenJti.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if ((now - entry.getValue().timestampMillis()) >= ttlMillis) {
                iterator.remove();
                removed++;
            }
        }
        if (removed > 0) {
            LOGGER.debug("DPoP replay cache eviction: removed %s expired entries, %s remaining", removed, seenJti.size());
        }
    }

    private void evictOldest() {
        int overflow = seenJti.size() - maxSize;
        if (overflow <= 0) {
            return;
        }
        long now = System.currentTimeMillis();
        // Only evict entries whose freshness window (ttlMillis) has already elapsed, oldest first.
        // Evicting a jti still inside its window would forget it early and permit a replay, defeating
        // the protection this cache exists to provide. Under a flood of in-window jtis the cache may
        // temporarily exceed maxSize; the periodic evictExpired sweep reclaims those entries once
        // their windows close.
        var evictable = seenJti.entrySet().stream()
                .filter(entry -> (now - entry.getValue().timestampMillis()) >= ttlMillis)
                .sorted(Map.Entry.comparingByValue(
                        Comparator.comparingLong(Entry::insertionOrder)))
                .limit(overflow)
                .toList();
        evictable.forEach(entry -> seenJti.remove(entry.getKey(), entry.getValue()));
        if (evictable.size() < overflow) {
            LOGGER.debug("DPoP replay cache over soft capacity: retained %s in-window jtis to preserve replay protection (overflow=%s, evicted=%s)",
                    seenJti.size(), overflow, evictable.size());
        }
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
        seenJti.clear();
    }
}

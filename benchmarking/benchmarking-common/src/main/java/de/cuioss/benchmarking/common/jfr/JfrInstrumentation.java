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
package de.cuioss.benchmarking.common.jfr;

import org.HdrHistogram.Histogram;
import org.HdrHistogram.Recorder;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Central management for JFR instrumentation in benchmarks.
 * Provides utilities for recording events and computing statistics.
 */
public class JfrInstrumentation {

    private static final long HIGHEST_TRACKABLE_VALUE = TimeUnit.SECONDS.toNanos(10);
    private static final int NUMBER_OF_SIGNIFICANT_VALUE_DIGITS = 3;

    private final Map<String, OperationStats> operationStats = new ConcurrentHashMap<>();
    private final AtomicInteger concurrentOperations = new AtomicInteger(0);
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "JFR-Statistics-Reporter");
        t.setDaemon(true);
        return t;
    });

    public JfrInstrumentation() {
        // Schedule periodic statistics reporting
        scheduler.scheduleAtFixedRate(this::reportStatistics, 1, 1, TimeUnit.SECONDS);
    }

    /**
     * Records the start of a benchmark operation.
     * @return an AutoCloseable that should be used in try-with-resources to ensure proper event completion
     */
    public OperationRecorder recordOperation(String benchmarkName, String operationType) {
        return new OperationRecorder(benchmarkName, operationType);
    }

    /**
     * Records a benchmark phase transition.
     */
    public void recordPhase(String benchmarkName, String phase, int iteration, int totalIterations, int fork, int threadCount) {
        BenchmarkPhaseEvent event = new BenchmarkPhaseEvent();
        event.benchmarkName = benchmarkName;
        event.phase = phase;
        event.iteration = iteration;
        event.totalIterations = totalIterations;
        event.fork = fork;
        event.threadCount = threadCount;
        event.commit();
    }

    /**
     * Shuts down the instrumentation and releases resources.
     */
    public void shutdown() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void reportStatistics() {
        operationStats.forEach((key, stats) -> {
            Histogram snapshot = stats.recorder.getIntervalHistogram();
            if (snapshot.getTotalCount() > 0) {
                OperationStatisticsEvent event = new OperationStatisticsEvent();
                String[] parts = key.split(":");
                event.benchmarkName = parts[0];
                event.operationType = parts[1];
                event.sampleCount = snapshot.getTotalCount();
                event.successCount = stats.successCount.getAndSet(0);
                event.errorCount = stats.errorCount.getAndSet(0);
                event.meanLatency = (long) snapshot.getMean();
                event.p50Latency = snapshot.getValueAtPercentile(50.0);
                event.p95Latency = snapshot.getValueAtPercentile(95.0);
                event.p99Latency = snapshot.getValueAtPercentile(99.0);
                event.maxLatency = snapshot.getMaxValue();
                event.standardDeviation = (long) snapshot.getStdDeviation();
                event.variance = Math.pow(snapshot.getStdDeviation(), 2);
                event.coefficientOfVariation = snapshot.getMean() > 0 ?
                        (snapshot.getStdDeviation() / snapshot.getMean() * 100) : 0;
                event.concurrentThreads = stats.maxConcurrentThreads.getAndSet(0);
                event.commit();
            }
        });
    }

    /**
     * Helper class for recording individual operations.
     */
    public class OperationRecorder implements AutoCloseable {
        private final OperationEvent event;
        private final String statsKey;
        private final long startTime;

        private OperationRecorder(String benchmarkName, String operationType) {
            this.event = new OperationEvent();
            this.event.benchmarkName = benchmarkName;
            this.event.operationType = operationType;
            this.event.threadName = Thread.currentThread().getName();
            this.statsKey = benchmarkName + ":" + operationType;
            this.startTime = System.nanoTime();

            event.begin();
            int concurrent = concurrentOperations.incrementAndGet();
            event.concurrentOperations = concurrent;

            // Update max concurrent threads
            OperationStats stats = operationStats.get(statsKey);
            if (stats != null) {
                stats.maxConcurrentThreads.updateAndGet(current -> Math.max(current, concurrent));
            }
        }

        public OperationRecorder withPayloadSize(long size) {
            event.payloadSize = size;
            return this;
        }

        public OperationRecorder withMetadata(String key, String value) {
            event.metadataKey = key;
            event.metadataValue = value;
            return this;
        }

        public OperationRecorder withSuccess(boolean success) {
            event.success = success;
            return this;
        }

        public OperationRecorder withError(String errorType) {
            event.success = false;
            event.errorType = errorType;
            return this;
        }

        @Override
        public void close() {
            concurrentOperations.decrementAndGet();
            event.end();

            if (event.shouldCommit()) {
                event.commit();
            }

            // Record statistics
            long duration = System.nanoTime() - startTime;
            OperationStats stats = operationStats.computeIfAbsent(statsKey, k -> new OperationStats());
            stats.recorder.recordValue(duration);

            if (event.success) {
                stats.successCount.incrementAndGet();
            } else {
                stats.errorCount.incrementAndGet();
            }

        }
    }

    private static class OperationStats {
        final Recorder recorder = new Recorder(HIGHEST_TRACKABLE_VALUE, NUMBER_OF_SIGNIFICANT_VALUE_DIGITS);
        final AtomicLong successCount = new AtomicLong();
        final AtomicLong errorCount = new AtomicLong();
        final AtomicInteger maxConcurrentThreads = new AtomicInteger();
    }
}
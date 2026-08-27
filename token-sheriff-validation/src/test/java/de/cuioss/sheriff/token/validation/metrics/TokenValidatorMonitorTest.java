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
package de.cuioss.sheriff.token.validation.metrics;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.concurrent.StripedRingBufferStatistics;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.IntStream;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for {@link TokenValidatorMonitor}.
 * <p>
 * Tests cover:
 * <ul>
 *   <li>Basic functionality - recording measurements and calculating averages</li>
 *   <li>Thread safety - massive parallel operations from multiple threads</li>
 *   <li>Performance characteristics - minimal overhead validation</li>
 *   <li>Edge cases - boundary conditions and error scenarios</li>
 *   <li>Window behavior - rolling window mechanics</li>
 * </ul>
 * <p>
 * This test class ensures that metrics monitoring operations are accurate,
 * thread-safe, and have minimal impact on runtime metrics.
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests TokenValidatorMonitor functionality")
class TokenValidatorMonitorTest {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidatorMonitorTest.class);

    @Test
    @DisplayName("Should create monitor with default window size")
    void shouldCreateMonitorWithDefaultWindowSize() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        assertNotNull(monitor, "Monitor should be created");

        // Verify initial state - no measurements recorded
        for (MeasurementType type : MeasurementType.values()) {
            var metricsOpt = monitor.getValidationMetrics(type);
            assertTrue(metricsOpt.isPresent(), "Metrics should be present for enabled type " + type);
            var metrics = metricsOpt.get();
            assertEquals(0, metrics.sampleCount(), "Initial sample count should be zero for " + type);
            assertEquals(Duration.ZERO, metrics.p50(), "Initial P50 should be zero for " + type);
            assertEquals(0, monitor.getSampleCount(type),
                    "Initial sample count should be zero for " + type);
        }
    }

    @Test
    @DisplayName("Should create monitor with custom window size")
    void shouldCreateMonitorWithCustomWindowSize() {
        var monitor = TokenValidatorMonitorConfig.builder()
                .windowSize(50)
                .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                .build()
                .createMonitor();
        assertNotNull(monitor, "Monitor should be created with custom window size");
    }

    @Test
    @DisplayName("Should reject invalid window sizes")
    void shouldRejectInvalidWindowSizes() {
        assertThrows(IllegalArgumentException.class,
                () -> createMonitorWithWindowSize(0),
                "Should reject zero window size");

        assertThrows(IllegalArgumentException.class,
                () -> createMonitorWithWindowSize(-1),
                "Should reject negative window size");
    }

    @SuppressWarnings("UnusedReturnValue")
    private TokenValidatorMonitor createMonitorWithWindowSize(int windowSize) {
        return TokenValidatorMonitorConfig.builder()
                .windowSize(windowSize)
                .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                .build()
                .createMonitor();
    }

    @Test
    @DisplayName("Should record single measurement")
    void shouldRecordSingleMeasurement() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementType = MeasurementType.SIGNATURE_VALIDATION;

        // Record 1 millisecond (1,000,000 nanoseconds)
        long durationNanos = 1_000_000;
        monitor.recordMeasurement(measurementType, durationNanos);

        assertEquals(1, monitor.getSampleCount(measurementType),
                "Should have one sample recorded");

        var metricsOpt = monitor.getValidationMetrics(measurementType);
        assertTrue(metricsOpt.isPresent(), "Metrics should be present");
        var metrics = metricsOpt.get();
        assertEquals(Duration.ofMillis(1), metrics.p50(),
                "P50 should equal the single measurement");
    }

    @Test
    @DisplayName("Should record multiple measurements and calculate average")
    void shouldRecordMultipleMeasurementsAndCalculateAverage() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementType = MeasurementType.COMPLETE_VALIDATION;

        // Record measurements: 1ms, 2ms, 3ms (average = 2ms)
        monitor.recordMeasurement(measurementType, 1_000_000); // 1ms
        monitor.recordMeasurement(measurementType, 2_000_000); // 2ms
        monitor.recordMeasurement(measurementType, 3_000_000); // 3ms

        assertEquals(3, monitor.getSampleCount(measurementType),
                "Should have three samples recorded");

        StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                .orElseThrow(() -> new AssertionError("Metrics should be present"));
        assertEquals(Duration.ofMillis(2), metrics.p50(),
                "P50 should be 2ms");
    }

    @Test
    @DisplayName("Should handle microsecond precision")
    void shouldHandleMicrosecondPrecision() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementType = MeasurementType.TOKEN_PARSING;

        // Record 500 microseconds (500,000 nanoseconds)
        long durationNanos = 500_000;
        monitor.recordMeasurement(measurementType, durationNanos);

        StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                .orElseThrow(() -> new AssertionError("Metrics should be present"));
        assertEquals(Duration.ofNanos(500_000), metrics.p50(),
                "Should maintain microsecond precision");
    }

    @Test
    @DisplayName("Should isolate measurements between types")
    void shouldIsolateMeasurementsBetweenTypes() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();

        // Record different values for different types
        monitor.recordMeasurement(MeasurementType.SIGNATURE_VALIDATION, 5_000_000); // 5ms
        monitor.recordMeasurement(MeasurementType.CLAIMS_VALIDATION, 1_000_000);    // 1ms

        assertEquals(Duration.ofMillis(5),
                monitor.getValidationMetrics(MeasurementType.SIGNATURE_VALIDATION)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                "Signature validation P50 should be 5ms");

        assertEquals(Duration.ofMillis(1),
                monitor.getValidationMetrics(MeasurementType.CLAIMS_VALIDATION)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                "Claims validation P50 should be 1ms");

        assertEquals(Duration.ZERO,
                monitor.getValidationMetrics(MeasurementType.TOKEN_PARSING)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                "Unused measurement type should remain at zero");
    }

    @Test
    @DisplayName("Should respect rolling window size")
    void shouldRespectRollingWindowSize() {
        var windowSize = 3;
        var monitor = TokenValidatorMonitorConfig.builder()
                .windowSize(windowSize)
                .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                .build()
                .createMonitor();
        var measurementType = MeasurementType.HEADER_VALIDATION;

        // Record more measurements than window size
        monitor.recordMeasurement(measurementType, 1_000_000); // 1ms - should be overwritten
        monitor.recordMeasurement(measurementType, 2_000_000); // 2ms
        monitor.recordMeasurement(measurementType, 3_000_000); // 3ms
        monitor.recordMeasurement(measurementType, 4_000_000); // 4ms - overwrites 1ms

        // Sample count should not exceed window size
        assertTrue(monitor.getSampleCount(measurementType) <= windowSize,
                "Sample count should not exceed window size");

        // P50 should reflect recent values
        StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                .orElseThrow(() -> new AssertionError("Metrics should be present"));
        long p50Millis = metrics.p50().toMillis();
        assertTrue(p50Millis >= 2 && p50Millis <= 4,
                "P50 should reflect recent measurements: " + p50Millis + "ms");
    }

    @Test
    @DisplayName("Should reset specific measurement type")
    void shouldResetSpecificMeasurementType() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();

        // Record measurements for multiple types
        monitor.recordMeasurement(MeasurementType.SIGNATURE_VALIDATION, 5_000_000);
        monitor.recordMeasurement(MeasurementType.CLAIMS_VALIDATION, 1_000_000);

        // Reset only signature validation
        monitor.reset(MeasurementType.SIGNATURE_VALIDATION);

        assertEquals(Duration.ZERO,
                monitor.getValidationMetrics(MeasurementType.SIGNATURE_VALIDATION)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                "Reset measurement type should be zero");

        assertEquals(Duration.ofMillis(1),
                monitor.getValidationMetrics(MeasurementType.CLAIMS_VALIDATION)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                "Other measurement types should remain unchanged");
    }

    @Test
    @DisplayName("Should reset all measurements")
    void shouldResetAllMeasurements() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();

        // Record measurements for all types
        for (MeasurementType type : MeasurementType.values()) {
            monitor.recordMeasurement(type, 1_000_000);
        }

        // Reset all
        monitor.resetAll();

        // Verify all are reset
        for (MeasurementType type : MeasurementType.values()) {
            assertEquals(Duration.ZERO, monitor.getValidationMetrics(type)
                            .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                    "All measurement types should be reset: " + type);
            assertEquals(0, monitor.getSampleCount(type),
                    "All sample counts should be reset: " + type);
        }
    }

    @Test
    @DisplayName("Should handle zero and negative durations")
    void shouldHandleZeroAndNegativeDurations() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementType = MeasurementType.CACHE_LOOKUP;

        // Record zero duration
        monitor.recordMeasurement(measurementType, 0);
        assertEquals(Duration.ZERO, monitor.getValidationMetrics(measurementType)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                "Zero duration should be handled correctly");

        // Record negative duration (should be clamped to zero)
        monitor.recordMeasurement(measurementType, -1000);
        assertEquals(Duration.ZERO, monitor.getValidationMetrics(measurementType)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                "Negative duration should be clamped to zero");
    }

    @Test
    @DisplayName("Should be thread-safe under moderate load")
    void shouldBeThreadSafeUnderModerateLoad() {
        var threadCount = 10;
        var measurementsPerThread = 1000;
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementType = MeasurementType.COMPLETE_VALIDATION;
        var startLatch = new CountDownLatch(1);
        var completedThreads = new AtomicInteger(0);
        var executor = Executors.newFixedThreadPool(threadCount);

        // Submit all threads
        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < measurementsPerThread; j++) {
                        // Use different durations per thread for verification
                        long duration = (threadId + 1) * 1_000_000L; // 1ms, 2ms, 3ms, etc.
                        monitor.recordMeasurement(measurementType, duration);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    completedThreads.incrementAndGet();
                }
            });
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for all threads to complete
        await("All threads to complete their measurements")
                .atMost(15, SECONDS)
                .until(() -> completedThreads.get() == threadCount);

        executor.shutdown();

        // Verify measurements were recorded (exact count may be less due to window size)
        assertTrue(monitor.getSampleCount(measurementType) > 0,
                "Should have recorded measurements");

        StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                .orElseThrow(() -> new AssertionError("Metrics should be present"));
        assertTrue(metrics.p50().toNanos() > 0,
                "P50 should be positive: " + metrics.p50().toNanos() + "ns");
    }

    @Test
    @DisplayName("Should handle massive parallel load")
    void shouldHandleMassiveParallelLoad() {
        var threadCount = 50;
        var measurementsPerThread = 5000;
        var monitor = TokenValidatorMonitorConfig.builder()
                .windowSize(200) // Larger window for this test
                .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                .build()
                .createMonitor();
        var measurementType = MeasurementType.SIGNATURE_VALIDATION;
        var startLatch = new CountDownLatch(1);
        var completedThreads = new AtomicInteger(0);
        var totalMeasurements = new AtomicLong(0);
        var executor = Executors.newFixedThreadPool(threadCount);

        // Submit all threads
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < measurementsPerThread; j++) {
                        // Use consistent duration for average calculation verification
                        monitor.recordMeasurement(measurementType, 2_000_000); // 2ms
                        totalMeasurements.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    completedThreads.incrementAndGet();
                }
            });
        }

        // Measure metrics impact
        long startTime = System.nanoTime();
        startLatch.countDown();

        // Wait for all threads to complete
        await("All threads to complete massive parallel measurements")
                .atMost(30, SECONDS)
                .until(() -> completedThreads.get() == threadCount);

        long endTime = System.nanoTime();
        long totalDurationMs = (endTime - startTime) / 1_000_000;

        executor.shutdown();

        // Verify measurements were recorded
        assertTrue(monitor.getSampleCount(measurementType) > 0,
                "Should have recorded measurements under massive load");

        // Verify P50 is reasonable (should be close to 2ms)
        StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                .orElseThrow(() -> new AssertionError("Metrics should be present"));
        long p50Millis = metrics.p50().toMillis();
        assertTrue(p50Millis >= 1 && p50Millis <= 3,
                "P50 should be close to 2ms under massive load: " + p50Millis + "ms");

        // Throughput smoke check. The real value of this test is thread-safety and correctness
        // under massive concurrent load (asserted above); the 30s await already fails on gross
        // slowness. This runs under parallel surefire forks and noisy CI, so the bound is
        // deliberately loose to tolerate CPU oversubscription while still catching a pathological
        // regression (e.g. accidental global locking would be orders of magnitude worse).
        double measurementsPerMs = totalMeasurements.get() / (double) totalDurationMs;

        assertTrue(measurementsPerMs > 100,
                "Performance too slow: %s measurements/ms (expected > 100)".formatted(measurementsPerMs));

        LOGGER.info("Massive parallel test: %s threads, %s measurements/thread, %s measurements/ms",
                threadCount, measurementsPerThread, measurementsPerMs);
    }

    @Test
    @DisplayName("Should handle concurrent access to different measurement types")
    void shouldHandleConcurrentAccessToDifferentMeasurementTypes() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementTypes = MeasurementType.values();
        var threadsPerType = 5;
        var measurementsPerThread = 100;
        var startLatch = new CountDownLatch(1);
        var completedThreads = new AtomicInteger(0);
        var executor = Executors.newFixedThreadPool(measurementTypes.length * threadsPerType);

        // Submit threads for each measurement type
        for (int typeIndex = 0; typeIndex < measurementTypes.length; typeIndex++) {
            final var measurementType = measurementTypes[typeIndex];
            final long baseDuration = (typeIndex + 1) * 1_000_000L; // 1ms, 2ms, 3ms, etc.

            for (int threadIndex = 0; threadIndex < threadsPerType; threadIndex++) {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        for (int j = 0; j < measurementsPerThread; j++) {
                            monitor.recordMeasurement(measurementType, baseDuration);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        completedThreads.incrementAndGet();
                    }
                });
            }
        }

        // Start all threads simultaneously
        startLatch.countDown();

        // Wait for all threads to complete
        int expectedThreads = measurementTypes.length * threadsPerType;
        await("All measurement type threads to complete")
                .atMost(20, SECONDS)
                .until(() -> completedThreads.get() == expectedThreads);

        executor.shutdown();

        // Verify each measurement type has the expected average
        for (int i = 0; i < measurementTypes.length; i++) {
            var measurementType = measurementTypes[i];
            var expectedDurationMs = i + 1;

            assertTrue(monitor.getSampleCount(measurementType) > 0,
                    "Should have samples for " + measurementType);

            StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                    .orElseThrow(() -> new AssertionError("Metrics should be present for " + measurementType));
            assertEquals(expectedDurationMs, metrics.p50().toMillis(),
                    "P50 for " + measurementType + " should be " + expectedDurationMs + "ms");
        }
    }

    @RepeatedTest(5)
    @DisplayName("Should be consistent across multiple runs")
    void shouldBeConsistentAcrossMultipleRuns() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementType = MeasurementType.CLAIMS_VALIDATION;

        // Record consistent measurements
        IntStream.range(0, 100).forEach(i ->
                monitor.recordMeasurement(measurementType, 1_500_000)); // 1.5ms each

        StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                .orElseThrow(() -> new AssertionError("Metrics should be present"));
        assertEquals(Duration.ofNanos(1_500_000), metrics.p50(),
                "P50 should be consistent across repeated runs");
    }

    @Test
    @DisplayName("Should have minimal metrics overhead")
    void shouldHaveMinimalPerformanceOverhead() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementType = MeasurementType.SIGNATURE_VALIDATION;
        var iterations = 100_000;

        // Warm up the JIT so the timed loop measures steady-state cost, not compilation.
        for (int i = 0; i < 20_000; i++) {
            monitor.recordMeasurement(measurementType, 1_000_000);
        }

        // Measure time for recording measurements
        long startTime = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            monitor.recordMeasurement(measurementType, 1_000_000);
        }
        long endTime = System.nanoTime();

        long totalOverheadNanos = endTime - startTime;
        double overheadPerMeasurementNanos = totalOverheadNanos / (double) iterations;

        // Smoke check that recording is not pathologically expensive (a striped ring-buffer
        // write is sub-microsecond uncontended). This runs under parallel surefire forks and on
        // shared CI runners, so the bound is deliberately loose to tolerate CPU contention while
        // still catching gross regressions (e.g. accidental locking or O(n) growth would be
        // orders of magnitude higher). Precise performance is tracked by the JMH benchmark-core
        // module, not this unit test.
        assertTrue(overheadPerMeasurementNanos < 20_000,
                "Performance overhead too high: %s ns/measurement (expected < 20000)".formatted(
                        overheadPerMeasurementNanos));

        LOGGER.info("Performance overhead: %s ns per measurement", overheadPerMeasurementNanos);
    }

    @Test
    @DisplayName("Should calculate percentiles correctly")
    void shouldCalculatePercentilesCorrectly() {
        var monitor = TokenValidatorMonitorConfig.builder()
                .windowSize(1000) // Large window to hold all values
                .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                .build()
                .createMonitor();
        var measurementType = MeasurementType.SIGNATURE_VALIDATION;

        // Add a range of values with known distribution
        for (int i = 1; i <= 100; i++) {
            monitor.recordMeasurement(measurementType, i * 1_000_000); // 1ms to 100ms
        }

        StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                .orElseThrow(() -> new AssertionError("Metrics should be present"));

        // Verify percentiles are ordered correctly
        assertTrue(metrics.p99().compareTo(metrics.p95()) >= 0,
                "P99 should be >= P95");
        assertTrue(metrics.p95().compareTo(metrics.p50()) >= 0,
                "P95 should be >= P50");

        // Verify they're within expected ranges
        // Due to striped ring buffer behavior, values may be slightly higher than expected
        assertTrue(metrics.p50().toMillis() >= 40 && metrics.p50().toMillis() <= 70,
                "P50 should be around 50ms, got: " + metrics.p50().toMillis());
        assertTrue(metrics.p95().toMillis() >= 80,
                "P95 should be at least 80ms, got: " + metrics.p95().toMillis());
        assertTrue(metrics.p99().toMillis() >= 90,
                "P99 should be at least 90ms, got: " + metrics.p99().toMillis());
    }

    @Test
    @DisplayName("Should return zero metrics for empty buffer")
    void shouldReturnZeroMetricsForEmptyBuffer() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();

        Optional<StripedRingBufferStatistics> metricsOpt = monitor.getValidationMetrics(MeasurementType.TOKEN_PARSING);
        assertTrue(metricsOpt.isPresent(), "Metrics should be present for enabled measurement type");

        StripedRingBufferStatistics metrics = metricsOpt.get();
        assertEquals(0, metrics.sampleCount(), "Empty buffer should have zero sample count");
        assertEquals(Duration.ZERO, metrics.p50(), "Empty buffer should have zero P50");
        assertEquals(Duration.ZERO, metrics.p95(), "Empty buffer should have zero P95");
        assertEquals(Duration.ZERO, metrics.p99(), "Empty buffer should have zero P99");
    }

    @Test
    @DisplayName("Should handle single measurement for percentiles")
    void shouldHandleSingleMeasurementForPercentiles() {
        var monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        var measurementType = MeasurementType.CLAIMS_VALIDATION;

        monitor.recordMeasurement(measurementType, 5_000_000); // 5ms

        StripedRingBufferStatistics metrics = monitor.getValidationMetrics(measurementType)
                .orElseThrow(() -> new AssertionError("Metrics should be present"));
        assertEquals(1, metrics.sampleCount());
        assertEquals(Duration.ofMillis(5), metrics.p50());
        assertEquals(Duration.ofMillis(5), metrics.p95());
        assertEquals(Duration.ofMillis(5), metrics.p99());
    }
}
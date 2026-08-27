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

import de.cuioss.tools.concurrent.StripedRingBuffer;
import de.cuioss.tools.concurrent.StripedRingBufferStatistics;
import lombok.Getter;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Provides high-metrics, thread-safe monitoring of JWT validation pipeline metrics.
 * <p>
 * This class measures execution times for different stages of JWT validation with microsecond
 * precision. It maintains a configurable rolling window of recent measurements for each
 * pipeline step and provides average calculation capabilities.
 * <p>
 * <strong>Design Principles:</strong>
 * <ul>
 *   <li><strong>Thread-Safe:</strong> All operations are lock-free using atomic operations</li>
 *   <li><strong>Zero Runtime Impact:</strong> Optimized for minimal overhead during measurement</li>
 *   <li><strong>Microsecond Precision:</strong> All measurements recorded in microseconds</li>
 *   <li><strong>Rolling Window:</strong> Maintains configurable number of recent samples</li>
 *   <li><strong>Pipeline Aware:</strong> Measures each validation step separately</li>
 * </ul>
 * <p>
 * <strong>Implementation:</strong>
 * Uses a striped ring buffer design with multiple independent buffers to minimize contention
 * between threads. Each measurement type maintains its own set of striped buffers for optimal
 * metrics in high-concurrency environments.
 * <p>
 * <strong>Usage Example:</strong>
 * <pre>
 * // Create monitor via its configuration (default window size, all measurement types)
 * TokenValidatorMonitor monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
 *
 * // Record a measurement
 * long startNanos = System.nanoTime();
 * // ... perform signature validation ...
 * long durationNanos = System.nanoTime() - startNanos;
 * monitor.recordMeasurement(MeasurementType.SIGNATURE_VALIDATION, durationNanos);
 *
 * // Get comprehensive metrics for analysis
 * Optional&lt;StripedRingBufferStatistics&gt; metricsOpt = monitor.getValidationMetrics(MeasurementType.SIGNATURE_VALIDATION);
 * if (metricsOpt.isPresent()) {
 *     StripedRingBufferStatistics metrics = metricsOpt.get();
 *     Duration avgSignatureTime = metrics.p50();
 *     Duration p99SignatureTime = metrics.p99();
 * }
 * </pre>
 * <p>
 * This implementation is structured to simplify later integration with micrometer-based
 * metrics systems but does not create any dependency on external monitoring frameworks.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class TokenValidatorMonitor {


    /**
     * Striped ring buffers for each measurement type.
     */
    private final StripedRingBuffer[] measurementBuffers;

    /**
     * Set of enabled measurement types. Only measurements for these types
     * will be recorded; others will be no-op operations.
     */
    @Getter
    private final Set<MeasurementType> enabledTypes;

    /**
     * Creates a new metrics monitor with specified window size and enabled measurement types.
     * <p>
     * Package-private constructor to be used from TokenValidatorMonitorConfig.
     *
     * @param windowSize number of samples to maintain per measurement type (must be positive)
     * @param enabledTypes set of measurement types to monitor (others will be no-op)
     * @throws IllegalArgumentException if windowSize is not positive
     */
    TokenValidatorMonitor(int windowSize, Set<MeasurementType> enabledTypes) {
        if (windowSize <= 0) {
            throw new IllegalArgumentException("Window size must be positive, got: " + windowSize);
        }

        this.enabledTypes = Set.copyOf(enabledTypes); // Defensive copy

        // Initialize one striped ring buffer per measurement type
        this.measurementBuffers = new StripedRingBuffer[MeasurementType.values().length];
        for (int i = 0; i < measurementBuffers.length; i++) {
            // Only create buffers for enabled types to save memory
            if (this.enabledTypes.contains(MeasurementType.values()[i])) {
                // Use NANOSECONDS as we store nanosecond values
                measurementBuffers[i] = new StripedRingBuffer(windowSize, TimeUnit.NANOSECONDS);
            }
        }
    }

    /**
     * Records a metrics measurement for the specified pipeline step.
     * <p>
     * This method is designed for maximum metrics with minimal overhead.
     * The measurement is recorded in nanoseconds internally, maintaining
     * high precision for accurate percentile calculations.
     * <p>
     * If the measurement type is not enabled in this monitor's configuration,
     * this method performs a no-op operation for optimal performance.
     *
     * @param measurementType the type of measurement being recorded
     * @param durationNanos   the duration in nanoseconds
     */
    public void recordMeasurement(MeasurementType measurementType, long durationNanos) {
        // Early return for disabled measurement types (no-op)
        if (!enabledTypes.contains(measurementType)) {
            return;
        }

        StripedRingBuffer buffer = measurementBuffers[measurementType.ordinal()];
        if (buffer != null) { // Additional safety check
            // Store in nanoseconds for maximum precision
            buffer.recordMeasurement(Math.max(0, durationNanos));
        }
    }

    /**
     * Gets comprehensive performance metrics for the specified measurement type.
     * <p>
     * This method returns an {@link Optional} containing {@link StripedRingBufferStatistics} with:
     * <ul>
     *   <li>Sample count - number of measurements recorded</li>
     *   <li>50th percentile (P50/median) - 50% of requests are faster than this</li>
     *   <li>95th percentile (P95) - 95% of requests are faster than this</li>
     *   <li>99th percentile (P99) - 99% of requests are faster than this</li>
     * </ul>
     * <p>
     * If no measurements have been recorded or the measurement type is disabled,
     * returns an empty Optional.
     *
     * @param measurementType the type of measurement to analyze
     * @return optional containing striped ring buffer statistics, empty if measurement type is not enabled
     */
    public Optional<StripedRingBufferStatistics> getValidationMetrics(MeasurementType measurementType) {
        StripedRingBuffer buffer = measurementBuffers[measurementType.ordinal()];
        if (buffer == null) {
            return Optional.empty(); // Measurement type not enabled
        }

        // Get comprehensive statistics
        return Optional.of(buffer.getStatistics());
    }

    /**
     * Gets the current sample count for the specified measurement type.
     *
     * @param measurementType the type of measurement to check
     * @return the number of samples currently recorded (up to window size), or 0 if type is disabled
     */
    int getSampleCount(MeasurementType measurementType) {
        StripedRingBuffer buffer = measurementBuffers[measurementType.ordinal()];
        return buffer != null ? buffer.getStatistics().sampleCount() : 0;
    }

    /**
     * Resets all measurements for the specified type.
     *
     * @param measurementType the type of measurement to reset
     */
    void reset(MeasurementType measurementType) {
        StripedRingBuffer buffer = measurementBuffers[measurementType.ordinal()];
        if (buffer != null) {
            buffer.reset();
        }
    }

    /**
     * Resets all measurements for all enabled types.
     */
    void resetAll() {
        for (StripedRingBuffer buffer : measurementBuffers) {
            if (buffer != null) {
                buffer.reset();
            }
        }
    }

    /**
     * Checks if the specified measurement type is enabled for recording.
     *
     * @param measurementType the measurement type to check
     * @return true if the measurement type is enabled and will record metrics, false otherwise
     */
    public boolean isEnabled(MeasurementType measurementType) {
        return enabledTypes.contains(measurementType);
    }

}
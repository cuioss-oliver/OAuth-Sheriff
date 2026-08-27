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

import lombok.RequiredArgsConstructor;

/**
 * Active implementation of {@link MetricsTicker} that records timing measurements
 * to a {@link TokenValidatorMonitor}.
 * <p>
 * This implementation captures the start time when {@link #startRecording()} is called
 * and calculates the elapsed time when {@link #stopAndRecord()} is called, recording
 * the measurement to the configured monitor.
 * <p>
 * Each instance is tied to a specific {@link MeasurementType}, allowing the measurement
 * to be properly categorized when recorded.
 * <p>
 * Note: This implementation is not thread-safe. Each thread should use its own instance.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
public final class ActiveMetricsTicker implements MetricsTicker {

    /**
     * The monitor to record measurements to.
     */
   
    private final TokenValidatorMonitor monitor;

    /**
     * The type of measurement being recorded.
     */
   
    private final MeasurementType measurementType;

    /**
     * The start time in nanoseconds, captured when startRecording is called.
     */
    private long startTime;

    /**
     * Captures the current time in nanoseconds for later measurement calculation.
     */
    @Override
    public void startRecording() {
        startTime = System.nanoTime();
    }

    /**
     * Calculates the elapsed time since {@link #startRecording()} was called
     * and records it to the monitor.
     * <p>
     * If {@link #startRecording()} was not called first, the behavior is undefined
     * (likely recording a very large or negative elapsed time).
     */
    @Override
    public void stopAndRecord() {
        long elapsedTime = System.nanoTime() - startTime;
        monitor.recordMeasurement(measurementType, elapsedTime);
    }
}
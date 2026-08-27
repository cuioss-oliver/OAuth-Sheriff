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

/**
 * Interface for timing measurements in the JWT validation pipeline.
 * <p>
 * This interface provides a clean abstraction for performance monitoring,
 * allowing for both active measurement recording and no-op implementations
 * to minimize overhead when metrics are disabled.
 * <p>
 * Implementations must be thread-safe if they will be used in concurrent contexts.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public interface MetricsTicker {

    /**
     * Starts recording the current time for later measurement calculation.
     * <p>
     * For active implementations, this typically captures {@code System.nanoTime()}.
     * For no-op implementations, this method does nothing.
     */
    void startRecording();

    /**
     * Stops recording and submits the elapsed time to the performance monitor.
     * <p>
     * For active implementations, this calculates the elapsed time since
     * {@link #startRecording()} was called and records it via the
     * {@link TokenValidatorMonitor}.
     * <p>
     * For no-op implementations, this method does nothing.
     * <p>
     * This method should be called exactly once after {@link #startRecording()},
     * typically in a finally block to ensure it's always called.
     */
    void stopAndRecord();
}
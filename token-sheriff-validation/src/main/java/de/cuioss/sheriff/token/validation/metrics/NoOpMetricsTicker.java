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
 * No-operation implementation of {@link MetricsTicker} used when metrics recording is disabled.
 * <p>
 * This implementation has zero overhead as all methods are empty and can be optimized away
 * by the JVM's JIT compiler. The singleton pattern ensures minimal memory footprint.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@SuppressWarnings("java:S6548") // owolff: fits for its purpose as a no-op implementation
public final class NoOpMetricsTicker implements MetricsTicker {

    /**
     * Singleton instance to avoid creating multiple instances.
     */
    public static final NoOpMetricsTicker INSTANCE = new NoOpMetricsTicker();

    /**
     * Private constructor to enforce singleton pattern.
     */
    private NoOpMetricsTicker() {
        // Prevent instantiation
    }

    /**
     * No-op implementation that does nothing.
     */
    @Override
    public void startRecording() {
        // Intentionally empty - no operation
    }

    /**
     * No-op implementation that does nothing.
     */
    @Override
    public void stopAndRecord() {
        // Intentionally empty - no operation
    }
}
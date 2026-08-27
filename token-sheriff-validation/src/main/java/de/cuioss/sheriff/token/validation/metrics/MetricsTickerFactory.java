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

import lombok.experimental.UtilityClass;

/**
 * Factory class for creating {@link MetricsTicker} instances.
 * <p>
 * This factory encapsulates the logic for creating appropriate ticker implementations
 * based on the monitor's configuration, breaking the cyclic dependency between
 * MeasurementType, TokenValidatorMonitor, and ActiveMetricsTicker.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@UtilityClass
public class MetricsTickerFactory {

    /**
     * Creates a {@link MetricsTicker} for the specified measurement type.
     * <p>
     * The recording decision is derived from the monitor's enabled types configuration.
     * If the measurement type is not enabled in the monitor, returns a no-op ticker with zero overhead.
     * Otherwise, returns an active ticker that will record measurements to the provided monitor.
     *
     * @param measurementType the type of measurement to create a ticker for
     * @param monitor the monitor to record measurements to (or check for enabled status)
     * @return a MetricsTicker instance appropriate for the monitor's configuration
     */
   
    private static MetricsTicker createTicker(MeasurementType measurementType,
            TokenValidatorMonitor monitor) {
        if (!monitor.isEnabled(measurementType)) {
            return NoOpMetricsTicker.INSTANCE;
        }
        return new ActiveMetricsTicker(monitor, measurementType);
    }

    /**
     * Creates a started {@link MetricsTicker} for the specified measurement type.
     * <p>
     * This is a convenience method that creates a ticker and immediately calls
     * {@link MetricsTicker#startRecording()} on it. This simplifies the common
     * pattern of creating a ticker and immediately starting it.
     * <p>
     * The recording decision is derived from the monitor's enabled types configuration.
     * If the measurement type is not enabled in the monitor, returns a no-op ticker with zero overhead.
     * Otherwise, returns an active ticker that is already started.
     *
     * @param measurementType the type of measurement to create a ticker for
     * @param monitor the monitor to record measurements to (or check for enabled status)
     * @return a started MetricsTicker instance appropriate for the monitor's configuration
     */
   
    public static MetricsTicker createStartedTicker(MeasurementType measurementType,
            TokenValidatorMonitor monitor) {
        MetricsTicker ticker = createTicker(measurementType, monitor);
        ticker.startRecording();
        return ticker;
    }
}
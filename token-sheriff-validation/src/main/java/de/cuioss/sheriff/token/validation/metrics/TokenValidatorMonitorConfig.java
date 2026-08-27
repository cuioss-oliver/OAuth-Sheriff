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

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;

import java.util.EnumSet;
import java.util.Set;

/**
 * Configuration for TokenValidatorMonitor to control which metrics are collected
 * and how they are stored.
 * <p>
 * This configuration allows selective monitoring of JWT validation pipeline steps,
 * enabling fine-grained control over metrics collection overhead and storage
 * requirements. When no measurement types are configured, no metrics will be
 * recorded, effectively disabling monitoring.
 * <p>
 * <strong>Performance Considerations:</strong>
 * <ul>
 *   <li>Only configured measurement types incur recording overhead</li>
 *   <li>Unconfigured types result in no-op operations</li>
 *   <li>Smaller window sizes reduce memory usage</li>
 *   <li>Empty measurement type set disables all monitoring</li>
 * </ul>
 * <p>
 * <strong>Usage Example:</strong>
 * <pre>
 * // Monitor only signature validation with small window
 * TokenValidatorMonitorConfig config = TokenValidatorMonitorConfig.builder()
 *     .windowSize(50)
 *     .measurementType(MeasurementType.SIGNATURE_VALIDATION)
 *     .measurementType(MeasurementType.COMPLETE_VALIDATION)
 *     .build();
 *
 * // Create configured monitor
 * TokenValidatorMonitor monitor = config.createMonitor();
 *
 * // Or disable all monitoring
 * TokenValidatorMonitorConfig disabled = TokenValidatorMonitorConfig.builder()
 *     .windowSize(100)
 *     .build(); // No measurement types = disabled
 * </pre>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@Builder
@Getter
public class TokenValidatorMonitorConfig {

    /**
     * All available measurement types for convenient configuration.
     * Use this constant when you want to monitor all pipeline steps.
     */
    public static final Set<MeasurementType> ALL_MEASUREMENT_TYPES =
            Set.copyOf(EnumSet.allOf(MeasurementType.class));

    /**
     * Default window size for the rolling measurement buffer.
     */
    public static final int DEFAULT_WINDOW_SIZE = 100;

    /**
     * The number of recent measurements to keep in the rolling window for each
     * configured measurement type.
     * <p>
     * Must be positive. Larger values provide more stable averages but consume
     * more memory. Smaller values react faster to performance changes but may
     * be more volatile.
     */
    @Builder.Default
    private final int windowSize = DEFAULT_WINDOW_SIZE;

    /**
     * The set of measurement types to monitor and record.
     * <p>
     * Only the measurement types included in this set will be recorded.
     * All other measurement types will result in no-op operations.
     * If this set is empty, no monitoring will be performed at all.
     * <p>
     * Use {@link #ALL_MEASUREMENT_TYPES} to monitor all available types.
     */
    @Singular
    private final Set<MeasurementType> measurementTypes;

    /**
     * Creates a preconfigured TokenValidatorMonitor based on this configuration.
     * <p>
     * The returned monitor will only record measurements for the configured
     * measurement types. All other types will be ignored (no-op).
     *
     * @return a new TokenValidatorMonitor configured according to this config
     * @throws IllegalArgumentException if windowSize is not positive
     */
    public TokenValidatorMonitor createMonitor() {
        Set<MeasurementType> types = measurementTypes != null ? measurementTypes : EnumSet.noneOf(MeasurementType.class);
        return new TokenValidatorMonitor(windowSize, types);
    }


    /**
     * Creates a configuration with the default window size that enables ALL measurement types.
     *
     * @return configuration with all measurement types enabled and default window size
     */
    public static TokenValidatorMonitorConfig defaultEnabled() {
        return TokenValidatorMonitorConfig.builder()
                .measurementTypes(ALL_MEASUREMENT_TYPES)
                .build();
    }

    /**
     * Creates a configuration that disables all monitoring.
     *
     * @return configuration with no measurement types enabled
     */
    public static TokenValidatorMonitorConfig disabled() {
        return TokenValidatorMonitorConfig.builder()
                .build(); // Empty measurement types = disabled
    }
}
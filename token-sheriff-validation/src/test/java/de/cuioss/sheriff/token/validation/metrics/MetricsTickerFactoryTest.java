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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link MetricsTickerFactory}.
 *
 * @author Oliver Wolff
 */
@DisplayName("Tests MetricsTickerFactory functionality")
class MetricsTickerFactoryTest {

    @Test
    @DisplayName("Should create NoOp started ticker when measurement type is disabled")
    void shouldCreateNoOpTickerWhenDisabled() {
        TokenValidatorMonitor monitor = TokenValidatorMonitorConfig.builder()
                .windowSize(100)
                .measurementTypes(Set.of(MeasurementType.SIGNATURE_VALIDATION))
                .build()
                .createMonitor();

        MetricsTicker ticker = MetricsTickerFactory.createStartedTicker(MeasurementType.TOKEN_PARSING, monitor);
        assertSame(NoOpMetricsTicker.INSTANCE, ticker, "Should return NoOp ticker for disabled type");
    }

    @Test
    @DisplayName("Should create ActiveMetricsTicker when measurement type is enabled")
    void shouldCreateActiveTickerWhenEnabled() {
        TokenValidatorMonitor monitor = TokenValidatorMonitorConfig.builder()
                .windowSize(100)
                .measurementTypes(Set.of(MeasurementType.SIGNATURE_VALIDATION))
                .build()
                .createMonitor();

        MetricsTicker ticker = MetricsTickerFactory.createStartedTicker(MeasurementType.SIGNATURE_VALIDATION, monitor);
        assertInstanceOf(ActiveMetricsTicker.class, ticker, "Should return Active ticker for enabled type");
    }

    @Test
    @DisplayName("Should create started ticker that begins recording immediately")
    void shouldCreateStartedTicker() {
        TokenValidatorMonitor monitor = TokenValidatorMonitorConfig.defaultEnabled().createMonitor();
        MeasurementType measurementType = MeasurementType.COMPLETE_VALIDATION;

        MetricsTicker ticker = MetricsTickerFactory.createStartedTicker(measurementType, monitor);
        assertNotNull(ticker, "Started ticker should not be null");

        // Test that it records properly
        ticker.stopAndRecord();

        // Verify measurement was recorded
        assertTrue(monitor.getSampleCount(measurementType) > 0,
                "Started ticker should record measurements when stopped");
    }

    @Test
    @DisplayName("Should create started NoOp ticker for disabled type")
    void shouldCreateStartedNoOpTickerForDisabledType() {
        TokenValidatorMonitor monitor = TokenValidatorMonitorConfig.builder()
                .windowSize(100)
                .measurementTypes(Set.of(MeasurementType.SIGNATURE_VALIDATION))
                .build()
                .createMonitor();

        MetricsTicker ticker = MetricsTickerFactory.createStartedTicker(MeasurementType.TOKEN_PARSING, monitor);
        assertSame(NoOpMetricsTicker.INSTANCE, ticker, "Should return NoOp ticker for disabled type");

        // Verify no measurement is recorded
        ticker.stopAndRecord();
        assertEquals(0, monitor.getSampleCount(MeasurementType.TOKEN_PARSING),
                "NoOp ticker should not record measurements");
    }
}
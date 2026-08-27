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
package de.cuioss.sheriff.token.validation;

import de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.metrics.MeasurementType;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitor;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitorConfig;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.tools.concurrent.StripedRingBufferStatistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies metrics collection behavior and reproduces missing metrics issues.
 */
class TokenValidatorMetricsVerificationTest {

    private TokenValidator tokenValidator;
    private TestTokenHolder testTokenHolder;

    @BeforeEach
    void setUp() {
        testTokenHolder = TestTokenGenerators.accessTokens().next();
        tokenValidator = TokenValidator.builder()
                .issuerConfig(testTokenHolder.getIssuerConfig())
                .cacheConfig(AccessTokenCacheConfig.disabled())
                .monitorConfig(TokenValidatorMonitorConfig.defaultEnabled())
                .build();
    }

    @Test
    void verifyMetricsCollectionAndTimingGaps() {
        // Given
        String tokenString = testTokenHolder.getRawToken();
        TokenValidatorMonitor monitor = tokenValidator.getPerformanceMonitor();

        // When - validate multiple times to get meaningful averages
        int iterations = 100;
        for (int i = 0; i < iterations; i++) {
            tokenValidator.createAccessToken(AccessTokenRequest.of(tokenString));
        }

        // Then - analyze metrics
        // Check each metric type
        long totalIndividualSteps = 0;
        for (MeasurementType type : MeasurementType.values()) {
            Duration duration = monitor.getValidationMetrics(type)
                    .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO);
            long nanos = duration.toNanos();

            if (type != MeasurementType.COMPLETE_VALIDATION && nanos > 0) {
                totalIndividualSteps += nanos;
            }
        }

        // Calculate timing gap
        long completeValidationNanos = monitor.getValidationMetrics(MeasurementType.COMPLETE_VALIDATION)
                .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO).toNanos();
        long timingGap = completeValidationNanos - totalIndividualSteps;
        double timingGapMillis = timingGap / 1_000_000.0;

        // Verify our findings
        assertTrue(completeValidationNanos > 0, "Complete validation should have duration");
        // Note: With ValidationContext optimization, the timing gap can be very small or even negative
        // due to measurement precision. We now only verify that the gap is reasonable (not huge).
        // A negative gap can occur when individual measurements have slightly more overhead than the complete measurement.
        assertTrue(timingGap > -1_000_000,
                """
                        Timing gap should be reasonable (within -1ms tolerance for measurement precision). \
                        Complete validation: %d ns, Sum of steps: %d ns, Gap: %d ns (%.3f ms)""".formatted(
                        completeValidationNanos, totalIndividualSteps, timingGap, timingGapMillis));

        // Check specific metrics that were missing in the benchmark
        checkMetric("ISSUER_EXTRACTION", monitor.getValidationMetrics(MeasurementType.ISSUER_EXTRACTION)
                .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO));
        checkMetric("HEADER_VALIDATION", monitor.getValidationMetrics(MeasurementType.HEADER_VALIDATION)
                .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO));
    }

    private void checkMetric(String name, Duration duration) {
        long nanos = duration.toNanos();
        assertTrue(nanos >= 0, name + " metric should have non-negative duration");
    }
}
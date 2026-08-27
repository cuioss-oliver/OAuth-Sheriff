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

import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.metrics.MeasurementType;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitor;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitorConfig;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.concurrent.StripedRingBufferStatistics;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test to verify that performance monitoring is properly integrated
 * into the TokenValidator pipeline and recording measurements during token validation.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("TokenValidator Performance Monitoring Integration Tests")
class TokenValidatorPerformanceIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidatorPerformanceIntegrationTest.class);

    private static int sampleCount(TokenValidatorMonitor monitor, MeasurementType type) {
        return monitor.getValidationMetrics(type).map(StripedRingBufferStatistics::sampleCount).orElse(0);
    }

    @Test
    @DisplayName("Should record performance metrics during token validation attempts")
    void shouldRecordPerformanceMetricsDuringValidation() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        var issuerConfig = tokenHolder.getIssuerConfig();
        var tokenValidator = TokenValidator.builder().monitorConfig(TokenValidatorMonitorConfig.defaultEnabled()).issuerConfig(issuerConfig).build();

        TokenValidatorMonitor performanceMonitor = tokenValidator.getPerformanceMonitor();

        // Verify initial state - no measurements
        assertEquals(Duration.ZERO, performanceMonitor.getValidationMetrics(MeasurementType.COMPLETE_VALIDATION)
                .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO));
        assertEquals(0, sampleCount(performanceMonitor, MeasurementType.COMPLETE_VALIDATION));

        // Try to validate an invalid token (empty string) - this should record metrics even for failures
        var emptyRequest = AccessTokenRequest.of("");
        try {
            tokenValidator.createAccessToken(emptyRequest);
            fail("Should have thrown TokenValidationException for empty token");
        } catch (IllegalArgumentException | IllegalStateException | TokenValidationException e) {
            // Expected - token validation should fail for empty string
        }

        // Verify that complete validation time was recorded (even for failed validation)
        assertTrue(sampleCount(performanceMonitor, MeasurementType.COMPLETE_VALIDATION) > 0,
                "Complete validation time should be recorded even for failed validations");
        assertTrue(performanceMonitor.getValidationMetrics(MeasurementType.COMPLETE_VALIDATION)
                .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO).toNanos() > 0,
                "Complete validation average should be positive");

        // Try with a malformed token - this should get further in the pipeline
        var malformedRequest = AccessTokenRequest.of("not.a.valid.jwt.token");
        try {
            tokenValidator.createAccessToken(malformedRequest);
            fail("Should have thrown TokenValidationException for malformed token");
        } catch (IllegalArgumentException | IllegalStateException | TokenValidationException e) {
            // Expected - token validation should fail for malformed token
        }

        // Verify that more measurements were recorded
        assertTrue(sampleCount(performanceMonitor, MeasurementType.COMPLETE_VALIDATION) >= 2,
                "Should have at least 2 complete validation measurements");

        // Check if token parsing was attempted (depends on how far validation got)
        var parsingCount = sampleCount(performanceMonitor, MeasurementType.TOKEN_PARSING);
        var parsingAverage = performanceMonitor.getValidationMetrics(MeasurementType.TOKEN_PARSING)
                .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO);

        if (parsingCount > 0) {
            assertTrue(parsingAverage.toNanos() > 0,
                    "Token parsing average should be positive when parsing was attempted");
        }

        // cui-rewrite:disable CuiLogRecordPatternRecipe
        // This is a test class that outputs diagnostic information for analysis
        LOGGER.info("Performance metrics after validation attempts:");
        LOGGER.info("- Complete validation: %s samples, avg %s μs",
                sampleCount(performanceMonitor, MeasurementType.COMPLETE_VALIDATION),
                performanceMonitor.getValidationMetrics(MeasurementType.COMPLETE_VALIDATION)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO).toNanos() / 1000.0);
        LOGGER.info("- Token parsing: %s samples, avg %s μs",
                sampleCount(performanceMonitor, MeasurementType.TOKEN_PARSING),
                performanceMonitor.getValidationMetrics(MeasurementType.TOKEN_PARSING)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO).toNanos() / 1000.0);
        LOGGER.info("- Header validation: %s samples, avg %s μs",
                sampleCount(performanceMonitor, MeasurementType.HEADER_VALIDATION),
                performanceMonitor.getValidationMetrics(MeasurementType.HEADER_VALIDATION)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO).toNanos() / 1000.0);
        LOGGER.info("- Signature validation: %s samples, avg %s μs",
                sampleCount(performanceMonitor, MeasurementType.SIGNATURE_VALIDATION),
                performanceMonitor.getValidationMetrics(MeasurementType.SIGNATURE_VALIDATION)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO).toNanos() / 1000.0);
        LOGGER.info("- Claims validation: %s samples, avg %s μs",
                sampleCount(performanceMonitor, MeasurementType.CLAIMS_VALIDATION),
                performanceMonitor.getValidationMetrics(MeasurementType.CLAIMS_VALIDATION)
                        .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO).toNanos() / 1000.0);
    }

    @Test
    @DisplayName("Should provide access to performance monitor through getter")
    void shouldProvideAccessToPerformanceMonitor() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        var issuerConfig = tokenHolder.getIssuerConfig();
        var tokenValidator = TokenValidator.builder().issuerConfig(issuerConfig).build();

        TokenValidatorMonitor performanceMonitor = tokenValidator.getPerformanceMonitor();
        assertNotNull(performanceMonitor, "Performance monitor should be accessible");

        // Verify it's properly initialized
        for (MeasurementType type : MeasurementType.values()) {
            assertEquals(Duration.ZERO, performanceMonitor.getValidationMetrics(type)
                            .map(StripedRingBufferStatistics::p50).orElse(Duration.ZERO),
                    "Initial average should be zero for " + type);
            assertEquals(0, sampleCount(performanceMonitor, type),
                    "Initial sample count should be zero for " + type);
        }
    }
}

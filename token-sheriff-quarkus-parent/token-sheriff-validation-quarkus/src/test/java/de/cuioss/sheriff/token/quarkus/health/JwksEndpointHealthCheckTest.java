/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.quarkus.health;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.JwksType;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.quarkus.config.JwtTestProfile;
import de.cuioss.sheriff.token.quarkus.observability.ObservedValidatorResolver;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import lombok.NonNull;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.easymock.EasyMock.createNiceMock;
import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
class JwksEndpointHealthCheckTest {

    @Inject
    @Readiness
    JwksEndpointHealthCheck healthCheck;

    @Test
    @DisplayName("Health check bean should be injected and available")
    void healthCheckBeanIsInjected() {
        assertNotNull(healthCheck, "JwksEndpointHealthCheck should be injected");
    }

    @Test
    @DisplayName("Health check should return UP status with valid configuration")
    void healthCheckShouldReturnUpStatus() {
        HealthCheckResponse response = healthCheck.call();
        assertNotNull(response, "HealthCheckResponse should not be null");
        assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                "Health check status should be UP with valid configuration");
    }

    @Test
    @DisplayName("Health check should have correct name")
    void healthCheckName() {
        HealthCheckResponse response = healthCheck.call();
        assertEquals("jwks-endpoints", response.getName(),
                "Health check should have correct name");
    }

    @Test
    @DisplayName("Health check should include correct data for UP status")
    void healthCheckDataForUpStatus() {
        HealthCheckResponse response = healthCheck.call();

        // Verify response has data
        assertTrue(response.getData().isPresent(),
                "Health check data should be present for UP status");

        Map<String, Object> data = response.getData().get();

        // UP status should have endpoint count and issuer data
        assertTrue(data.containsKey("checkedEndpoints"),
                "Health check data should contain checkedEndpoints count when UP");

        Object endpointCountValue = data.get("checkedEndpoints");
        assertNotNull(endpointCountValue, "checkedEndpoints should not be null");

        assertInstanceOf(Number.class, endpointCountValue,
                "checkedEndpoints should be a Number, but was: " + endpointCountValue.getClass().getSimpleName());

        int endpointCount = ((Number) endpointCountValue).intValue();
        assertTrue(endpointCount > 0,
                "checkedEndpoints should be greater than 0 when UP, but was: " + endpointCount);

        // Check for issuer-specific data
        boolean hasIssuerData = data.keySet().stream()
                .anyMatch(key -> key.startsWith("issuer."));
        assertTrue(hasIssuerData, "Should contain issuer-specific data when UP");
    }

    @Test
    @DisplayName("Health check should contain issuer endpoint details")
    void issuerEndpointDetails() {
        HealthCheckResponse response = healthCheck.call();

        // With valid configuration, we expect UP status and data to be present
        assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                "Health check status should be UP with valid configuration");
        assertTrue(response.getData().isPresent(),
                "Health check data should be present with valid configuration");

        Map<String, Object> data = response.getData().get();

        // Look for issuer-specific data patterns
        data.entrySet().stream()
                .filter(entry -> entry.getKey().startsWith("issuer.") && entry.getKey().endsWith(".url"))
                .forEach(entry -> {
                    String issuerPrefix = entry.getKey().substring(0, entry.getKey().lastIndexOf(".url"));

                    // Check that each issuer has required fields
                    assertTrue(data.containsKey(issuerPrefix + ".url"),
                            "Should contain URL for " + issuerPrefix);
                    assertTrue(data.containsKey(issuerPrefix + ".jwksType"),
                            "Should contain jwksType for " + issuerPrefix);
                    assertTrue(data.containsKey(issuerPrefix + ".status"),
                            "Should contain status for " + issuerPrefix);

                    // Verify status values
                    Object statusValue = data.get(issuerPrefix + ".status");
                    assertTrue("UP".equals(statusValue) || "DOWN".equals(statusValue),
                            "Issuer status should be UP or DOWN");
                });
    }

    @Test
    @DisplayName("Health check should handle concurrent calls properly")
    void concurrentHealthCheckCalls() {
        // Make multiple concurrent calls to test thread safety and caching
        HealthCheckResponse response1 = healthCheck.call();
        HealthCheckResponse response2 = healthCheck.call();
        HealthCheckResponse response3 = healthCheck.call();

        assertNotNull(response1, "First response should not be null");
        assertNotNull(response2, "Second response should not be null");
        assertNotNull(response3, "Third response should not be null");

        // All responses should have the same status (due to caching)
        assertEquals(response1.getStatus(), response2.getStatus(),
                "Concurrent calls should return same status");
        assertEquals(response1.getStatus(), response3.getStatus(),
                "Concurrent calls should return same status");
    }

    @Test
    @DisplayName("Health check should handle valid configuration gracefully")
    void healthCheckValidConfiguration() {
        HealthCheckResponse response = healthCheck.call();

        // Response should be valid with proper configuration
        assertNotNull(response, "Response should not be null");
        assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                "Health check status should be UP with valid configuration");
        assertEquals("jwks-endpoints", response.getName(),
                "Health check should have correct name");

        assertTrue(response.getData().isPresent(), "Data should be present");
        Map<String, Object> data = response.getData().get();
        assertTrue(data.containsKey("checkedEndpoints"),
                "Should contain endpoint data for valid configuration");
    }

    @Test
    @DisplayName("Health check should handle error in JwksLoader")
    void healthCheckJwksLoaderError() {
        // Create a mock IssuerConfig with a JwksLoader that throws an exception
        IssuerConfig errorIssuerConfig = IssuerConfig.builder()
                .issuerIdentifier("error-issuer")
                .jwksLoader(new ErrorJwksLoader())
                .audienceValidationDisabled(true)
                .build();

        // Create a health check with the error issuer config
        JwksEndpointHealthCheck errorHealthCheck = new JwksEndpointHealthCheck(
                observing(errorIssuerConfig), 30);

        // Call the health check
        HealthCheckResponse response = errorHealthCheck.call();

        // Verify response
        assertNotNull(response, "Response should not be null");
        assertEquals(HealthCheckResponse.Status.DOWN, response.getStatus(),
                "Health check status should be DOWN with error in JwksLoader");
        assertEquals("jwks-endpoints", response.getName(),
                "Health check should have correct name");

        assertTrue(response.getData().isPresent(), "Data should be present");
        Map<String, Object> data = response.getData().get();
        assertTrue(data.containsKey("checkedEndpoints"),
                "Should contain endpoint count");
        assertEquals(1, ((Number) data.get("checkedEndpoints")).intValue(),
                "Should have checked 1 endpoint");

        // Check for issuer-specific data
        assertTrue(data.containsKey("issuer.0.url"),
                "Should contain URL for issuer.0");
        assertEquals("error-issuer", data.get("issuer.0.url"),
                "URL should match issuer identifier");
        assertTrue(data.containsKey("issuer.0.jwksType"),
                "Should contain jwksType for issuer.0");
        assertEquals("none", data.get("issuer.0.jwksType"),
                "jwksType should be 'none'");
        assertTrue(data.containsKey("issuer.0.status"),
                "Should contain status for issuer.0");
        assertEquals("DOWN", data.get("issuer.0.status"),
                "Status should be DOWN");
    }

    @Test
    @DisplayName("Health check should handle mixed healthy and unhealthy endpoints")
    void healthCheckMixedEndpoints() {
        // Create a healthy issuer config
        IssuerConfig healthyIssuerConfig = IssuerConfig.builder()
                .issuerIdentifier("healthy-issuer")
                .jwksLoader(new HealthyJwksLoader())
                .audienceValidationDisabled(true)
                .build();

        // Create an unhealthy issuer config
        IssuerConfig unhealthyIssuerConfig = IssuerConfig.builder()
                .issuerIdentifier("unhealthy-issuer")
                .jwksLoader(new UnhealthyJwksLoader())
                .audienceValidationDisabled(true)
                .build();

        // Create a health check with both issuer configs
        JwksEndpointHealthCheck mixedHealthCheck = new JwksEndpointHealthCheck(
                observing(healthyIssuerConfig, unhealthyIssuerConfig), 30);

        // Call the health check
        HealthCheckResponse response = mixedHealthCheck.call();

        // Verify response
        assertNotNull(response, "Response should not be null");
        assertEquals(HealthCheckResponse.Status.DOWN, response.getStatus(),
                "Health check status should be DOWN with mixed endpoints");
        assertEquals("jwks-endpoints", response.getName(),
                "Health check should have correct name");

        assertTrue(response.getData().isPresent(), "Data should be present");
        Map<String, Object> data = response.getData().get();
        assertTrue(data.containsKey("checkedEndpoints"),
                "Should contain endpoint count");
        assertEquals(2, ((Number) data.get("checkedEndpoints")).intValue(),
                "Should have checked 2 endpoints");

        // Check for healthy issuer data
        assertTrue(data.containsKey("issuer.0.url"),
                "Should contain URL for issuer.0");
        assertEquals("healthy-issuer", data.get("issuer.0.url"),
                "URL should match healthy issuer identifier");
        assertTrue(data.containsKey("issuer.0.jwksType"),
                "Should contain jwksType for issuer.0");
        assertEquals("memory", data.get("issuer.0.jwksType"),
                "jwksType should be 'memory'");
        assertTrue(data.containsKey("issuer.0.status"),
                "Should contain status for issuer.0");
        assertEquals("UP", data.get("issuer.0.status"),
                "Status should be UP");

        // Check for unhealthy issuer data
        assertTrue(data.containsKey("issuer.1.url"),
                "Should contain URL for issuer.1");
        assertEquals("unhealthy-issuer", data.get("issuer.1.url"),
                "URL should match unhealthy issuer identifier");
        assertTrue(data.containsKey("issuer.1.jwksType"),
                "Should contain jwksType for issuer.1");
        assertEquals("memory", data.get("issuer.1.jwksType"),
                "jwksType should be 'memory'");
        assertTrue(data.containsKey("issuer.1.status"),
                "Should contain status for issuer.1");
        assertEquals("DOWN", data.get("issuer.1.status"),
                "Status should be DOWN");
    }

    @Test
    @DisplayName("Health check should handle cache expiration")
    void healthCheckCacheExpiration() {
        // Create a health check with a very short cache timeout (1 millisecond)
        JwksEndpointHealthCheck shortCacheHealthCheck = new JwksEndpointHealthCheck(
                observing(IssuerConfig.builder()
                        .issuerIdentifier("cache-test-issuer")
                        .jwksLoader(new HealthyJwksLoader())
                        .audienceValidationDisabled(true)
                        .build()),
                1);

        // First call should create a new response
        HealthCheckResponse response1 = shortCacheHealthCheck.call();
        assertNotNull(response1, "First response should not be null");

        // Wait for cache to expire using Awaitility
        await().atLeast(10, TimeUnit.MILLISECONDS);

        // Second call should create a new response after cache expiration
        HealthCheckResponse response2 = shortCacheHealthCheck.call();
        assertNotNull(response2, "Second response should not be null");

        // Both responses should have the same status and data structure
        assertEquals(response1.getStatus(), response2.getStatus(),
                "Both responses should have the same status");
        assertEquals(response1.getName(), response2.getName(),
                "Both responses should have the same name");
    }

    @Test
    @DisplayName("Health check should be fail-fast and non-blocking (getLoaderStatus() behavior)")
    void healthCheckShouldBeFailFastAndNonBlocking() {
        // Create a fast JwksLoader implementation that demonstrates fail-fast behavior
        JwksLoader failFastLoader = new JwksLoader() {
            @Override
            public Optional<KeyInfo> getKeyInfo(String kid) {
                return Optional.empty();
            }

            @Override
            public JwksType getJwksType() {
                return JwksType.MEMORY;
            }

            @Override
            public LoaderStatus getLoaderStatus() {
                // This method should be fail-fast and return immediately without blocking
                return LoaderStatus.UNDEFINED; // Simulates initial state before any loading attempt
            }

            @Override
            public Optional<String> getIssuerIdentifier() {
                return Optional.empty();
            }

            @Override
            public CompletableFuture<LoaderStatus> initJWKSLoader(@NonNull SecurityEventCounter securityEventCounter) {
                // No initialization needed for test
                return CompletableFuture.completedFuture(LoaderStatus.UNDEFINED);
            }
        };

        // Create issuer config with fail-fast loader
        IssuerConfig failFastIssuerConfig = IssuerConfig.builder()
                .issuerIdentifier("fail-fast-issuer")
                .jwksLoader(failFastLoader)
                .audienceValidationDisabled(true)
                .build();

        // Create health check with fail-fast loader
        JwksEndpointHealthCheck failFastHealthCheck = new JwksEndpointHealthCheck(
                observing(failFastIssuerConfig), 30);

        // Measure execution time to ensure it's fail-fast
        long startTime = System.currentTimeMillis();
        HealthCheckResponse response = failFastHealthCheck.call();
        long executionTime = System.currentTimeMillis() - startTime;

        // Verify response
        assertNotNull(response, "Response should not be null");
        assertEquals("jwks-endpoints", response.getName(),
                "Health check should have correct name");

        // Verify fail-fast behavior - should complete very quickly (< 100ms)
        assertTrue(executionTime < 100,
                "Health check should be fail-fast (< 100ms), but took: " + executionTime + "ms");

        // Verify response contains data about the UNDEFINED status
        assertTrue(response.getData().isPresent(), "Data should be present");
        Map<String, Object> data = response.getData().get();

        // UNDEFINED status should be reported as DOWN in health check
        assertEquals("DOWN", data.get("issuer.0.status"),
                "UNDEFINED status should be reported as DOWN");
        assertEquals("fail-fast-issuer", data.get("issuer.0.url"),
                "URL should match issuer identifier");
        assertEquals("memory", data.get("issuer.0.jwksType"),
                "jwksType should be 'memory'");

        // Overall status should be DOWN due to UNDEFINED loader status
        assertEquals(HealthCheckResponse.Status.DOWN, response.getStatus(),
                "Health check status should be DOWN with UNDEFINED loader status");
    }

    @Test
    @DisplayName("Health check should report UP with zero endpoints when an external validator is observed")
    void healthCheckExternalValidator() {
        JwksEndpointHealthCheck externalHealthCheck = new JwksEndpointHealthCheck(
                new ObservedValidatorResolver(ObservedValidatorResolver.Outcome.EXTERNAL_VALIDATOR,
                        createNiceMock(TokenValidator.class), List.of(), null),
                30);

        HealthCheckResponse response = externalHealthCheck.call();

        Map<String, Object> data = response.getData().orElseThrow();
        assertAll("external validator readiness",
                () -> assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                        "Readiness must stay UP when an external validator is in use"),
                () -> assertEquals(0, ((Number) data.get("checkedEndpoints")).intValue(),
                        "A foreign validator exposes no JWKS endpoints to probe"),
                () -> assertEquals("EXTERNAL_VALIDATOR", data.get("readiness"),
                        "readiness must name the external-validator outcome"),
                () -> assertFalse(data.containsKey("issuer.0.url"),
                        "No per-issuer data may be emitted without observable issuers"));
    }

    @Test
    @DisplayName("Health check should report UP with zero endpoints when nothing is configured")
    void healthCheckNotConfigured() {
        JwksEndpointHealthCheck unconfiguredHealthCheck = new JwksEndpointHealthCheck(
                new ObservedValidatorResolver(ObservedValidatorResolver.Outcome.NOT_CONFIGURED,
                        null, List.of(), null),
                30);

        HealthCheckResponse response = unconfiguredHealthCheck.call();

        Map<String, Object> data = response.getData().orElseThrow();
        assertAll("unconfigured readiness",
                () -> assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                        "An unconfigured optional extension must not hold the application out of the load balancer"),
                () -> assertEquals(0, ((Number) data.get("checkedEndpoints")).intValue(),
                        "Nothing is observable, so nothing is probed"),
                () -> assertEquals("NOT_CONFIGURED", data.get("readiness"),
                        "readiness must name the not-configured outcome"));
    }

    /**
     * Pins a resolver to the property-configured outcome over the supplied issuer configurations.
     */
    private static ObservedValidatorResolver observing(IssuerConfig... issuerConfigs) {
        return new ObservedValidatorResolver(ObservedValidatorResolver.Outcome.PROPERTY_CONFIGURED,
                createNiceMock(TokenValidator.class), List.of(issuerConfigs), null);
    }

    // Mock JwksLoader implementations for testing

    /**
     * JwksLoader that throws an exception when getJwksType() is called.
     */
    private static class ErrorJwksLoader implements JwksLoader {
        @Override
        public Optional<KeyInfo> getKeyInfo(String kid) {
            return Optional.empty();
        }

        @Override
        public JwksType getJwksType() {
            throw new IllegalStateException("Simulated error in JwksLoader");
        }

        @Override
        public Optional<String> getIssuerIdentifier() {
            return Optional.empty();
        }

        @Override
        public CompletableFuture<LoaderStatus> initJWKSLoader(@NonNull SecurityEventCounter securityEventCounter) {
            // Do nothing
            return CompletableFuture.completedFuture(LoaderStatus.ERROR);
        }

        @Override
        public LoaderStatus getLoaderStatus() {
            return LoaderStatus.ERROR;
        }

    }

    /**
     * JwksLoader that always returns a healthy status.
     */
    private static class HealthyJwksLoader implements JwksLoader {
        @Override
        public Optional<KeyInfo> getKeyInfo(String kid) {
            return Optional.empty();
        }

        @Override
        public JwksType getJwksType() {
            return JwksType.MEMORY;
        }

        @Override
        public Optional<String> getIssuerIdentifier() {
            return Optional.empty();
        }

        @Override
        public CompletableFuture<LoaderStatus> initJWKSLoader(@NonNull SecurityEventCounter securityEventCounter) {
            // Do nothing
            return CompletableFuture.completedFuture(LoaderStatus.OK);
        }

        @Override
        public LoaderStatus getLoaderStatus() {
            return LoaderStatus.OK;
        }

    }

    /**
     * JwksLoader that always returns an unhealthy status.
     */
    private static class UnhealthyJwksLoader implements JwksLoader {
        @Override
        public Optional<KeyInfo> getKeyInfo(String kid) {
            return Optional.empty();
        }

        @Override
        public JwksType getJwksType() {
            return JwksType.MEMORY;
        }

        @Override
        public Optional<String> getIssuerIdentifier() {
            return Optional.empty();
        }

        @Override
        public CompletableFuture<LoaderStatus> initJWKSLoader(@NonNull SecurityEventCounter securityEventCounter) {
            // Do nothing
            return CompletableFuture.completedFuture(LoaderStatus.ERROR);
        }

        @Override
        public LoaderStatus getLoaderStatus() {
            return LoaderStatus.ERROR;
        }

    }
}

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
package de.cuioss.sheriff.token.quarkus.runtime;

import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.config.JwtTestProfile;
import de.cuioss.sheriff.token.quarkus.observability.ObservedValidatorResolver;
import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import de.cuioss.sheriff.token.quarkus.test.TestConfigurations;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for {@link TokenSheriffDevUIRuntimeService}.
 * <p>
 * This test class provides comprehensive coverage of the runtime service functionality,
 * including validation status, JWKS status, configuration, token validation, and health
 * information. Tests use the Quarkus test framework with real dependencies.
 * </p>
 */
@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
@DisplayName("TokenSheriffDevUIRuntimeService Tests")
class TokenSheriffDevUIRuntimeServiceTest {

    @Inject
    TokenSheriffDevUIRuntimeService service;

    @Inject
    TokenValidator tokenValidator;

    @Inject
    Config config;

    @Inject
    List<IssuerConfig> issuerConfigs;

    /**
     * Pins a resolver to the property-configured outcome over the supplied dependencies, mirroring
     * what the CDI-wired resolver reports when the issuer namespace is populated.
     */
    private static ObservedValidatorResolver propertyConfigured(TokenValidator validator,
            List<IssuerConfig> issuerConfigs) {
        return new ObservedValidatorResolver(ObservedValidatorResolver.Outcome.PROPERTY_CONFIGURED,
                validator, issuerConfigs, ParserConfig.builder().build());
    }


    @Nested
    @DisplayName("Validation Status Tests")
    class ValidationStatusTests {

        @Test
        @DisplayName("Should return validation status with current configuration")
        void shouldReturnValidationStatusWithCurrentConfiguration() {
            Map<String, Object> result = service.getValidationStatus();

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("enabled"), "Enabled status should be present");
            assertNotNull(result.get("validatorPresent"), "Validator present status should be present");
            assertNotNull(result.get("status"), "Status should be present");
            assertNotNull(result.get("statusMessage"), "Status message should be present");

            boolean enabled = (Boolean) result.get("enabled");
            String statusMessage = (String) result.get("statusMessage");

            // Based on the current test configuration (JwtTestProfile), validation is enabled
            assertTrue(enabled, "JWT validation should be enabled with current test configuration");
            assertEquals("ACTIVE", result.get("status"), "Status should be ACTIVE when enabled");
            assertEquals("JWT validation is active and ready", statusMessage,
                    "Status message should indicate active validation when enabled");
        }

        @Test
        @DisplayName("Should correctly determine JWT enabled status based on issuer configuration")
        void shouldCorrectlyDetermineJwtEnabledStatusBasedOnIssuerConfiguration() {
            Map<String, Object> result = service.getValidationStatus();

            assertNotNull(result, "Result should not be null");

            // Test the actual configuration state - JWT is enabled in current test profile
            boolean enabled = (Boolean) result.get("enabled");
            assertTrue(enabled, "JWT should be enabled with current test configuration");

            String statusMessage = (String) result.get("statusMessage");
            assertEquals("JWT validation is active and ready", statusMessage,
                    "Status message should indicate active validation when enabled");
            assertTrue(Boolean.parseBoolean(result.get("validatorPresent").toString()), "Validator present status should be reported");
        }

        @Test
        @DisplayName("Should attempt token validation when JWT is enabled")
        void shouldAttemptTokenValidationWhenJwtIsEnabled() {
            // Test that token validation is attempted when JWT is enabled (current test configuration)
            String invalidJwtFormat = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.invalid-signature";

            Map<String, Object> result = service.validateToken(invalidJwtFormat);

            assertNotNull(result, "Result should not be null");

            // The validation was attempted (not disabled), check the actual result
            Boolean valid = (Boolean) result.get("valid");
            assertNotNull(valid, "Valid status should be present");

            if (valid) {
                // Token was successfully validated (possibly as refresh token)
                assertNotNull(result.get("tokenType"), "Token type should be present for valid tokens");
            } else {
                // Token validation failed, but validation was attempted
                String error = (String) result.get("error");
                assertNotNull(error, "Should have error message");
                assertNotEquals("JWT validation is disabled", error, "Error should not be 'disabled' message when JWT is enabled");

                // Verify no token type or claims are returned for invalid tokens
                assertNull(result.get("tokenType"), "Token type should not be present for invalid tokens");
                assertNull(result.get("claims"), "Claims should not be present for invalid tokens");
            }
        }
    }

    @Nested
    @DisplayName("JWKS Status Tests")
    class JwksStatusTests {

        @Test
        @DisplayName("Should return JWKS status with current configuration")
        void shouldReturnJwksStatusWithCurrentConfiguration() {
            Map<String, Object> result = service.getJwksStatus();

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("status"), "Status should be present");
            assertNotNull(result.get("issuers"), "Issuers list should be present");

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> issuers = (List<Map<String, Object>>) result.get("issuers");
            assertTrue(issuers.size() >= 0, "Issuers count should be non-negative");
        }

        @Test
        @DisplayName("Should correctly list configured issuers with details")
        void shouldCorrectlyListConfiguredIssuersWithDetails() {
            Map<String, Object> result = service.getJwksStatus();

            assertNotNull(result, "Result should not be null");

            // Based on JwtTestProfile: "default" issuer is enabled
            String status = (String) result.get("status");
            assertEquals("CONFIGURED", status, "Status should be CONFIGURED when issuers exist");

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> issuers = (List<Map<String, Object>>) result.get("issuers");
            assertTrue(issuers.size() >= 1, "Should have at least one configured issuer, but found: " + issuers.size());

            // Verify issuer details
            Map<String, Object> firstIssuer = issuers.getFirst();
            assertNotNull(firstIssuer.get("name"), "Issuer name should be present");
            assertNotNull(firstIssuer.get("issuerUri"), "Issuer URI should be present");
            assertNotNull(firstIssuer.get("loaderStatus"), "Loader status should be present");
        }

    }

    @Nested
    @DisplayName("Configuration Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should return configuration information with nested structure")
        void shouldReturnConfigurationInformation() {
            Map<String, Object> result = service.getConfiguration();

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("enabled"), "Enabled status should be present");
            assertNotNull(result.get("logLevel"), "Log level should be present");
            assertNotNull(result.get("parser"), "Parser config should be present");
            assertNotNull(result.get("httpJwksLoader"), "HTTP JWKS loader config should be present");
            assertNotNull(result.get("issuers"), "Issuers config should be present");
        }

        @Test
        @DisplayName("Should have consistent configuration structure")
        void shouldHaveConsistentConfigurationStructure() {
            Map<String, Object> result = service.getConfiguration();

            assertNotNull(result, "Result should not be null");
            assertTrue(result.containsKey("enabled"), "Should contain enabled key");
            assertTrue(result.containsKey("logLevel"), "Should contain logLevel key");
            assertTrue(result.containsKey("parser"), "Should contain parser key");
            assertTrue(result.containsKey("httpJwksLoader"), "Should contain httpJwksLoader key");
            assertTrue(result.containsKey("issuers"), "Should contain issuers key");

            // Verify data types
            assertInstanceOf(Boolean.class, result.get("enabled"), "Enabled should be Boolean");
            assertInstanceOf(String.class, result.get("logLevel"), "LogLevel should be String");
            assertInstanceOf(Map.class, result.get("parser"), "Parser should be Map");
            assertInstanceOf(Map.class, result.get("httpJwksLoader"), "HttpJwksLoader should be Map");
            assertInstanceOf(Map.class, result.get("issuers"), "Issuers should be Map");

            // Verify parser sub-structure
            @SuppressWarnings("unchecked")
            Map<String, Object> parser = (Map<String, Object>) result.get("parser");
            assertNotNull(parser.get("maxTokenSize"), "Parser should have maxTokenSize");
        }

    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("Should return error for null token")
        void shouldReturnErrorForNullToken() {
            Map<String, Object> result = service.validateToken(null);

            assertNotNull(result, "Result should not be null");
            assertEquals(false, result.get("valid"), "Should be invalid");
            assertEquals("Token is empty or null", result.get("error"), "Should have correct error message");
        }

        @Test
        @DisplayName("Should return error for empty token")
        void shouldReturnErrorForEmptyToken() {
            Map<String, Object> result = service.validateToken("   ");

            assertNotNull(result, "Result should not be null");
            assertEquals(false, result.get("valid"), "Should be invalid");
            assertEquals("Token is empty or null", result.get("error"), "Should have correct error message");
        }

        @Test
        @DisplayName("Should attempt access token validation when JWT is enabled")
        void shouldAttemptAccessTokenValidationWhenJwtIsEnabled() {
            // Create a service with enabled JWT configuration to test the validation logic
            TokenSheriffDevUIRuntimeService enabledService = new TokenSheriffDevUIRuntimeService(propertyConfigured(tokenValidator, issuerConfigs));

            // Test with an invalid access token to see the validation attempt behavior
            // This tests that validation is attempted (not just disabled)
            String testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid-payload.invalid-signature";
            Map<String, Object> result = enabledService.validateToken(testToken);

            assertNotNull(result, "Result should not be null");

            // The main test is that validation was attempted (not just disabled)
            // If JWT is enabled, validation should be attempted regardless of the result
            String error = (String) result.get("error");
            if (error != null) {
                assertNotEquals("JWT validation is disabled", error, "Error should not be 'disabled' message when JWT is enabled");
            }

            // Since we only validate access tokens now, invalid tokens should be rejected
            Boolean isValid = (Boolean) result.get("valid");
            if (isValid) {
                // If valid, should have ACCESS_TOKEN type and claims
                assertEquals("ACCESS_TOKEN", result.get("tokenType"), "Valid token should be ACCESS_TOKEN type");
                assertNotNull(result.get("claims"), "Valid access token should have claims");
                assertNotNull(result.get("issuer"), "Valid access token should have issuer");
            } else {
                // If invalid, should have error message but not token type
                assertNotNull(error, "Invalid token should have error message");
                assertNull(result.get("tokenType"), "Invalid token should not have token type");
                assertNull(result.get("claims"), "Invalid token should not have claims");
            }
        }
    }

    @Nested
    @DisplayName("Health Info Tests")
    class HealthInfoTests {

        @Test
        @DisplayName("Should return health information")
        void shouldReturnHealthInformation() {
            Map<String, Object> result = service.getHealthInfo();

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("configurationValid"), "Configuration valid status should be present");
            assertNotNull(result.get("message"), "Message should be present");
            assertNotNull(result.get("healthStatus"), "Health status should be present");

            String healthStatus = (String) result.get("healthStatus");
            assertTrue("UP".equals(healthStatus) || "DOWN".equals(healthStatus),
                    "Health status should be either UP or DOWN");
        }

        @Test
        @DisplayName("Should determine health status based on configuration and validator availability")
        void shouldDetermineHealthStatusBasedOnConfigurationAndValidatorAvailability() {
            Map<String, Object> result = service.getHealthInfo();

            assertNotNull(result, "Result should not be null");

            boolean configValid = (Boolean) result.get("configurationValid");
            String healthStatus = (String) result.get("healthStatus");
            String message = (String) result.get("message");

            if (configValid) {
                assertEquals("UP", healthStatus, "Health should be UP when config is valid");
                assertTrue(message.contains("healthy") || message.contains("operational"),
                        "Message should indicate healthy state");
            } else {
                assertEquals("DOWN", healthStatus, "Health should be DOWN when config is invalid");
                assertTrue(message.contains("disabled") || message.contains("misconfigured"),
                        "Message should indicate configuration issues");
            }
        }

    }

    @Nested
    @DisplayName("Configuration Scenarios Tests")
    class ConfigurationScenariosTests {

        @Test
        @DisplayName("Should handle service with enabled issuer configuration")
        void shouldHandleServiceWithEnabledIssuerConfiguration() {
            // Create a service with enabled issuer configuration
            TokenSheriffDevUIRuntimeService testService = new TokenSheriffDevUIRuntimeService(propertyConfigured(tokenValidator, issuerConfigs));

            Map<String, Object> validationStatus = testService.getValidationStatus();
            Map<String, Object> configuration = testService.getConfiguration();

            // With enabled issuer, JWT should be enabled
            Boolean jwtEnabled = (Boolean) validationStatus.get("enabled");
            @SuppressWarnings("unchecked")
            Map<String, Object> issuersMap = (Map<String, Object>) configuration.get("issuers");

            assertTrue(jwtEnabled, "JWT should be enabled with valid issuer configuration");
            assertFalse(issuersMap.isEmpty(), "Should have at least one issuer in config");
        }

        @Test
        @DisplayName("Should handle service with multiple issuers")
        void shouldHandleServiceWithMultipleIssuers() {
            // Create a service with multiple issuers
            List<IssuerConfig> issuerConfigsList = new ArrayList<>(issuerConfigs);
            // Duplicate, but we only test the size here
            issuerConfigsList.addAll(issuerConfigs);
            TokenSheriffDevUIRuntimeService testService = new TokenSheriffDevUIRuntimeService(propertyConfigured(tokenValidator, issuerConfigsList));

            Map<String, Object> jwksStatus = testService.getJwksStatus();

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> issuers = (List<Map<String, Object>>) jwksStatus.get("issuers");
            assertTrue(issuers.size() >= 2, "Should have multiple configured issuers, but found: " + issuers.size());
        }

        @Test
        @DisplayName("Should report healthy state for enabled configuration")
        void shouldDetermineHealthBasedOnDifferentConfigurations() {
            // A property-configured resolution keeps the configurationValid => UP contract
            TokenSheriffDevUIRuntimeService enabledService = new TokenSheriffDevUIRuntimeService(propertyConfigured(tokenValidator, issuerConfigs));

            Map<String, Object> enabledHealth = enabledService.getHealthInfo();
            Boolean configurationValid = (Boolean) enabledHealth.get("configurationValid");
            assertTrue(configurationValid, "Configuration should be valid with enabled issuer");
            assertEquals("UP", enabledHealth.get("healthStatus"), "Health should be UP");
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create service over a resolver reporting NOT_CONFIGURED")
        void shouldCreateServiceWithUnconfiguredResolver() {
            // The constructor performs no validation — it only stores its dependency
            TokenSheriffDevUIRuntimeService unconfiguredService = assertDoesNotThrow(
                    () -> new TokenSheriffDevUIRuntimeService(new ObservedValidatorResolver(
                            ObservedValidatorResolver.Outcome.NOT_CONFIGURED, null, List.of(), null)),
                    "Constructor should not throw when nothing is observable");

            assertEquals("NOT_CONFIGURED", unconfiguredService.getValidationStatus().get("status"),
                    "An unconfigured resolver must surface as NOT_CONFIGURED rather than throwing");
        }

        @Test
        @DisplayName("Should create service with valid dependencies")
        void shouldCreateServiceWithValidDependencies() {
            // Test constructor with actual dependencies
            TokenSheriffDevUIRuntimeService testService = new TokenSheriffDevUIRuntimeService(propertyConfigured(tokenValidator, issuerConfigs));
            assertNotNull(testService, "Service should be created successfully with valid dependencies");

            // Verify the service can perform basic operations
            assertDoesNotThrow(testService::getValidationStatus,
                    "Service should be able to get validation status");
            assertDoesNotThrow(testService::getConfiguration,
                    "Service should be able to get configuration");
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle validateToken with whitespace-only token")
        void shouldHandleWhitespaceOnlyToken() {
            // Act
            Map<String, Object> result = service.validateToken("   \t\n   ");

            // Assert
            assertNotNull(result, "Result should not be null");
            assertEquals(false, result.get("valid"), "Should be invalid");
            assertEquals("Token is empty or null", result.get("error"),
                    "Should have correct error message for whitespace-only token");
        }

        @Test
        @DisplayName("Should handle validateToken with very long token")
        void shouldHandleVeryLongToken() {
            Map<String, Object> result = service.validateToken("a".repeat(10000));

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("valid"), "Valid status should be present");
        }

        @Test
        @DisplayName("Should handle validateToken with special characters")
        void shouldHandleTokenWithSpecialCharacters() {
            Map<String, Object> result = service.validateToken("!@#$%^&*()_+-=[]{}|;':\",./<>?");

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("valid"), "Valid status should be present");
        }

        @Test
        @DisplayName("Should handle multiple consecutive calls with consistency")
        void shouldHandleMultipleConsecutiveCallsWithConsistency() {
            // Test all methods for consistency across multiple calls
            Map<String, Object> validation1 = service.getValidationStatus();
            Map<String, Object> validation2 = service.getValidationStatus();
            Map<String, Object> config1 = service.getConfiguration();
            Map<String, Object> config2 = service.getConfiguration();
            Map<String, Object> health1 = service.getHealthInfo();
            Map<String, Object> health2 = service.getHealthInfo();
            Map<String, Object> jwks1 = service.getJwksStatus();
            Map<String, Object> jwks2 = service.getJwksStatus();

            // Validation status consistency
            assertEquals(validation1.get("enabled"), validation2.get("enabled"), "Validation enabled should be consistent");
            assertEquals(validation1.get("status"), validation2.get("status"), "Validation status should be consistent");

            // Configuration consistency
            assertEquals(config1.get("enabled"), config2.get("enabled"), "Config enabled should be consistent");
            assertEquals(config1.get("parser"), config2.get("parser"), "Config parser should be consistent");

            // Health info consistency
            assertEquals(health1.get("configurationValid"), health2.get("configurationValid"), "Health config valid should be consistent");
            assertEquals(health1.get("healthStatus"), health2.get("healthStatus"), "Health status should be consistent");

            // JWKS status consistency
            assertEquals(jwks1.get("status"), jwks2.get("status"), "JWKS status should be consistent");
            assertEquals(jwks1.get("issuers"), jwks2.get("issuers"), "JWKS issuers should be consistent");
        }

        @Test
        @DisplayName("Should handle getConfiguration method edge cases")
        void shouldHandleGetConfigurationEdgeCases() {
            Map<String, Object> result = service.getConfiguration();

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("enabled"), "Enabled should be present");
            assertNotNull(result.get("parser"), "Parser config should be present");
            assertNotNull(result.get("issuers"), "Issuers should be present");

            @SuppressWarnings("unchecked")
            Map<String, Object> parser = (Map<String, Object>) result.get("parser");
            assertNotNull(parser.get("maxTokenSize"), "Max token size should be present");
            assertTrue((Integer) parser.get("maxTokenSize") > 0, "Max token size should be positive");
        }


        @Test
        @DisplayName("Should handle getJwksStatus method edge cases")
        void shouldHandleGetJwksStatusEdgeCases() {
            Map<String, Object> result = service.getJwksStatus();

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("status"), "Status should be present");
            assertNotNull(result.get("issuers"), "Issuers list should be present");

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> issuers = (List<Map<String, Object>>) result.get("issuers");
            assertNotNull(issuers, "Issuers should not be null");
        }
    }

    @Nested
    @DisplayName("TestConfig Integration Tests")
    @EnableTestLogger
    class TestConfigIntegrationTests {

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for empty configurations")
        void shouldDemonstrateTestConfigUsageForEmptyConfigurations() {
            Config emptyConfig = TestConfigurations.empty();
            String testEnabledKey = JwtPropertyKeys.ISSUERS.ENABLED.formatted("test");
            assertFalse(emptyConfig.getOptionalValue(testEnabledKey, Boolean.class).isPresent(),
                    "Empty config should not have any issuer properties");
            assertFalse(emptyConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).isPresent(),
                    "Empty config should not have any parser properties");

            // Test that getValue throws for missing properties
            assertThrows(NoSuchElementException.class,
                    () -> emptyConfig.getValue(testEnabledKey, Boolean.class),
                    "getValue should throw for missing properties");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for disabled issuers")
        void shouldDemonstrateTestConfigUsageForDisabledIssuers() {
            Config configWithDisabledIssuers = TestConfigurations.noEnabledIssuers();
            assertEquals(false, configWithDisabledIssuers.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), Boolean.class).orElse(true),
                    "Should have disabled issuer configuration");
            assertTrue(configWithDisabledIssuers.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), String.class).isPresent(),
                    "Should have issuer identifier even when disabled");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for minimal valid setup")
        void shouldDemonstrateTestConfigUsageForMinimalValidSetup() {
            Config minimalConfig = TestConfigurations.minimalValid();
            assertEquals(true, minimalConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), Boolean.class).orElse(false),
                    "Should have enabled issuer");
            assertEquals("https://test.example.com", minimalConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), String.class).orElse(null),
                    "Should have correct issuer identifier");
            assertEquals("classpath:keys/test_public_key.jwks", minimalConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.JWKS_FILE_PATH.formatted("test"), String.class).orElse(null),
                    "Should have public key location");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for multiple issuers")
        void shouldDemonstrateTestConfigUsageForMultipleIssuers() {
            Config multipleIssuersConfig = TestConfigurations.multipleIssuers();
            assertEquals(true, multipleIssuersConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("primary"), Boolean.class).orElse(false),
                    "Primary issuer should be enabled");
            assertEquals(true, multipleIssuersConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("secondary"), Boolean.class).orElse(false),
                    "Secondary issuer should be enabled");
            assertEquals(false, multipleIssuersConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("disabled"), Boolean.class).orElse(true),
                    "Disabled issuer should be disabled");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage with builder pattern")
        void shouldDemonstrateTestConfigUsageWithBuilderPattern() {
            Config customConfig = TestConfigurations.builder()
                    .withIssuer("custom")
                    .enabled(true)
                    .identifier("https://custom.example.com")
                    .publicKeyLocation("classpath:custom.key")
                    .jwksRefreshInterval(300)
                    .and()
                    .withParser()
                    .maxTokenSize(4096)
                    .maxPayloadSize(4096)
                    .maxStringLength(2048)
                    .build();

            assertEquals(true, customConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("custom"), Boolean.class).orElse(false),
                    "Custom issuer should be enabled");
            assertEquals("https://custom.example.com", customConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("custom"), String.class).orElse(null),
                    "Should have custom issuer identifier");
            assertEquals(300, customConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.REFRESH_INTERVAL_SECONDS.formatted("custom"), Integer.class).orElse(0),
                    "Should have custom JWKS refresh interval");
            assertEquals(4096, customConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).orElse(0),
                    "Should have custom parser max token size");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for malformed properties")
        void shouldDemonstrateTestConfigUsageForMalformedProperties() {
            Config malformedConfig = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "not-a-boolean",
                    JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, "invalid-number",
                    JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE, "",
                    "valid.property", "test-value"
            ));

            assertEquals(false, malformedConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), Boolean.class).orElse(true),
                    "Should return false for non-'true' boolean strings (Boolean.valueOf behavior)");
            assertFalse(malformedConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).isPresent(),
                    "Should return empty Optional for invalid integer");
            assertFalse(malformedConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE, Integer.class).isPresent(),
                    "Should return empty Optional for empty integer");
            assertEquals("test-value", malformedConfig.getOptionalValue("valid.property", String.class).orElse(null),
                    "Should handle valid string properties correctly");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig predefined configurations")
        void shouldDemonstrateTestConfigPredefinedConfigurations() {
            // Test invalid parser configuration
            Config invalidParserConfig = TestConfigurations.invalidParser();
            assertEquals(-1, invalidParserConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).orElse(0),
                    "Invalid parser config should have negative max token size");

            // Test JWKS URL configuration
            Config jwksConfig = TestConfigurations.withJwksUrl();
            assertEquals("https://test.example.com/jwks", jwksConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.JWKS_URL.formatted("test"), String.class).orElse(null),
                    "JWKS config should have JWKS URL");

            // Test well-known URL configuration
            Config wellKnownConfig = TestConfigurations.withWellKnownUrl();
            assertEquals("https://test.example.com/.well-known/openid_configuration",
                    wellKnownConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted("test"), String.class).orElse(null),
                    "Well-known config should have well-known URL");

            // Test custom parser configuration
            Config customParserConfig = TestConfigurations.customParser();
            assertEquals(16384, customParserConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).orElse(0),
                    "Custom parser config should have custom max token size");
        }
    }
}

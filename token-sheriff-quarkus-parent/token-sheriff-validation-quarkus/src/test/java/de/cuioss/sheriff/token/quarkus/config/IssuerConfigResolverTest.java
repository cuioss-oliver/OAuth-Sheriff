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
package de.cuioss.sheriff.token.quarkus.config;

import de.cuioss.http.client.adapter.RetryConfig;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.dpop.DpopConfig;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;
import java.util.Map;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;
import static de.cuioss.test.juli.LogAsserts.assertLogMessagePresent;
import static de.cuioss.test.juli.LogAsserts.assertLogMessagePresentContaining;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests IssuerConfigResolver functionality.
 */
@DisplayName("IssuerConfigResolver")
@EnableTestLogger
class IssuerConfigResolverTest {

    private static final String TEST_ISSUER = "test";
    private static final String ANOTHER_ISSUER = "another";

    @Nested
    @DisplayName("Constructor Validation")
    class ConstructorValidation {

        @Test
        @DisplayName("should accept valid config")
        void shouldAcceptValidConfig() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks"
            ));

            assertDoesNotThrow(() -> new IssuerConfigResolver(config, RetryConfig.defaults(), null, null),
                    "Should accept valid config");
        }

        @Test
        @DisplayName("should accept empty config but fail on resolution")
        void shouldAcceptEmptyConfig() {
            TestConfig emptyConfig = new TestConfig(Map.of());

            IssuerConfigResolver resolver = new IssuerConfigResolver(emptyConfig, RetryConfig.defaults(), null, null);

            // Note: The resolver will throw when trying to resolve configs, but construction should succeed
            assertThrows(IllegalStateException.class, resolver::resolveIssuerConfigs,
                    "Should throw when trying to resolve with empty config");
        }

        @Test
        @DisplayName("should accept ParserConfig in 4-arg constructor")
        void shouldAcceptParserConfig() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            ParserConfig parserConfig = ParserConfig.builder().build();

            // Should construct successfully with ParserConfig
            IssuerConfigResolver resolver = new IssuerConfigResolver(
                    config, RetryConfig.defaults(), null, parserConfig);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();
            assertEquals(1, result.size(), "Should find one issuer");
            assertNotNull(result.getFirst().getJwksLoader(),
                    "Should have JWKS loader configured with ParserConfig");
        }
    }

    @Nested
    @DisplayName("Issuer Discovery")
    class IssuerDiscovery {

        @Test
        @DisplayName("should throw when no issuers configured")
        void shouldThrowWhenNoIssuersConfigured() {
            TestConfig config = new TestConfig(Map.of());
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            IllegalStateException exception = assertThrows(IllegalStateException.class,
                    resolver::resolveIssuerConfigs,
                    "Should throw when no issuers found");
            assertEquals("No issuer configurations found in properties", exception.getMessage());
        }

        @Test
        @DisplayName("should throw when no issuers enabled")
        void shouldThrowWhenNoIssuersEnabled() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "false"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            IllegalStateException exception = assertThrows(IllegalStateException.class,
                    resolver::resolveIssuerConfigs,
                    "Should throw when no enabled issuers found");
            assertEquals("No enabled issuer configurations found", exception.getMessage());
        }

        @Test
        @DisplayName("should discover issuer from properties")
        void shouldDiscoverIssuerFromProperties() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size(), "Should find one issuer");
            assertTrue(result.getFirst().isEnabled(), "Should be enabled");
        }

        @Test
        @DisplayName("should discover multiple issuers")
        void shouldDiscoverMultipleIssuers() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(ANOTHER_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(ANOTHER_ISSUER), "https://other.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(ANOTHER_ISSUER), "https://other.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(ANOTHER_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(2, result.size(), "Should find two issuers");
            assertTrue(result.stream().allMatch(IssuerConfig::isEnabled), "All should be enabled");
        }
    }

    @Nested
    @DisplayName("hasEnabledIssuers Probe")
    class HasEnabledIssuersProbe {

        @Test
        @DisplayName("should report false when no issuer names are discovered")
        void shouldReportFalseWithoutIssuerNames() {
            assertFalse(IssuerConfigResolver.hasEnabledIssuers(new TestConfig(Map.of())),
                    "An empty namespace must not report enabled issuers");
        }

        @Test
        @DisplayName("should report false when every discovered issuer is disabled")
        void shouldReportFalseWhenAllIssuersDisabled() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "false",
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(ANOTHER_ISSUER), "false"
            ));

            assertFalse(IssuerConfigResolver.hasEnabledIssuers(config),
                    "A namespace whose issuers are all disabled must not report enabled issuers");
        }

        @Test
        @DisplayName("should report false when the enabled flag is absent (default is disabled)")
        void shouldReportFalseWhenEnabledFlagAbsent() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com"
            ));

            assertFalse(IssuerConfigResolver.hasEnabledIssuers(config),
                    "An issuer without an explicit enabled=true must not count as enabled");
        }

        @Test
        @DisplayName("should report true when at least one discovered issuer is enabled")
        void shouldReportTrueWithOneEnabledIssuer() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "false",
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(ANOTHER_ISSUER), "true"
            ));

            assertTrue(IssuerConfigResolver.hasEnabledIssuers(config),
                    "A single enabled issuer must be enough to report enabled issuers");
        }

        @Test
        @DisplayName("should not build any issuer configuration while probing")
        void shouldNotBuildIssuerConfigsWhileProbing() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "http://localhost:8080/realms/test",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "http://localhost:8080/jwks"
            ));

            // resolveIssuerConfigs would reject the cleartext http JWKS URL; the probe must not care
            assertTrue(assertDoesNotThrow(() -> IssuerConfigResolver.hasEnabledIssuers(config),
                    "The probe must not run builder validation"),
                    "The enabled issuer must still be detected");
        }
    }

    @Nested
    @DisplayName("Enabled Property Handling")
    @EnableTestLogger(debug = IssuerConfigResolver.class)
    class EnabledProperty {

        @Test
        @DisplayName("should skip disabled issuers")
        void shouldSkipDisabledIssuers() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(ANOTHER_ISSUER), "false",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(ANOTHER_ISSUER), "https://other.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(ANOTHER_ISSUER), "https://other.com/jwks"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size(), "Should find only enabled issuer");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Skipping disabled issuer: " + ANOTHER_ISSUER);
        }

        @ParameterizedTest
        @DisplayName("should respect enabled property value")
        @CsvSource({
                "true, true",
                "false, false"
        })
        void shouldRespectEnabledProperty(String enabledValue, boolean expectedEnabled) {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), enabledValue,
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            if (expectedEnabled) {
                List<IssuerConfig> result = resolver.resolveIssuerConfigs();
                assertEquals(1, result.size());
                assertEquals(expectedEnabled, result.getFirst().isEnabled());
            } else {
                assertThrows(IllegalStateException.class, resolver::resolveIssuerConfigs);
            }
        }

        @Test
        @DisplayName("should default to disabled when enabled not specified")
        void shouldDefaultToDisabledWhenNotSpecified() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            // Default is now disabled — require explicit enabled=true
            assertThrows(IllegalStateException.class, resolver::resolveIssuerConfigs,
                    "Should throw when no enabled issuers found (default is disabled)");
        }
    }

    @Nested
    @DisplayName("JWKS Source Configuration")
    class JwksSourceConfiguration {

        @Test
        @DisplayName("should configure HTTP JWKS URL with timeouts")
        void shouldConfigureHttpJwksUrl() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.CONNECT_TIMEOUT_SECONDS.formatted(TEST_ISSUER), "30",
                    JwtPropertyKeys.ISSUERS.READ_TIMEOUT_SECONDS.formatted(TEST_ISSUER), "60",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertNotNull(issuer.getJwksLoader(), "Should have JWKS loader");
        }

        @Test
        @DisplayName("should configure well-known URL with refresh interval")
        void shouldConfigureWellKnownUrl() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted(TEST_ISSUER), "https://example.com/.well-known/openid_configuration",
                    JwtPropertyKeys.ISSUERS.REFRESH_INTERVAL_SECONDS.formatted(TEST_ISSUER), "3600",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertNotNull(issuer.getJwksLoader(), "Should have JWKS loader");
        }

        @Test
        @DisplayName("should reject mutually exclusive JWKS sources")
        void shouldRejectMutuallyExclusiveJwksSources() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted(TEST_ISSUER), "https://example.com/.well-known/openid_configuration",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    resolver::resolveIssuerConfigs,
                    "Should reject mutually exclusive JWKS sources");

            assertTrue(exception.getMessage().contains("mutually exclusive"),
                    "Exception should indicate mutual exclusivity violation");
        }

    }

    @Nested
    @DisplayName("Property Configuration")
    class PropertyConfiguration {

        @Test
        @DisplayName("should configure issuer identifier")
        void shouldConfigureIssuerIdentifier() {
            String issuerIdentifier = "https://example.com";
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), issuerIdentifier,
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            assertNotNull(result.getFirst().getJwksLoader(), "Should have JWKS loader");
        }

        @Test
        @DisplayName("should configure expected audiences from comma-separated list")
        void shouldConfigureAudiences() {
            String audiences = "client1,client2,client3";
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.EXPECTED_AUDIENCE.formatted(TEST_ISSUER), audiences,
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertEquals(3, issuer.getExpectedAudience().size(), "Should have three audiences");
            assertTrue(issuer.getExpectedAudience().contains("client1"), "Should contain client1");
            assertTrue(issuer.getExpectedAudience().contains("client2"), "Should contain client2");
            assertTrue(issuer.getExpectedAudience().contains("client3"), "Should contain client3");
        }

        @Test
        @DisplayName("should ignore empty segments in comma-separated lists")
        void shouldIgnoreEmptyCsvSegments() {
            String audiences = "client1,, client2 ,";
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.EXPECTED_AUDIENCE.formatted(TEST_ISSUER), audiences,
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertEquals(2, issuer.getExpectedAudience().size(),
                    "Empty segments must be filtered out");
            assertTrue(issuer.getExpectedAudience().contains("client1"), "Should contain client1");
            assertTrue(issuer.getExpectedAudience().contains("client2"), "Should contain trimmed client2");
        }

        @Test
        @DisplayName("should configure expected client IDs from comma-separated list")
        void shouldConfigureClientIds() {
            String clientIds = "id1, id2 , id3";
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.EXPECTED_CLIENT_ID.formatted(TEST_ISSUER), clientIds,
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertEquals(3, issuer.getExpectedClientId().size(), "Should have three client IDs");
            assertTrue(issuer.getExpectedClientId().contains("id1"), "Should contain id1");
            assertTrue(issuer.getExpectedClientId().contains("id2"), "Should contain id2");
            assertTrue(issuer.getExpectedClientId().contains("id3"), "Should contain id3");
        }

        @Test
        @DisplayName("should configure algorithm preferences from comma-separated list")
        void shouldConfigureAlgorithmPreferences() {
            String algorithms = "RS256,ES256,PS256";
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.ALGORITHM_PREFERENCES.formatted(TEST_ISSUER), algorithms,
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertNotNull(issuer.getAlgorithmPreferences(), "Should have algorithm preferences");
            SignatureAlgorithmPreferences preferences = issuer.getAlgorithmPreferences();
            List<String> preferredAlgorithms = preferences.getPreferredAlgorithms();
            assertEquals(3, preferredAlgorithms.size(), "Should have three algorithms");
            assertEquals("RS256", preferredAlgorithms.getFirst(), "First should be RS256");
            assertEquals("ES256", preferredAlgorithms.get(1), "Second should be ES256");
            assertEquals("PS256", preferredAlgorithms.get(2), "Third should be PS256");
        }

        @ParameterizedTest
        @DisplayName("should configure claimSubOptional flag")
        @CsvSource({
                "true, true",
                "false, false"
        })
        void shouldConfigureClaimSubOptional(String claimSubOptionalValue, boolean expectedClaimSubOptional) {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.CLAIM_SUB_OPTIONAL.formatted(TEST_ISSUER), claimSubOptionalValue,
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertEquals(expectedClaimSubOptional, issuer.isClaimSubOptional(),
                    "Should configure claimSubOptional to " + expectedClaimSubOptional);
        }

        @Test
        @DisplayName("should default claimSubOptional to false when not specified")
        void shouldDefaultClaimSubOptionalToFalse() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertFalse(issuer.isClaimSubOptional(), "Should default claimSubOptional to false");
        }

        @Test
        @DisplayName("should configure clock skew seconds from property")
        void shouldConfigureClockSkewSeconds() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.CLOCK_SKEW_SECONDS.formatted(TEST_ISSUER), "120",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertEquals(120, issuer.getClockSkewSeconds(),
                    "Should configure clockSkewSeconds to 120");
        }

        @Test
        @DisplayName("should default clock skew seconds to 60 when not specified")
        void shouldDefaultClockSkewSecondsTo60() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertEquals(60, issuer.getClockSkewSeconds(),
                    "Should default clockSkewSeconds to 60");
        }

        @Test
        @DisplayName("should configure max token age seconds from property")
        void shouldConfigureMaxTokenAgeSeconds() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.MAX_TOKEN_AGE_SECONDS.formatted(TEST_ISSUER), "300",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertEquals(300, issuer.getMaxTokenAgeSeconds(),
                    "Should configure maxTokenAgeSeconds to 300");
        }

        @Test
        @DisplayName("should default max token age seconds to null when not specified")
        void shouldDefaultMaxTokenAgeSecondsToNull() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            IssuerConfig issuer = result.getFirst();
            assertNull(issuer.getMaxTokenAgeSeconds(),
                    "Should default maxTokenAgeSeconds to null");
        }
    }

    @Nested
    @DisplayName("DPoP Configuration (RFC 9449)")
    class DpopConfiguration {

        @Test
        @DisplayName("should configure DPoP when enabled with defaults")
        void shouldConfigureDpopWhenEnabled() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.DPOP_ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            DpopConfig dpopConfig = result.getFirst().getDpopConfig();
            assertNotNull(dpopConfig, "DPoP config should be present when enabled");
            assertFalse(dpopConfig.isRequired(), "Should default to not required");
            assertEquals(DpopConfig.DEFAULT_PROOF_MAX_AGE_SECONDS, dpopConfig.getProofMaxAgeSeconds());
            assertEquals(DpopConfig.DEFAULT_NONCE_CACHE_SIZE, dpopConfig.getNonceCacheSize());
            assertEquals(DpopConfig.DEFAULT_NONCE_CACHE_TTL_SECONDS, dpopConfig.getNonceCacheTtlSeconds());
        }

        @Test
        @DisplayName("should not configure DPoP when disabled")
        void shouldNotConfigureDpopWhenDisabled() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.DPOP_ENABLED.formatted(TEST_ISSUER), "false",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            assertNull(result.getFirst().getDpopConfig(), "DPoP config should be null when disabled");
        }

        @Test
        @DisplayName("should not configure DPoP when not specified")
        void shouldNotConfigureDpopWhenNotSpecified() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            assertNull(result.getFirst().getDpopConfig(), "DPoP config should be null when not specified");
        }

        @Test
        @DisplayName("should configure DPoP with custom values")
        void shouldConfigureDpopWithCustomValues() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.DPOP_ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.DPOP_REQUIRED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.DPOP_PROOF_MAX_AGE_SECONDS.formatted(TEST_ISSUER), "120",
                    JwtPropertyKeys.ISSUERS.DPOP_NONCE_CACHE_SIZE.formatted(TEST_ISSUER), "5000",
                    JwtPropertyKeys.ISSUERS.DPOP_NONCE_CACHE_TTL_SECONDS.formatted(TEST_ISSUER), "600",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size());
            DpopConfig dpopConfig = result.getFirst().getDpopConfig();
            assertNotNull(dpopConfig, "DPoP config should be present");
            assertTrue(dpopConfig.isRequired(), "Should be required");
            assertEquals(120, dpopConfig.getProofMaxAgeSeconds());
            assertEquals(5000, dpopConfig.getNonceCacheSize());
            assertEquals(600, dpopConfig.getNonceCacheTtlSeconds());
        }

        @Test
        @DisplayName("should fail fast when dpop.required is set without dpop.enabled")
        void shouldFailWhenDpopRequiredWithoutEnabled() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.DPOP_REQUIRED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            IllegalStateException exception = assertThrows(IllegalStateException.class,
                    resolver::resolveIssuerConfigs,
                    "Should fail fast instead of silently disabling DPoP");
            assertTrue(exception.getMessage().contains(
                            JwtPropertyKeys.ISSUERS.DPOP_REQUIRED.formatted(TEST_ISSUER)),
                    "Exception should name the offending property: " + exception.getMessage());
            assertTrue(exception.getMessage().contains(
                            JwtPropertyKeys.ISSUERS.DPOP_ENABLED.formatted(TEST_ISSUER)),
                    "Exception should instruct to set dpop.enabled=true: " + exception.getMessage());
        }

        @Test
        @DisplayName("should fail fast when a dpop sub-property is set with dpop.enabled=false")
        void shouldFailWhenDpopSubPropertyWithEnabledFalse() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.DPOP_ENABLED.formatted(TEST_ISSUER), "false",
                    JwtPropertyKeys.ISSUERS.DPOP_PROOF_MAX_AGE_SECONDS.formatted(TEST_ISSUER), "120",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            IllegalStateException exception = assertThrows(IllegalStateException.class,
                    resolver::resolveIssuerConfigs,
                    "Should fail fast instead of silently disabling DPoP");
            assertTrue(exception.getMessage().contains(
                            JwtPropertyKeys.ISSUERS.DPOP_PROOF_MAX_AGE_SECONDS.formatted(TEST_ISSUER)),
                    "Exception should name the offending property: " + exception.getMessage());
        }
    }

    @Nested
    @DisplayName("Secure Transport Opt-Ins (H1/C1)")
    @EnableTestLogger(debug = IssuerConfigResolver.class)
    class SecureTransportOptIns {

        @Test
        @DisplayName("should reject cleartext http JWKS URL by default (H1 secure default)")
        void shouldRejectInsecureHttpByDefault() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "http://localhost:8080/realms/test",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "http://localhost:8080/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            assertThrows(IllegalArgumentException.class, resolver::resolveIssuerConfigs,
                    "Cleartext http JWKS URL must be rejected when allow-insecure-http is unset (default false)");
        }

        @Test
        @DisplayName("should accept cleartext http JWKS URL when allow-insecure-http=true")
        void shouldAllowInsecureHttpWhenOptedIn() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "http://localhost:8080/realms/test",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "http://localhost:8080/jwks",
                    JwtPropertyKeys.ISSUERS.ALLOW_INSECURE_HTTP.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ALLOW_LOOPBACK_EGRESS.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size(), "Should resolve one issuer");
            assertNotNull(result.getFirst().getJwksLoader(),
                    "Should have JWKS loader when cleartext http is opted in");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG,
                    "Enabled cleartext HTTP for " + TEST_ISSUER);
            assertLogMessagePresentContaining(TestLogLevel.DEBUG,
                    "Enabled loopback egress for " + TEST_ISSUER);
        }

        @Test
        @DisplayName("should reject cleartext http well-known URL by default (H1 secure default)")
        void shouldRejectInsecureWellKnownByDefault() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "http://localhost:8080/realms/test",
                    JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted(TEST_ISSUER),
                    "http://localhost:8080/realms/test/.well-known/openid-configuration",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            assertThrows(IllegalArgumentException.class, resolver::resolveIssuerConfigs,
                    "Cleartext http well-known URL must be rejected when allow-insecure-http is unset (default false)");
        }

        @Test
        @DisplayName("should accept cleartext http well-known URL when opted in")
        void shouldAllowInsecureWellKnownWhenOptedIn() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "http://localhost:8080/realms/test",
                    JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted(TEST_ISSUER),
                    "http://localhost:8080/realms/test/.well-known/openid-configuration",
                    JwtPropertyKeys.ISSUERS.ALLOW_INSECURE_HTTP.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ALLOW_LOOPBACK_EGRESS.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size(), "Should resolve one issuer");
            assertNotNull(result.getFirst().getJwksLoader(),
                    "Should have JWKS loader when cleartext http well-known is opted in");
        }

        @Test
        @DisplayName("should thread allowed-egress-hosts allow-list into the JWKS config")
        void shouldConfigureAllowedEgressHosts() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://keycloak:8443/realms/test",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER),
                    "https://keycloak:8443/realms/test/protocol/openid-connect/certs",
                    JwtPropertyKeys.ISSUERS.ALLOWED_EGRESS_HOSTS.formatted(TEST_ISSUER), "keycloak, dex",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            List<IssuerConfig> result = resolver.resolveIssuerConfigs();

            assertEquals(1, result.size(), "Should resolve one issuer");
            assertNotNull(result.getFirst().getJwksLoader(),
                    "Should have JWKS loader when egress hosts are allow-listed");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG,
                    "Allow-listed egress hosts for " + TEST_ISSUER);
        }
    }

    @Nested
    @DisplayName("Logging Validation")
    @EnableTestLogger(debug = IssuerConfigResolver.class)
    class LoggingValidation {

        @Test
        @DisplayName("should log discovery and resolution process")
        void shouldLogDiscoveryAndResolution() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            resolver.resolveIssuerConfigs();

            assertLogMessagePresent(TestLogLevel.INFO, INFO.RESOLVING_ISSUER_CONFIGURATIONS.format());
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Discovered issuer names:");
            assertLogMessagePresent(TestLogLevel.INFO, INFO.RESOLVED_ISSUER_CONFIGURATION.format(TEST_ISSUER));
            assertLogMessagePresent(TestLogLevel.INFO, INFO.RESOLVED_ENABLED_ISSUER_CONFIGURATIONS.format("1"));
        }

        @Test
        @DisplayName("should log JWKS source configuration")
        void shouldLogJwksSourceConfiguration() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            resolver.resolveIssuerConfigs();

            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Configured HTTP JWKS URL for " + TEST_ISSUER);
        }

        @Test
        @DisplayName("should log when skipping disabled issuers")
        void shouldLogDisabledIssuerSkipping() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(ANOTHER_ISSUER), "false",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(ANOTHER_ISSUER), "https://other.com",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(ANOTHER_ISSUER), "https://other.com/jwks"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            resolver.resolveIssuerConfigs();

            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Skipping disabled issuer: " + ANOTHER_ISSUER);
            assertLogMessagePresent(TestLogLevel.INFO, INFO.RESOLVED_ISSUER_CONFIGURATION.format(TEST_ISSUER));
        }

        @Test
        @DisplayName("should log claimSubOptional configuration")
        void shouldLogClaimSubOptionalConfiguration() {
            TestConfig config = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com",
                    JwtPropertyKeys.ISSUERS.CLAIM_SUB_OPTIONAL.formatted(TEST_ISSUER), "true",
                    JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(TEST_ISSUER), "https://example.com/jwks",
                    JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(TEST_ISSUER), "true"
            ));
            IssuerConfigResolver resolver = new IssuerConfigResolver(config, RetryConfig.defaults(), null, null);

            resolver.resolveIssuerConfigs();

            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Set claim subject optional for " + TEST_ISSUER + ": true");
        }
    }
}

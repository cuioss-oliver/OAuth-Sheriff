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
package de.cuioss.sheriff.token.quarkus.producer;

import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link TokenValidatorProducer} focusing on producer-level functionality.
 * Configuration validation is covered in the config package tests.
 */
@EnableTestLogger
class TokenValidatorProducerUnitTest {

    @Test
    @DisplayName("Should successfully initialize TokenValidator with valid configuration")
    void shouldSuccessfullyInitializeTokenValidator() {
        Map<String, String> props = Map.of(
                JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, "4096",
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), "https://test.example.com",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("test"), "true",
                JwtPropertyKeys.ISSUERS.JWKS_CONTENT.formatted("test"), "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"test-key\",\"alg\":\"RS256\",\"n\":\"nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e3zvAIhySnxIZi9aDaPvSlAeZ7VVl5ivy_43QvTRpM3eBFs9A1Y9a9aCtHSP8KXRTYhH2TvPxLOOFg0Lu-pwrps6CqvbeZjQlqCh9cGowQ\",\"e\":\"AQAB\"}]}"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig, null, null);

        producer.init();

        assertNotNull(producer.tokenValidator, "Should create TokenValidator");
        assertNotNull(producer.issuerConfigs, "Should create issuer configs");
        assertFalse(producer.issuerConfigs.isEmpty(), "Should have at least one issuer config");
        LogAsserts.assertLogMessagePresent(TestLogLevel.INFO, INFO.INITIALIZING_JWT_VALIDATION_COMPONENTS.format());
        LogAsserts.assertLogMessagePresent(TestLogLevel.INFO, INFO.JWT_VALIDATION_COMPONENTS_INITIALIZED.format("1"));
    }

    @Test
    @DisplayName("Should fail when no enabled issuers found")
    void shouldFailWhenNoEnabledIssuersFound() {
        Map<String, String> props = Map.of(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "false",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), "https://test.example.com",
                JwtPropertyKeys.ISSUERS.JWKS_CONTENT.formatted("test"), "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"test-key\",\"alg\":\"RS256\",\"n\":\"nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e3zvAIhySnxIZi9aDaPvSlAeZ7VVl5ivy_43QvTRpM3eBFs9A1Y9a9aCtHSP8KXRTYhH2TvPxLOOFg0Lu-pwrps6CqvbeZjQlqCh9cGowQ\",\"e\":\"AQAB\"}]}"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig, null, null);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                producer::init);
        assertEquals("No enabled issuer configurations found", exception.getMessage());
    }
}
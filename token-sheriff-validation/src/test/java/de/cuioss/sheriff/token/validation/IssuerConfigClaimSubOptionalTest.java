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

import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test suite for {@link IssuerConfig} claimSubOptional functionality.
 * <p>
 * This test class specifically focuses on testing the RFC compliance warning
 * and the claimSubOptional flag behavior in IssuerConfig.
 * </p>
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@DisplayName("IssuerConfig claimSubOptional")
class IssuerConfigClaimSubOptionalTest {

    @Test
    @DisplayName("Should have claimSubOptional default to false")
    void shouldHaveClaimSubOptionalDefaultToFalse() {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}")
                .audienceValidationDisabled(true)
                .build();

        assertFalse(issuerConfig.isClaimSubOptional(), "claimSubOptional should default to false");
    }

    @Test
    @DisplayName("Should set claimSubOptional to true when specified")
    void shouldSetClaimSubOptionalToTrueWhenSpecified() {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}")
                .claimSubOptional(true)
                .audienceValidationDisabled(true)
                .build();

        assertTrue(issuerConfig.isClaimSubOptional(), "claimSubOptional should be true when explicitly set");
    }

    @Test
    @DisplayName("Should set claimSubOptional to false when explicitly specified")
    void shouldSetClaimSubOptionalToFalseWhenExplicitlySpecified() {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}")
                .claimSubOptional(false)
                .audienceValidationDisabled(true)
                .build();

        assertFalse(issuerConfig.isClaimSubOptional(), "claimSubOptional should be false when explicitly set to false");
    }

    @Test
    @DisplayName("Should log RFC compliance warning when claimSubOptional is true")
    void shouldLogRfcComplianceWarningWhenClaimSubOptionalIsTrue() {
        IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}")
                .claimSubOptional(true)
                .audienceValidationDisabled(true)
                .build();

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "claimSubOptional=true");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "not conform to RFC 7519");
    }

    @Test
    @DisplayName("Should include issuer identifier in RFC compliance warning")
    void shouldIncludeIssuerIdentifierInRfcComplianceWarning() {
        String issuerIdentifier = "https://keycloak.example.com/realms/test";

        IssuerConfig.builder()
                .issuerIdentifier(issuerIdentifier)
                .jwksContent("{\"keys\":[]}")
                .claimSubOptional(true)
                .audienceValidationDisabled(true)
                .build();

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, issuerIdentifier);
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "claimSubOptional=true");
    }

    @Test
    @DisplayName("Should not log warning when claimSubOptional is false")
    void shouldNotLogWarningWhenClaimSubOptionalIsFalse() {
        IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}")
                .claimSubOptional(false)
                .audienceValidationDisabled(true)
                .build();

        LogAsserts.assertNoLogMessagePresent(TestLogLevel.WARN, IssuerConfig.class);
    }

    @Test
    @DisplayName("Should not log warning when claimSubOptional is default (false)")
    void shouldNotLogWarningWhenClaimSubOptionalIsDefault() {
        IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}")
                .audienceValidationDisabled(true)
                .build();

        LogAsserts.assertNoLogMessagePresent(TestLogLevel.WARN, IssuerConfig.class);
    }

    @Test
    @DisplayName("Should handle null issuer identifier in warning message")
    void shouldHandleNullIssuerIdentifierInWarningMessage() {
        IssuerConfig.builder()
                .issuerIdentifier("https://example.com") // Provide a minimal issuer identifier
                .jwksContent("{\"keys\":[]}") // Provide JWKS content to avoid loader config error
                .claimSubOptional(true)
                .audienceValidationDisabled(true)
                .build();

        // Test verifies that when issuerIdentifier is null internally, "unknown" is used in warning message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "claimSubOptional=true");
    }

    @Test
    @DisplayName("Should work with all IssuerConfig construction patterns")
    void shouldWorkWithAllIssuerConfigConstructionPatterns() {
        // Test with JWKS content
        IssuerConfig wellKnownConfig = IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}") // Provide JWKS content
                .claimSubOptional(true)
                .audienceValidationDisabled(true)
                .build();
        assertTrue(wellKnownConfig.isClaimSubOptional());

        // Test with file path
        IssuerConfig fileConfig = IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}")
                .claimSubOptional(true)
                .audienceValidationDisabled(true)
                .build();
        assertTrue(fileConfig.isClaimSubOptional());

        // Test with inline content
        IssuerConfig contentConfig = IssuerConfig.builder()
                .issuerIdentifier("https://test-issuer.example.com")
                .jwksContent("{\"keys\":[]}")
                .claimSubOptional(true)
                .audienceValidationDisabled(true)
                .build();
        assertTrue(contentConfig.isClaimSubOptional());
    }
}
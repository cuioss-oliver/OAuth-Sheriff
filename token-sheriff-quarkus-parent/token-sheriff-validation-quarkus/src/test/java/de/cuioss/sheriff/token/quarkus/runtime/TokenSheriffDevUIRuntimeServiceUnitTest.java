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

import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.quarkus.observability.ObservedValidatorResolver;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.dpop.DpopConfig;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Plain unit tests for {@link TokenSheriffDevUIRuntimeService}, independent of the
 * Quarkus container. The sibling {@code @QuarkusTest} exercises the service through
 * CDI, but its coverage is not visible to the surefire JaCoCo report — these tests
 * make the service's behavior measurable there as well.
 */
@DisplayName("TokenSheriffDevUIRuntimeService plain unit tests")
class TokenSheriffDevUIRuntimeServiceUnitTest {

    private static final String DISABLED_ISSUER = "https://disabled-issuer.example.com";
    private static final String UNAVAILABLE_EXTERNAL_VALIDATOR = "unavailable (external validator)";
    private static final String UNAVAILABLE_NOT_CONFIGURED = "unavailable (not configured)";

    private TestTokenHolder tokenHolder;
    private IssuerConfig issuerConfig;
    private IssuerConfig disabledIssuerConfig;
    private TokenValidator tokenValidator;
    private TokenSheriffDevUIRuntimeService service;

    @BeforeEach
    void setUp() {
        tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN,
                ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));
        issuerConfig = tokenHolder.getIssuerConfig();
        // A disabled issuer has no JwksLoader and no audience — the DevUI views must
        // render it without failing; carries a DpopConfig so both dpopEnabled arms show up
        disabledIssuerConfig = IssuerConfig.builder()
                .enabled(false)
                .issuerIdentifier(DISABLED_ISSUER)
                .dpopConfig(DpopConfig.builder().build())
                .build();
        tokenValidator = TokenValidator.builder()
                .parserConfig(ParserConfig.builder().build())
                .issuerConfig(issuerConfig)
                .build();
        service = new TokenSheriffDevUIRuntimeService(new ObservedValidatorResolver(
                ObservedValidatorResolver.Outcome.PROPERTY_CONFIGURED, tokenValidator,
                List.of(issuerConfig, disabledIssuerConfig), ParserConfig.builder().build()));
    }

    @Test
    @DisplayName("getValidationStatus reports ACTIVE with validator present")
    void validationStatusWithValidator() {
        Map<String, Object> status = service.getValidationStatus();

        assertEquals(true, status.get("enabled"));
        assertEquals(true, status.get("validatorPresent"));
        assertEquals("ACTIVE", status.get("status"));
        assertEquals("JWT validation is active and ready", status.get("statusMessage"));
    }

    @Test
    @DisplayName("getValidationStatus reports missing validator")
    void validationStatusWithoutValidator() {
        Map<String, Object> status = unconfiguredService().getValidationStatus();

        assertEquals(true, status.get("enabled"));
        assertEquals(false, status.get("validatorPresent"));
        assertEquals("NOT_CONFIGURED", status.get("status"));
    }

    @Test
    @DisplayName("getJwksStatus lists enabled and disabled issuers with loader details")
    void jwksStatusListsIssuers() {
        Map<String, Object> jwksStatus = service.getJwksStatus();

        assertEquals("CONFIGURED", jwksStatus.get("status"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> issuers = (List<Map<String, Object>>) jwksStatus.get("issuers");
        assertEquals(2, issuers.size());

        Map<String, Object> enabledIssuer = issuers.getFirst();
        assertEquals(issuerConfig.getIssuerIdentifier(), enabledIssuer.get("name"));
        assertEquals(issuerConfig.getIssuerIdentifier(), enabledIssuer.get("issuerUri"));
        assertEquals("configured", enabledIssuer.get("jwksUri"));
        assertEquals(issuerConfig.getLoaderStatus().toString(), enabledIssuer.get("loaderStatus"));

        Map<String, Object> disabledIssuer = issuers.get(1);
        assertEquals(DISABLED_ISSUER, disabledIssuer.get("name"));
        assertEquals("not configured", disabledIssuer.get("jwksUri"));
        assertEquals(LoaderStatus.UNDEFINED.toString(), disabledIssuer.get("loaderStatus"));
    }

    @Test
    @DisplayName("getConfiguration exposes parser values and per-issuer details")
    void configurationExposesParserAndIssuers() {
        ParserConfig parserConfig = ParserConfig.builder().build();
        Map<String, Object> configuration = service.getConfiguration();

        assertEquals(true, configuration.get("enabled"));
        assertEquals("INFO", configuration.get("logLevel"));

        @SuppressWarnings("unchecked")
        Map<String, Object> parser = (Map<String, Object>) configuration.get("parser");
        assertEquals(parserConfig.getMaxTokenSize(), parser.get("maxTokenSize"));
        assertEquals(parserConfig.getMaxPayloadSize(), parser.get("maxPayloadSize"));
        assertEquals(parserConfig.getMaxStringLength(), parser.get("maxStringLength"));
        assertEquals(issuerConfig.getClockSkewSeconds(), parser.get("clockSkewSeconds"));

        @SuppressWarnings("unchecked")
        Map<String, Object> httpJwksLoader = (Map<String, Object>) configuration.get("httpJwksLoader");
        assertEquals(parserConfig.getMaxTokenSize(), httpJwksLoader.get("sizeLimit"));

        @SuppressWarnings("unchecked")
        Map<String, Object> issuers = (Map<String, Object>) configuration.get("issuers");
        assertEquals(2, issuers.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> enabledDetail = (Map<String, Object>) issuers.get(issuerConfig.getIssuerIdentifier());
        assertNotNull(enabledDetail, "enabled issuer detail should be keyed by identifier");
        assertEquals(issuerConfig.getIssuerIdentifier(), enabledDetail.get("issuerUri"));
        assertEquals("configured", enabledDetail.get("jwksUri"));
        assertEquals(String.join(", ", issuerConfig.getExpectedAudience()), enabledDetail.get("audience"));
        assertEquals(issuerConfig.getClockSkewSeconds(), enabledDetail.get("clockSkewSeconds"));
        assertEquals(issuerConfig.isClaimSubOptional(), enabledDetail.get("claimSubOptional"));
        assertEquals(false, enabledDetail.get("dpopEnabled"));

        @SuppressWarnings("unchecked")
        Map<String, Object> disabledDetail = (Map<String, Object>) issuers.get(DISABLED_ISSUER);
        assertNotNull(disabledDetail, "disabled issuer detail should be keyed by identifier");
        assertNull(disabledDetail.get("jwksUri"), "disabled issuer has no JWKS source");
        assertNull(disabledDetail.get("audience"), "disabled issuer has no audience");
        assertEquals(true, disabledDetail.get("dpopEnabled"));
    }

    @Test
    @DisplayName("validateToken accepts a valid access token and exposes its claims")
    void validateTokenAcceptsValidToken() {
        Map<String, Object> result = service.validateToken(tokenHolder.getRawToken());

        assertEquals(true, result.get("valid"), "signed token from matching issuer must validate");
        assertEquals("ACCESS_TOKEN", result.get("tokenType"));
        assertEquals(tokenHolder.getIssuer(), result.get("issuer"));

        @SuppressWarnings("unchecked")
        Map<String, String> claims = (Map<String, String>) result.get("claims");
        assertNotNull(claims, "valid token must expose its claims");
        assertFalse(claims.isEmpty(), "claims must not be empty");
        assertEquals(tokenHolder.getIssuer(), claims.get("iss"), "issuer claim must match");
    }

    @Test
    @DisplayName("validateToken rejects null, blank and malformed tokens")
    void validateTokenRejectsInvalidInput() {
        Map<String, Object> nullResult = service.validateToken(null);
        assertEquals(false, nullResult.get("valid"));
        assertEquals("Token is empty or null", nullResult.get("error"));

        Map<String, Object> blankResult = service.validateToken("   \t ");
        assertEquals(false, blankResult.get("valid"));
        assertEquals("Token is empty or null", blankResult.get("error"));

        Map<String, Object> malformedResult = service.validateToken("not-a-jwt");
        assertEquals(false, malformedResult.get("valid"));
        assertNotNull(malformedResult.get("error"), "malformed token must produce an error message");
        assertNull(malformedResult.get("tokenType"), "invalid token must not expose a token type");
        assertNull(malformedResult.get("claims"), "invalid token must not expose claims");
    }

    @Test
    @DisplayName("getHealthInfo reports UP with valid configuration")
    void healthInfoReportsUp() {
        Map<String, Object> health = service.getHealthInfo();

        assertEquals(true, health.get("configurationValid"));
        assertEquals("UP", health.get("healthStatus"));
        assertEquals("All JWT components are healthy and operational (PROPERTY_CONFIGURED)",
                health.get("message"));
    }

    @Test
    @DisplayName("EXTERNAL_VALIDATOR marks both parserConfig-derived surfaces as unavailable")
    void externalValidatorMarksParserSurfacesUnavailable() {
        Map<String, Object> configuration = externalValidatorService().getConfiguration();

        @SuppressWarnings("unchecked")
        Map<String, Object> parser = (Map<String, Object>) configuration.get("parser");
        @SuppressWarnings("unchecked")
        Map<String, Object> httpJwksLoader = (Map<String, Object>) configuration.get("httpJwksLoader");
        @SuppressWarnings("unchecked")
        Map<String, Object> issuers = (Map<String, Object>) configuration.get("issuers");

        assertAll("external validator configuration",
                () -> assertEquals(UNAVAILABLE_EXTERNAL_VALIDATOR, parser.get("status"),
                        "The parser section must carry the external-validator unavailability marker"),
                () -> assertFalse(parser.containsKey("maxTokenSize"),
                        "No parser field may be emitted without a parser configuration"),
                () -> assertEquals(UNAVAILABLE_EXTERNAL_VALIDATOR, httpJwksLoader.get("sizeLimit"),
                        "sizeLimit is the symmetric peer of the parser fields and carries the same marker"),
                () -> assertTrue(issuers.isEmpty(), "A foreign validator exposes no issuer configurations"));
    }

    @Test
    @DisplayName("EXTERNAL_VALIDATOR reports the external view state without throwing")
    void externalValidatorReportsViewState() {
        TokenSheriffDevUIRuntimeService externalService = externalValidatorService();

        Map<String, Object> validationStatus = externalService.getValidationStatus();
        Map<String, Object> jwksStatus = externalService.getJwksStatus();
        Map<String, Object> health = externalService.getHealthInfo();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> issuers = (List<Map<String, Object>>) jwksStatus.get("issuers");

        assertAll("external validator view state",
                () -> assertEquals("ACTIVE", validationStatus.get("status"),
                        "A foreign validator is still an active validator"),
                () -> assertEquals(true, validationStatus.get("validatorPresent"),
                        "The foreign validator must be reported as present"),
                () -> assertEquals("EXTERNAL_VALIDATOR", jwksStatus.get("status"),
                        "JWKS status must name the external-validator outcome"),
                () -> assertTrue(issuers.isEmpty(), "No issuer may be listed for a foreign validator"),
                () -> assertEquals(true, health.get("configurationValid"),
                        "An observable validator is a valid configuration"),
                () -> assertEquals("UP", health.get("healthStatus"), "Health must stay UP"));
    }

    @Test
    @DisplayName("NOT_CONFIGURED returns well-formed responses instead of throwing")
    void notConfiguredReturnsWellFormedResponses() {
        TokenSheriffDevUIRuntimeService unconfigured = unconfiguredService();

        Map<String, Object> configuration = assertDoesNotThrow(unconfigured::getConfiguration,
                "getConfiguration must not throw on an empty issuer list");
        Map<String, Object> jwksStatus = unconfigured.getJwksStatus();
        Map<String, Object> health = unconfigured.getHealthInfo();
        Map<String, Object> validation = unconfigured.validateToken("any-token");

        @SuppressWarnings("unchecked")
        Map<String, Object> parser = (Map<String, Object>) configuration.get("parser");

        assertAll("unconfigured view state",
                () -> assertEquals(UNAVAILABLE_NOT_CONFIGURED, parser.get("status"),
                        "The parser section must carry the not-configured unavailability marker"),
                () -> assertFalse(parser.containsKey("clockSkewSeconds"),
                        "The clock-skew read must be guarded against an empty issuer list"),
                () -> assertEquals("NOT_CONFIGURED", jwksStatus.get("status"),
                        "JWKS status must name the not-configured outcome"),
                () -> assertEquals(false, health.get("configurationValid"),
                        "Nothing observable is not a valid configuration"),
                () -> assertEquals("DOWN", health.get("healthStatus"),
                        "The DevUI service keeps its configurationValid => UP, else DOWN contract"),
                () -> assertEquals(false, validation.get("valid"), "No token can be validated"),
                () -> assertEquals("No validator configured", validation.get("error"),
                        "validateToken must report the missing validator rather than throwing"));
    }

    private TokenSheriffDevUIRuntimeService externalValidatorService() {
        return new TokenSheriffDevUIRuntimeService(new ObservedValidatorResolver(
                ObservedValidatorResolver.Outcome.EXTERNAL_VALIDATOR, tokenValidator, List.of(), null));
    }

    private static TokenSheriffDevUIRuntimeService unconfiguredService() {
        return new TokenSheriffDevUIRuntimeService(new ObservedValidatorResolver(
                ObservedValidatorResolver.Outcome.NOT_CONFIGURED, null, List.of(), null));
    }
}

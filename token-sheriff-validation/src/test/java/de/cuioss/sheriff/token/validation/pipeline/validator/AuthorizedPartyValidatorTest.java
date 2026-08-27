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
package de.cuioss.sheriff.token.validation.pipeline.validator;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link AuthorizedPartyValidator}.
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("AuthorizedPartyValidator")
class AuthorizedPartyValidatorTest {

    private static final String EXPECTED_CLIENT_ID_1 = "client1";
    private static final String EXPECTED_CLIENT_ID_2 = "client2";
    private static final String UNEXPECTED_CLIENT_ID = "unknown-client";
    private static final Set<String> EXPECTED_CLIENT_IDS = Set.of(EXPECTED_CLIENT_ID_1, EXPECTED_CLIENT_ID_2);


    private SecurityEventCounter securityEventCounter;
    private AuthorizedPartyValidator validator;

    @BeforeEach
    void setup() {
        securityEventCounter = new SecurityEventCounter();
        validator = new AuthorizedPartyValidator(EXPECTED_CLIENT_IDS, securityEventCounter, true);
    }

    @Test
    @DisplayName("Should skip validation when no expected client ID configured")
    void shouldSkipValidationWhenNoExpectedClientIdConfigured() {
        AuthorizedPartyValidator emptyValidator = new AuthorizedPartyValidator(Set.of(), securityEventCounter, true);
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        assertDoesNotThrow(() -> emptyValidator.validateAuthorizedParty(token));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.AZP_MISMATCH));
    }

    @Test
    @DisplayName("Should validate authorized party successfully when it matches expected client ID")
    void shouldValidateAuthorizedPartySuccessfullyWhenItMatchesExpectedClientId() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(EXPECTED_CLIENT_ID_1));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        assertDoesNotThrow(() -> validator.validateAuthorizedParty(token));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.AZP_MISMATCH));
    }

    @Test
    @DisplayName("Should validate authorized party successfully when it matches one of multiple expected client IDs")
    void shouldValidateAuthorizedPartySuccessfullyWhenItMatchesOneOfMultipleExpectedClientIds() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(EXPECTED_CLIENT_ID_2));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        assertDoesNotThrow(() -> validator.validateAuthorizedParty(token));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.AZP_MISMATCH));
    }

    @Test
    @DisplayName("Should fail validation when authorized party claim is missing")
    void shouldFailValidationWhenAuthorizedPartyClaimIsMissing() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUTHORIZED_PARTY.getName());
        claims.remove(ClaimName.CLIENT_ID.getName());
        AccessTokenContent token = new AccessTokenContent(claims, tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAuthorizedParty(token));
        assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType());
        assertTrue(exception.getMessage().contains("Missing required authorized party claim (azp or client_id)"));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.AZP_MISMATCH));
    }

    @Test
    @DisplayName("Should fail validation when authorized party claim is empty")
    void shouldFailValidationWhenAuthorizedPartyClaimIsEmpty() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(""));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAuthorizedParty(token));
        assertEquals(SecurityEventCounter.EventType.AZP_MISMATCH, exception.getEventType());
        assertTrue(exception.getMessage().contains("Authorized party mismatch"));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.AZP_MISMATCH));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.WARN.AZP_MISMATCH.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should fail validation when authorized party does not match expected client ID")
    void shouldFailValidationWhenAuthorizedPartyDoesNotMatchExpectedClientId() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(UNEXPECTED_CLIENT_ID));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAuthorizedParty(token));
        assertEquals(SecurityEventCounter.EventType.AZP_MISMATCH, exception.getEventType());
        assertTrue(exception.getMessage().contains("Authorized party mismatch"));
        assertTrue(exception.getMessage().contains(UNEXPECTED_CLIENT_ID));
        assertTrue(exception.getMessage().contains(EXPECTED_CLIENT_IDS.toString()));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.AZP_MISMATCH));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.WARN.AZP_MISMATCH.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should include expected client IDs in error message for mismatch")
    void shouldIncludeExpectedClientIdsInErrorMessageForMismatch() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(UNEXPECTED_CLIENT_ID));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAuthorizedParty(token));

        String errorMessage = exception.getMessage();
        assertTrue(errorMessage.contains(EXPECTED_CLIENT_ID_1));
        assertTrue(errorMessage.contains(EXPECTED_CLIENT_ID_2));
        assertTrue(errorMessage.contains("does not match any expected client ID"));
    }

    @Test
    @DisplayName("Should accept client_id fallback when azp absent and fallback enabled")
    void shouldAcceptClientIdFallbackWhenEnabled() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUTHORIZED_PARTY.getName());
        claims.put(ClaimName.CLIENT_ID.getName(), ClaimValue.forPlainString(EXPECTED_CLIENT_ID_1));
        AccessTokenContent token = new AccessTokenContent(claims, tokenHolder.getRawToken());

        assertDoesNotThrow(() -> validator.validateAuthorizedParty(token));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
    }

    @Test
    @DisplayName("Should reject client_id fallback when azp absent and clientIdFallbackEnabled=false")
    void shouldRejectClientIdFallbackWhenDisabled() {
        AuthorizedPartyValidator strictValidator = new AuthorizedPartyValidator(EXPECTED_CLIENT_IDS, securityEventCounter, false);
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUTHORIZED_PARTY.getName());
        claims.put(ClaimName.CLIENT_ID.getName(), ClaimValue.forPlainString(EXPECTED_CLIENT_ID_1));
        AccessTokenContent token = new AccessTokenContent(claims, tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> strictValidator.validateAuthorizedParty(token));
        assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType());
        assertTrue(exception.getMessage().contains("Missing required authorized party claim (azp or client_id)"));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
    }

    @Test
    @DisplayName("Should reject null claim values at token construction")
    void shouldRejectNullClaimValuesAtTokenConstruction() {
        // Since the claims map is defensively copied via Map.copyOf, null claim values are
        // rejected at construction time - a null azp value can never reach the validator.
        // The absent-claim case is covered by shouldFailValidationWhenAuthorizedPartyClaimIsMissing.
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.put(ClaimName.AUTHORIZED_PARTY.getName(), null);
        claims.remove(ClaimName.CLIENT_ID.getName());
        String rawToken = tokenHolder.getRawToken();

        assertThrows(NullPointerException.class,
                () -> new AccessTokenContent(claims, rawToken),
                "Null claim values must be rejected by the defensive copy");
    }
}
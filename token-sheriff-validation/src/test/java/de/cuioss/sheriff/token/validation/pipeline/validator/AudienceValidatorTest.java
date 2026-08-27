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
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
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
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link AudienceValidator}.
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("AudienceValidator")
class AudienceValidatorTest {

    private static final String EXPECTED_AUDIENCE_1 = "client1";
    private static final String EXPECTED_AUDIENCE_2 = "client2";
    private static final String UNEXPECTED_AUDIENCE = "unknown-client";
    private static final Set<String> EXPECTED_AUDIENCES = Set.of(EXPECTED_AUDIENCE_1, EXPECTED_AUDIENCE_2);

    private SecurityEventCounter securityEventCounter;
    private AudienceValidator validator;

    @BeforeEach
    void setup() {
        securityEventCounter = new SecurityEventCounter();
        validator = new AudienceValidator(EXPECTED_AUDIENCES, securityEventCounter, false, true);
    }

    @Test
    @DisplayName("Should skip validation when no expected audience configured")
    void shouldSkipValidationWhenNoExpectedAudienceConfigured() {
        AudienceValidator emptyValidator = new AudienceValidator(Set.of(), securityEventCounter, false, true);
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        assertDoesNotThrow(() -> emptyValidator.validateAudience(token));
    }

    @Test
    @DisplayName("Should validate single string audience successfully")
    void shouldValidateSingleStringAudienceSuccessfully() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUDIENCE.getName(), ClaimValue.forPlainString(EXPECTED_AUDIENCE_1));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        assertDoesNotThrow(() -> validator.validateAudience(token));
    }

    @Test
    @DisplayName("Should validate string list audience successfully")
    void shouldValidateStringListAudienceSuccessfully() {
        List<String> audienceList = List.of(UNEXPECTED_AUDIENCE, EXPECTED_AUDIENCE_1);
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUDIENCE.getName(), ClaimValue.forList(audienceList.toString(), audienceList));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        assertDoesNotThrow(() -> validator.validateAudience(token));
    }

    @Test
    @DisplayName("Should fail when single string audience does not match")
    void shouldFailWhenSingleStringAudienceDoesNotMatch() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUDIENCE.getName(), ClaimValue.forPlainString(UNEXPECTED_AUDIENCE));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAudience(token));
        assertEquals(SecurityEventCounter.EventType.AUDIENCE_MISMATCH, exception.getEventType());
        assertTrue(exception.getMessage().contains("Audience mismatch"));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.AUDIENCE_MISMATCH));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.WARN.AUDIENCE_MISMATCH.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should fail when string list audience does not contain any match")
    void shouldFailWhenStringListAudienceDoesNotContainAnyMatch() {
        List<String> audienceList = List.of(UNEXPECTED_AUDIENCE, "another-unknown");
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUDIENCE.getName(), ClaimValue.forList(audienceList.toString(), audienceList));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAudience(token));
        assertEquals(SecurityEventCounter.EventType.AUDIENCE_MISMATCH, exception.getEventType());
        assertTrue(exception.getMessage().contains("Audience mismatch"));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.AUDIENCE_MISMATCH));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.WARN.AUDIENCE_MISMATCH.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should pass when audience claim is single string even if unexpected value")
    void shouldPassWhenAudienceClaimIsSingleStringEvenIfUnexpectedValue() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.AUDIENCE.getName(), ClaimValue.forPlainString("123"));
        AccessTokenContent token = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAudience(token));
        assertEquals(SecurityEventCounter.EventType.AUDIENCE_MISMATCH, exception.getEventType());
        assertTrue(exception.getMessage().contains("Audience mismatch"));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.AUDIENCE_MISMATCH));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.WARN.AUDIENCE_MISMATCH.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should accept azp claim as fallback for missing audience in access token")
    void shouldAcceptAzpClaimAsFallbackForMissingAudienceInAccessToken() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUDIENCE.getName());
        claims.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(EXPECTED_AUDIENCE_1));
        AccessTokenContent token = new AccessTokenContent(claims, tokenHolder.getRawToken());

        assertDoesNotThrow(() -> validator.validateAudience(token));
    }

    @Test
    @DisplayName("Should pass for missing audience in ID token with valid azp fallback")
    void shouldPassForMissingAudienceInIdTokenWithValidAzpFallback() {
        TestTokenHolder tokenHolder = TestTokenGenerators.idTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUDIENCE.getName());
        claims.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(EXPECTED_AUDIENCE_1));
        IdTokenContent token = new IdTokenContent(claims, tokenHolder.getRawToken());

        assertDoesNotThrow(() -> validator.validateAudience(token));
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
    }

    @Test
    @DisplayName("Should reject access token with missing audience when accessTokenAudienceOptional=false")
    void shouldRejectAccessTokenWithMissingAudienceByDefault() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUDIENCE.getName());
        claims.remove(ClaimName.AUTHORIZED_PARTY.getName());
        AccessTokenContent token = new AccessTokenContent(claims, tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAudience(token));
        assertEquals(SecurityEventCounter.EventType.ACCESS_TOKEN_AUDIENCE_MISSING, exception.getEventType());
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.ACCESS_TOKEN_AUDIENCE_MISSING));
    }

    @Test
    @DisplayName("Should pass for missing audience in access token when accessTokenAudienceOptional=true")
    void shouldPassForMissingAudienceInAccessTokenWhenOptional() {
        AudienceValidator lenientValidator = new AudienceValidator(EXPECTED_AUDIENCES, securityEventCounter, true, true);
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUDIENCE.getName());
        claims.remove(ClaimName.AUTHORIZED_PARTY.getName());
        AccessTokenContent token = new AccessTokenContent(claims, tokenHolder.getRawToken());

        assertDoesNotThrow(() -> lenientValidator.validateAudience(token));
    }

    @Test
    @DisplayName("Should reject access token when azp fallback does not match expected audience")
    void shouldRejectWhenAzpFallbackDoesNotMatchExpectedAudience() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUDIENCE.getName());
        claims.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(UNEXPECTED_AUDIENCE));
        AccessTokenContent token = new AccessTokenContent(claims, tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAudience(token));
        assertEquals(SecurityEventCounter.EventType.ACCESS_TOKEN_AUDIENCE_MISSING, exception.getEventType());
    }

    @Test
    @DisplayName("Should reject azp fallback for missing audience when azpAudienceFallbackEnabled=false")
    void shouldRejectAzpFallbackWhenFallbackDisabled() {
        AudienceValidator strictValidator = new AudienceValidator(EXPECTED_AUDIENCES, securityEventCounter, false, false);
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUDIENCE.getName());
        claims.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(EXPECTED_AUDIENCE_1));
        AccessTokenContent token = new AccessTokenContent(claims, tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> strictValidator.validateAudience(token));
        assertEquals(SecurityEventCounter.EventType.ACCESS_TOKEN_AUDIENCE_MISSING, exception.getEventType());
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.ACCESS_TOKEN_AUDIENCE_MISSING));
    }

    @Test
    @DisplayName("Should fail for ID token without audience and without azp")
    void shouldFailForIdTokenWithoutAudienceAndWithoutAzp() {
        TestTokenHolder tokenHolder = TestTokenGenerators.idTokens().next();
        Map<String, ClaimValue> claims = new HashMap<>(tokenHolder.getClaims());
        claims.remove(ClaimName.AUDIENCE.getName());
        claims.remove(ClaimName.AUTHORIZED_PARTY.getName());
        IdTokenContent token = new IdTokenContent(claims, tokenHolder.getRawToken());

        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateAudience(token));
        assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType());
        assertTrue(exception.getMessage().contains("Missing required audience claim in ID token"));
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
    }
}
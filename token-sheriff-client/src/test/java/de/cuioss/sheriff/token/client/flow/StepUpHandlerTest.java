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
package de.cuioss.sheriff.token.client.flow;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.StepUpChallengeParser.StepUpChallenge;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("StepUpHandler + StepUpChallengeParser (RFC 9470)")
class StepUpHandlerTest {

    private static final String REDIRECT_URI = "https://rp.example.com/callback";
    private static final String AUTH_ENDPOINT = "https://issuer.example.com/authorize";
    private static final String ACR = "urn:mace:incommon:iap:silver";

    private final StepUpHandler stepUpHandler = new StepUpHandler();
    private final StepUpChallengeParser parser = new StepUpChallengeParser();

    private static ClientConfiguration config(String redirectUri) {
        return ClientConfiguration.builder()
                .issuer("https://issuer.example.com")
                .clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .redirectUri(redirectUri)
                .build();
    }

    private static ProviderMetadata metadata() {
        var metadata = new ProviderMetadata();
        metadata.issuer = "https://issuer.example.com";
        metadata.authorizationEndpoint = AUTH_ENDPOINT;
        metadata.codeChallengeMethodsSupported = List.of("S256");
        return metadata;
    }

    @Nested
    @DisplayName("initiate")
    class Initiate {

        @Test
        @DisplayName("Should mint an elevated authorization request carrying the challenge acr_values")
        void shouldCarryChallengeAcrValues() {
            var challenge = new StepUpChallenge(ACR, null);

            StepUpHandler.StepUpRequest request = stepUpHandler.initiate(config(REDIRECT_URI), metadata(), challenge);

            assertAll("elevated request",
                    () -> assertNotNull(request.authorizationUrl(), "an authorization URL is produced"),
                    () -> assertTrue(request.authorizationUrl().contains("acr_values="),
                            "the elevated request carries acr_values"),
                    () -> assertEquals(Optional.of(ACR), request.context().acrValues(),
                            "the fresh context requests the challenge acr_values"),
                    () -> assertEquals(REDIRECT_URI, request.context().redirectUri(),
                            "the fresh context keeps the configured redirect URI"));
        }

        @Test
        @DisplayName("Should emit the max_age freshness constraint on the elevated request (H2)")
        void shouldEmitMaxAge() {
            var challenge = new StepUpChallenge(ACR, 300);

            StepUpHandler.StepUpRequest request = stepUpHandler.initiate(config(REDIRECT_URI), metadata(), challenge);

            assertAll("max_age carried",
                    () -> assertTrue(request.authorizationUrl().contains("max_age=300"),
                            "the elevated request carries the max_age freshness constraint"),
                    () -> assertEquals(Optional.of(300), request.context().maxAge(),
                            "the fresh context models the requested max_age"));
        }

        @Test
        @DisplayName("Should mint a fresh non-replayable context (new state, nonce, PKCE) per step-up")
        void shouldMintFreshContext() {
            var challenge = new StepUpChallenge(ACR, 300);

            var first = stepUpHandler.initiate(config(REDIRECT_URI), metadata(), challenge).context();
            var second = stepUpHandler.initiate(config(REDIRECT_URI), metadata(), challenge).context();

            assertAll("fresh per step-up",
                    () -> assertNotEquals(first.state(), second.state(), "each step-up mints a new state"),
                    () -> assertNotEquals(first.nonce(), second.nonce(), "each step-up mints a new nonce"),
                    () -> assertNotEquals(first.pkceChallenge().codeVerifier(),
                            second.pkceChallenge().codeVerifier(), "each step-up mints a new PKCE verifier"));
        }

        @Test
        @DisplayName("Should fail closed when the client declares no redirect URI")
        void shouldFailWithoutRedirectUri() {
            var configuration = config(null);
            var metadata = metadata();
            var challenge = new StepUpChallenge(ACR, null);

            assertThrows(NullPointerException.class,
                    () -> stepUpHandler.initiate(configuration, metadata, challenge));
        }

        @Test
        @DisplayName("Should reject null arguments")
        void shouldRejectNullArguments() {
            var configuration = config(REDIRECT_URI);
            var metadata = metadata();
            var challenge = new StepUpChallenge(ACR, null);

            assertAll("null-guards",
                    () -> assertThrows(NullPointerException.class,
                            () -> stepUpHandler.initiate(null, metadata, challenge)),
                    () -> assertThrows(NullPointerException.class,
                            () -> stepUpHandler.initiate(configuration, null, challenge)),
                    () -> assertThrows(NullPointerException.class,
                            () -> stepUpHandler.initiate(configuration, metadata, null)));
        }

        @Test
        @DisplayName("Should reject a null authorization-request-builder collaborator")
        void shouldRejectNullBuilder() {
            assertThrows(NullPointerException.class, () -> new StepUpHandler(null));
        }
    }

    @Nested
    @DisplayName("parse")
    class Parse {

        @Test
        @DisplayName("Should parse an insufficient_user_authentication challenge with acr_values")
        void shouldParseAcrChallenge() {
            String header = "Bearer error=\"insufficient_user_authentication\", acr_values=\"" + ACR + "\"";

            Optional<StepUpChallenge> challenge = parser.parse(header);

            assertTrue(challenge.isPresent(), "a valid step-up challenge is parsed");
            assertEquals(Optional.of(ACR), challenge.get().getAcrValues(), "acr_values are extracted and unquoted");
        }

        @Test
        @DisplayName("Should parse an insufficient_user_authentication challenge with max_age")
        void shouldParseMaxAgeChallenge() {
            String header = "Bearer error=\"insufficient_user_authentication\", max_age=\"300\"";

            Optional<StepUpChallenge> challenge = parser.parse(header);

            assertTrue(challenge.isPresent(), "a max_age-only challenge is parsed");
            assertEquals(Optional.of(300), challenge.get().getMaxAge(), "max_age is extracted as an integer");
        }

        @Test
        @DisplayName("Should ignore a non-Bearer challenge")
        void shouldIgnoreNonBearer() {
            assertTrue(parser.parse("Basic realm=\"x\"").isEmpty(), "a non-Bearer scheme is ignored");
        }

        @Test
        @DisplayName("Should ignore a Bearer challenge whose error is not insufficient_user_authentication")
        void shouldIgnoreOtherError() {
            assertTrue(parser.parse("Bearer error=\"invalid_token\", acr_values=\"" + ACR + "\"").isEmpty(),
                    "only insufficient_user_authentication triggers a step-up");
        }

        @Test
        @DisplayName("Should ignore an insufficient_user_authentication challenge with neither acr_values nor max_age")
        void shouldIgnoreEmptyChallenge() {
            assertTrue(parser.parse("Bearer error=\"insufficient_user_authentication\"").isEmpty(),
                    "a challenge that constrains nothing is not actionable");
        }

        @Test
        @DisplayName("Should ignore null and blank headers")
        void shouldIgnoreNullAndBlank() {
            assertAll("absent headers",
                    () -> assertTrue(parser.parse(null).isEmpty(), "null header yields empty"),
                    () -> assertTrue(parser.parse("   ").isEmpty(), "blank header yields empty"));
        }

        @Test
        @DisplayName("Should ignore a non-numeric max_age rather than fail")
        void shouldIgnoreNonNumericMaxAge() {
            String header = "Bearer error=\"insufficient_user_authentication\", max_age=\"soon\"";

            assertTrue(parser.parse(header).isEmpty(),
                    "a non-numeric max_age is dropped, leaving no actionable constraint");
        }
    }

    @Nested
    @DisplayName("verifyResult (H1 / H2 post-exchange step-up verification)")
    class VerifyResult {

        private static final String WEAK_ACR = "urn:mace:incommon:iap:bronze";

        private IdTokenContent idToken(String acr, long authTimeEpochSeconds) {
            TestTokenHolder holder = TestTokenGenerators.idTokens().next();
            holder.withClaim("acr", ClaimValue.forPlainString(acr));
            holder.withClaim("auth_time", ClaimValue.forPlainString(Long.toString(authTimeEpochSeconds)));
            return holder.asIdTokenContent();
        }

        private IdTokenContent idTokenWithout(String claimName) {
            TestTokenHolder holder = TestTokenGenerators.idTokens().next();
            holder.withClaim("acr", ClaimValue.forPlainString(ACR));
            holder.withClaim("auth_time",
                    ClaimValue.forPlainString(Long.toString(Instant.now().getEpochSecond())));
            holder.withoutClaim(claimName);
            return holder.asIdTokenContent();
        }

        private IdTokenContent idTokenWithAuthTime(ClaimValue authTime) {
            TestTokenHolder holder = TestTokenGenerators.idTokens().next();
            holder.withClaim("acr", ClaimValue.forPlainString(ACR));
            holder.withClaim("auth_time", authTime);
            return holder.asIdTokenContent();
        }

        @Test
        @DisplayName("Should accept a step-up satisfying both the required acr and max_age")
        void shouldAcceptSatisfiedStepUp() {
            var challenge = new StepUpChallenge(ACR, 300);
            var idToken = idToken(ACR, Instant.now().getEpochSecond() - 10);

            assertDoesNotThrow(() -> stepUpHandler.verifyResult(challenge, idToken),
                    "a step-up whose acr and auth_time satisfy the challenge is accepted");
        }

        @Test
        @DisplayName("Should reject a step-up whose acr is weaker than required (H1)")
        void shouldRejectLowAcr() {
            var challenge = new StepUpChallenge(ACR, null);
            var idToken = idToken(WEAK_ACR, Instant.now().getEpochSecond());

            assertThrows(ClientProtocolException.class, () -> stepUpHandler.verifyResult(challenge, idToken),
                    "an acr weaker than required must not be treated as a satisfied step-up");
        }

        @Test
        @DisplayName("Should reject a step-up whose auth_time is older than the required max_age (H2)")
        void shouldRejectStaleAuthTime() {
            var challenge = new StepUpChallenge(null, 300);
            var idToken = idToken(ACR, Instant.now().getEpochSecond() - 1000);

            assertThrows(ClientProtocolException.class, () -> stepUpHandler.verifyResult(challenge, idToken),
                    "an authentication older than max_age must be rejected as stale");
        }

        @Test
        @DisplayName("Should treat a whitespace-only acr_values challenge as constraining nothing")
        void shouldAcceptWhenAcrValuesConstrainNothing() {
            var challenge = new StepUpChallenge("   ", null);
            var idToken = idToken(WEAK_ACR, Instant.now().getEpochSecond());

            assertDoesNotThrow(() -> stepUpHandler.verifyResult(challenge, idToken),
                    "a challenge listing no actual acr value cannot be violated by any acr");
        }

        @Test
        @DisplayName("Should reject a step-up whose ID token carries no acr claim at all (H1)")
        void shouldRejectMissingAcrClaim() {
            var challenge = new StepUpChallenge(ACR, null);
            var idToken = idTokenWithout("acr");

            assertThrows(ClientProtocolException.class, () -> stepUpHandler.verifyResult(challenge, idToken),
                    "an absent acr claim proves nothing about the authentication strength");
        }

        @Test
        @DisplayName("Should reject a step-up whose acr claim is blank (H1)")
        void shouldRejectBlankAcrClaim() {
            var challenge = new StepUpChallenge(ACR, null);
            var idToken = idToken("   ", Instant.now().getEpochSecond());

            assertThrows(ClientProtocolException.class, () -> stepUpHandler.verifyResult(challenge, idToken),
                    "a blank acr claim proves nothing about the authentication strength");
        }

        @Test
        @DisplayName("Should reject a step-up whose ID token carries no auth_time claim (H2)")
        void shouldRejectMissingAuthTimeClaim() {
            var challenge = new StepUpChallenge(null, 300);
            var idToken = idTokenWithout("auth_time");

            assertThrows(ClientProtocolException.class, () -> stepUpHandler.verifyResult(challenge, idToken),
                    "freshness cannot be verified without an auth_time claim");
        }

        @Test
        @DisplayName("Should reject a step-up whose auth_time is blank (H2)")
        void shouldRejectBlankAuthTime() {
            var challenge = new StepUpChallenge(null, 300);
            var idToken = idTokenWithAuthTime(ClaimValue.forPlainString("   "));

            assertThrows(ClientProtocolException.class, () -> stepUpHandler.verifyResult(challenge, idToken),
                    "an empty auth_time cannot establish freshness");
        }

        @Test
        @DisplayName("Should reject a step-up whose auth_time is not a numeric date (H2)")
        void shouldRejectNonNumericAuthTime() {
            var challenge = new StepUpChallenge(null, 300);
            var idToken = idTokenWithAuthTime(ClaimValue.forPlainString("yesterday"));

            var exception = assertThrows(ClientProtocolException.class,
                    () -> stepUpHandler.verifyResult(challenge, idToken),
                    "a non-numeric auth_time cannot establish freshness");

            assertInstanceOf(NumberFormatException.class, exception.getCause(),
                    "the parse failure is preserved as the cause");
        }

        @Test
        @DisplayName("Should accept a typed DATETIME auth_time without falling back to string parsing")
        void shouldAcceptTypedDateTimeAuthTime() {
            var authTime = OffsetDateTime.now(ZoneOffset.UTC).minusSeconds(30);
            var challenge = new StepUpChallenge(null, 300);
            var idToken = idTokenWithAuthTime(
                    ClaimValue.forDateTime("not-a-number", authTime));

            assertDoesNotThrow(() -> stepUpHandler.verifyResult(challenge, idToken),
                    "a typed auth_time is read from the parsed value, never from its original string");
        }
    }
}

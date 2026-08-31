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
package de.cuioss.sheriff.token.client.flow;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.dpop.DpopProofGenerator;
import de.cuioss.sheriff.token.client.dpop.SenderConstraint;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.HttpMethodMapper;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import lombok.Getter;
import mockwebserver3.MockResponse;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Transport-level coverage for {@link TokenEndpointClient}: the M8 log-injection defense on the
 * parse-error path, and the boundaries of the RFC 9449 §8 {@code use_dpop_nonce} retry.
 * <p>
 * <strong>M8:</strong> the token endpoint response body is authorization-server-controlled. When it is
 * malformed, DSL-JSON raises a parse error whose message echoes the offending fragment verbatim —
 * including any raw {@code CR}/{@code LF} the AS embedded. {@link TokenEndpointClient} must route that
 * fragment through {@code LogSanitizer.sanitize} (CWE-117) before it reaches the log appender or the
 * {@link TransportException} message, so the AS cannot forge a log line.
 * <p>
 * <strong>Nonce retry:</strong> a {@code use_dpop_nonce} challenge is retried exactly <em>once</em>, and
 * only when the challenge is genuine. The three cases below pin the boundaries the happy-path retry
 * coverage does not reach: a repeated challenge must not loop, a blank {@code DPoP-Nonce} must not be
 * treated as a challenge, and a challenge presented against an mTLS constraint must not be answered
 * with a DPoP proof.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("TokenEndpointClient parse-error sanitization (M8) and use_dpop_nonce retry boundaries")
class TokenEndpointClientTest {

    /** Cached 2048-bit RSA key pair, generated once for the whole class (DPoP proof material). */
    private static final KeyPair RSA_KEY_PAIR;

    static {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            RSA_KEY_PAIR = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key pair generation failed", e);
        }
    }

    @Getter
    private final TokenEndpointStubDispatcher moduleDispatcher = new TokenEndpointStubDispatcher();

    @BeforeEach
    void setUp() {
        moduleDispatcher.reset();
    }

    private static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer("https://issuer.example.com")
                .clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .redirectUri("https://rp.example.com/callback")
                .allowInsecureHttp(true)
                .build();
    }

    private static SenderConstraint dpopConstraint() {
        return SenderConstraint.dpop(new DpopProofGenerator(RSA_KEY_PAIR, "RS256"));
    }

    /**
     * Redeems against the stub endpoint under the supplied constraint and returns the surfaced
     * transport failure, so each nonce-boundary case asserts only on what distinguishes it: the
     * number of attempts the client actually made.
     */
    private TransportException redeemExpectingFailure(URIBuilder uriBuilder, SenderConstraint constraint) {
        var client = new TokenEndpointClient(config());
        String endpoint = uriBuilder.addPathSegment("token").buildAsString();
        Map<String, String> requestParams = Map.of("grant_type", "authorization_code");
        Map<String, String> requestHeaders = Map.of();

        return assertThrows(TransportException.class,
                () -> client.requestToken(endpoint, requestParams, requestHeaders, constraint),
                "an unrecoverable token-endpoint response must surface as a TransportException");
    }

    @Test
    @DisplayName("a malformed response with an embedded CR/LF is sanitized in the TransportException")
    void shouldSanitizeParseErrorFragment(URIBuilder uriBuilder) {
        var config = config();
        var client = new TokenEndpointClient(config);
        String endpoint = uriBuilder.addPathSegment("token").buildAsString();
        Map<String, String> requestParams = Map.of("grant_type", "authorization_code");
        Map<String, String> requestHeaders = Map.of();

        TransportException thrown = assertThrows(TransportException.class,
                () -> client.requestToken(endpoint, requestParams, requestHeaders),
                "a malformed token response must surface as a TransportException");

        String message = thrown.getMessage();
        assertAll("sanitized parse-error fragment",
                () -> assertFalse(message.indexOf('\r') >= 0,
                        "a raw CR from the AS-controlled body must not reach the exception message"),
                () -> assertFalse(message.indexOf('\n') >= 0,
                        "a raw LF from the AS-controlled body must not reach the exception message"),
                () -> assertTrue(message.contains("\\r") && message.contains("\\n"),
                        "the injected CR/LF must survive in escaped form, proving the fragment was carried and sanitized"));
    }

    @Test
    @DisplayName("a second use_dpop_nonce challenge on the retry does not trigger a further retry")
    void shouldNotRetryTwiceOnRepeatedNonceChallenge(URIBuilder uriBuilder) {
        moduleDispatcher.challengeWithNonce(Generators.letterStrings(16, 32).next());

        TransportException thrown = redeemExpectingFailure(uriBuilder, dpopConstraint());

        assertAll("single bounded retry",
                () -> assertEquals(2, moduleDispatcher.getCallCounter(),
                        "the challenge must be answered exactly once, never retried in a loop"),
                () -> assertTrue(thrown.getMessage().contains("400"),
                        "the unanswered challenge must surface as the endpoint's own status"));
    }

    @Test
    @DisplayName("a blank DPoP-Nonce header on a failed response does not trigger a retry")
    void shouldNotRetryOnBlankNonceHeader(URIBuilder uriBuilder) {
        moduleDispatcher.challengeWithNonce("   ");

        redeemExpectingFailure(uriBuilder, dpopConstraint());

        assertEquals(1, moduleDispatcher.getCallCounter(),
                "a blank nonce is not a usable challenge and must not be echoed into a retry");
    }

    @Test
    @DisplayName("a DPoP-Nonce challenge against an mTLS constraint does not trigger a retry")
    void shouldNotRetryNonceChallengeUnderMtlsConstraint(URIBuilder uriBuilder) {
        moduleDispatcher.challengeWithNonce(Generators.letterStrings(16, 32).next());
        var mtls = SenderConstraint.mtls(Generators.letterStrings(20, 40).next());

        redeemExpectingFailure(uriBuilder, mtls);

        assertEquals(1, moduleDispatcher.getCallCounter(),
                "an mTLS binding is transport-level; a DPoP nonce challenge is not answerable and must not be retried");
    }

    /**
     * Serves the token endpoint in one of two shapes: a syntactically malformed 200 body whose parse
     * error echoes an embedded {@code CR}/{@code LF} (the default, driving the M8 case), or an RFC 9449
     * §8 {@code use_dpop_nonce} challenge — a 400 carrying a {@code DPoP-Nonce} header — served on
     * <em>every</em> call, so a client that retried more than once is caught by the call counter.
     */
    static final class TokenEndpointStubDispatcher implements ModuleDispatcherElement {

        // The unparseable numeric expires_in embeds a raw CR/LF the AS controls; DSL-JSON's parse error
        // echoes that fragment verbatim, so it exercises the sanitizer on the parse-error path.
        private static final String MALFORMED_BODY =
                "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":9\r\nINJECTED9}";

        private static final String NONCE_CHALLENGE_BODY = "{\"error\":\"use_dpop_nonce\"}";

        private final AtomicInteger callCounter = new AtomicInteger();

        /** The {@code DPoP-Nonce} value to challenge with, or {@code null} to serve the malformed body. */
        private volatile String challengeNonce;

        /** Serve a {@code use_dpop_nonce} challenge carrying {@code nonce} on every call. */
        void challengeWithNonce(String nonce) {
            this.challengeNonce = nonce;
        }

        /** @return how many times the endpoint was called, i.e. the attempt count including retries */
        int getCallCounter() {
            return callCounter.get();
        }

        void reset() {
            this.challengeNonce = null;
            this.callCounter.set(0);
        }

        @Override
        public String getBaseUrl() {
            return "/token";
        }

        @Override
        public Set<HttpMethodMapper> supportedMethods() {
            return Set.of(HttpMethodMapper.POST);
        }

        @Override
        public Optional<MockResponse> handlePost(RecordedRequest request) {
            callCounter.incrementAndGet();
            String nonce = this.challengeNonce;
            if (nonce == null) {
                return Optional.of(new MockResponse(200,
                        Headers.of("Content-Type", "application/json"), MALFORMED_BODY));
            }
            return Optional.of(new MockResponse(400,
                    Headers.of("Content-Type", "application/json", "DPoP-Nonce", nonce),
                    NONCE_CHALLENGE_BODY));
        }
    }
}

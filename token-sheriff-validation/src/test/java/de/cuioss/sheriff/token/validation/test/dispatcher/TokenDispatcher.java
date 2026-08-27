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
package de.cuioss.sheriff.token.validation.test.dispatcher;

import de.cuioss.test.mockwebserver.dispatcher.HttpMethodMapper;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import lombok.NonNull;
import mockwebserver3.MockResponse;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static jakarta.servlet.http.HttpServletResponse.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * MockWebServer dispatcher for the OAuth 2.0 token endpoint (RFC 6749).
 * <p>
 * Serves grant responses in {@link ResponseStrategy#DEFAULT} mode and supports the
 * adversarial modes required by the commons threat catalog: RFC 6749 §5.2 error responses,
 * malformed bodies, and oversized bodies (DoS).
 * <p>
 * Follows the same configuration ({@code returnDefault()} / {@code returnError()} / …) and
 * verification ({@link #assertCallsAnswered(int)}) pattern as
 * {@link WellKnownDispatcher} and {@link JwksResolveDispatcher}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749">RFC 6749 — OAuth 2.0</a>
 */
@SuppressWarnings("UnusedReturnValue")
public class TokenDispatcher implements ModuleDispatcherElement {

    /**
     * "/oidc/token"
     */
    public static final String LOCAL_PATH = "/oidc/token";

    private final AtomicInteger callCounter = new AtomicInteger();
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;

    /** Caller-shaped response body/status that overrides the strategy switch when {@code customStatus >= 0}. */
    private volatile int customStatus = -1;
    private volatile String customBody = "";

    /** Optional per-redeem gate: when set, each call blocks (bounded 10 s) until the latch releases. */
    private volatile CountDownLatch redeemGate;

    public TokenDispatcher() {
        // No initialization needed
    }

    /**
     * Return the number of times this endpoint has been called.
     *
     * @return the current call count
     */
    public int getCallCounter() {
        return callCounter.get();
    }

    /**
     * Set the call count. Retained for callers that reset the counter to a known value.
     *
     * @param value the new call count
     */
    public void setCallCounter(int value) {
        callCounter.set(value);
    }

    /**
     * Serve a caller-shaped JSON body with HTTP 200, overriding the strategy-based response.
     * <p>
     * This is the hook the client flow tests use to return a real signed JWT the validation pipeline
     * accepts — the fixed {@link #defaultTokenResponse()} carries a placeholder token that cannot be
     * validated, so a flow test that redeems and validates a token supplies its own signed body here.
     *
     * @param jsonBody the exact JSON body to return
     * @return this instance for method chaining
     */
    public TokenDispatcher respondWith(String jsonBody) {
        return respondWith(SC_OK, jsonBody);
    }

    /**
     * Serve a caller-shaped body with an explicit status, overriding the strategy-based response.
     *
     * @param status   the HTTP status to return
     * @param jsonBody the exact body to return
     * @return this instance for method chaining
     */
    public TokenDispatcher respondWith(int status, String jsonBody) {
        this.customStatus = status;
        this.customBody = jsonBody;
        return this;
    }

    /**
     * Hold each redeem until {@code gate} releases (bounded 10 s). Left {@code null} the dispatcher
     * never blocks; a single-flight test installs a latch to prove concurrent refreshes collapse onto
     * one redeem.
     *
     * @param gate the latch each redeem awaits, or {@code null} to remove the gate
     * @return this instance for method chaining
     */
    public TokenDispatcher blockUntil(CountDownLatch gate) {
        this.redeemGate = gate;
        return this;
    }

    /**
     * Reset to the default strategy and clear any custom body, redeem gate, and call counter.
     */
    public void reset() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        this.customStatus = -1;
        this.customBody = "";
        this.redeemGate = null;
        this.callCounter.set(0);
    }

    /**
     * Return a valid token grant response (default).
     *
     * @return this instance for method chaining
     */
    public TokenDispatcher returnDefault() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        return this;
    }

    /**
     * Return an RFC 6749 §5.2 OAuth error response (HTTP 400).
     *
     * @return this instance for method chaining
     */
    public TokenDispatcher returnOAuthError() {
        this.responseStrategy = ResponseStrategy.OAUTH_ERROR;
        return this;
    }

    /**
     * Return an HTTP 500 server error.
     *
     * @return this instance for method chaining
     */
    public TokenDispatcher returnError() {
        this.responseStrategy = ResponseStrategy.SERVER_ERROR;
        return this;
    }

    /**
     * Adversarial: return a malformed (non-JSON) body with a 200 status.
     *
     * @return this instance for method chaining
     */
    public TokenDispatcher returnMalformedBody() {
        this.responseStrategy = ResponseStrategy.MALFORMED_BODY;
        return this;
    }

    /**
     * Adversarial: return an oversized body to exercise response-size limits (DoS).
     *
     * @return this instance for method chaining
     */
    public TokenDispatcher returnOversizedBody() {
        this.responseStrategy = ResponseStrategy.OVERSIZED_BODY;
        return this;
    }

    @Override
    public Optional<MockResponse> handlePost(@NonNull RecordedRequest request) {
        callCounter.incrementAndGet();
        awaitGate();
        Headers json = Headers.of("Content-Type", "application/json");
        if (customStatus >= 0) {
            return Optional.of(new MockResponse(customStatus, json, customBody));
        }
        return switch (responseStrategy) {
            case OAUTH_ERROR -> Optional.of(new MockResponse(SC_BAD_REQUEST, json,
                    "{\"error\":\"invalid_grant\",\"error_description\":\"The provided grant is invalid.\"}"));
            case SERVER_ERROR -> Optional.of(new MockResponse(SC_INTERNAL_SERVER_ERROR, Headers.of(), ""));
            case MALFORMED_BODY -> Optional.of(new MockResponse(SC_OK, json, "{ not json"));
            case OVERSIZED_BODY -> Optional.of(new MockResponse(SC_OK, json, AdversarialResponses.oversizedJson()));
            default -> Optional.of(new MockResponse(SC_OK, json, defaultTokenResponse()));
        };
    }

    /**
     * Build an RFC 6749 §5.1 token-endpoint success body carrying the supplied material. A
     * {@code null} refresh or ID token omits that member; this is the shared body-builder the client
     * flow tests use with {@link #respondWith(String)} to return real signed tokens.
     *
     * @param accessToken  the {@code access_token} value; must not be {@code null}
     * @param refreshToken the {@code refresh_token} value, or {@code null} to omit it
     * @param idToken      the {@code id_token} value, or {@code null} to omit it
     * @param expiresIn    the {@code expires_in} value in seconds
     * @return the JSON token-endpoint response body
     */
    public static String tokenResponse(String accessToken, String refreshToken, String idToken, long expiresIn) {
        StringBuilder json = new StringBuilder("{\"access_token\":\"").append(accessToken)
                .append("\",\"token_type\":\"Bearer\",\"expires_in\":").append(expiresIn);
        if (refreshToken != null) {
            json.append(",\"refresh_token\":\"").append(refreshToken).append('"');
        }
        if (idToken != null) {
            json.append(",\"id_token\":\"").append(idToken).append('"');
        }
        return json.append('}').toString();
    }

    private void awaitGate() {
        CountDownLatch gate = this.redeemGate;
        if (gate != null) {
            try {
                gate.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private String defaultTokenResponse() {
        return """
                {
                  "access_token": "mock-access-token",
                  "token_type": "Bearer",
                  "expires_in": 3600,
                  "refresh_token": "mock-refresh-token",
                  "id_token": "mock-id-token",
                  "scope": "openid profile email"
                }\
                """;
    }

    @Override
    public String getBaseUrl() {
        return LOCAL_PATH;
    }

    @Override
    public @NonNull Set<HttpMethodMapper> supportedMethods() {
        return Set.of(HttpMethodMapper.POST);
    }

    /**
     * Verifies whether this endpoint was called the given times.
     *
     * @param expected count of calls
     */
    public void assertCallsAnswered(int expected) {
        assertEquals(expected, callCounter.get());
    }

    /**
     * Response strategies for the token endpoint.
     */
    public enum ResponseStrategy {
        /** Valid token grant response. */
        DEFAULT,
        /** RFC 6749 §5.2 OAuth error response (HTTP 400). */
        OAUTH_ERROR,
        /** HTTP 500 server error. */
        SERVER_ERROR,
        /** Adversarial: malformed (non-JSON) body. */
        MALFORMED_BODY,
        /** Adversarial: oversized body (DoS). */
        OVERSIZED_BODY
    }
}

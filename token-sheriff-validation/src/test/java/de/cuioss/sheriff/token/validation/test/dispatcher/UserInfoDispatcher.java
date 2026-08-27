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
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import mockwebserver3.MockResponse;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;

import java.util.Optional;
import java.util.Set;

import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * MockWebServer dispatcher for the OpenID Connect userinfo endpoint (OIDC Core §5.3).
 * <p>
 * Serves a valid userinfo document in {@link ResponseStrategy#DEFAULT} mode and supports the
 * adversarial modes required by the commons threat catalog: tampered claims, {@code sub}
 * mismatch, an {@code invalid_token} error, and an oversized body (DoS).
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
@SuppressWarnings("UnusedReturnValue")
public class UserInfoDispatcher implements ModuleDispatcherElement {

    /**
     * "/oidc/userinfo"
     */
    public static final String LOCAL_PATH = "/oidc/userinfo";

    /** The subject the default response reports; adversarial modes deviate from it. */
    public static final String DEFAULT_SUBJECT = "test-subject";

    @Getter
    @Setter
    private int callCounter = 0;
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;

    public UserInfoDispatcher() {
        // No initialization needed
    }

    /**
     * Return a valid userinfo document (default).
     *
     * @return this instance for method chaining
     */
    public UserInfoDispatcher returnDefault() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        return this;
    }

    /**
     * Adversarial: return a userinfo document with tampered claim values.
     *
     * @return this instance for method chaining
     */
    public UserInfoDispatcher returnTamperedClaims() {
        this.responseStrategy = ResponseStrategy.TAMPERED_CLAIMS;
        return this;
    }

    /**
     * Adversarial: return a userinfo document whose {@code sub} does not match
     * {@link #DEFAULT_SUBJECT} (OIDC Core §5.3.2 requires the caller to reject this).
     *
     * @return this instance for method chaining
     */
    public UserInfoDispatcher returnSubMismatch() {
        this.responseStrategy = ResponseStrategy.SUB_MISMATCH;
        return this;
    }

    /**
     * Return an HTTP 401 with an {@code invalid_token} challenge.
     *
     * @return this instance for method chaining
     */
    public UserInfoDispatcher returnError() {
        this.responseStrategy = ResponseStrategy.ERROR;
        return this;
    }

    /**
     * Adversarial: return an oversized body to exercise response-size limits (DoS).
     *
     * @return this instance for method chaining
     */
    public UserInfoDispatcher returnOversizedBody() {
        this.responseStrategy = ResponseStrategy.OVERSIZED_BODY;
        return this;
    }

    @Override
    public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
        callCounter++;
        Headers json = Headers.of("Content-Type", "application/json");
        return switch (responseStrategy) {
            case TAMPERED_CLAIMS -> Optional.of(new MockResponse(SC_OK, json,
                    userInfo(DEFAULT_SUBJECT, "Tampered Name", "attacker@evil.example")));
            case SUB_MISMATCH -> Optional.of(new MockResponse(SC_OK, json,
                    userInfo("other-subject", "Test User", "test@example.com")));
            case ERROR -> Optional.of(new MockResponse(SC_UNAUTHORIZED,
                    Headers.of("WWW-Authenticate", "Bearer error=\"invalid_token\""), ""));
            case OVERSIZED_BODY -> Optional.of(new MockResponse(SC_OK, json, AdversarialResponses.oversizedJson()));
            default -> Optional.of(new MockResponse(SC_OK, json,
                    userInfo(DEFAULT_SUBJECT, "Test User", "test@example.com")));
        };
    }

    /**
     * OIDC Core §5.3.1 allows GET or POST for UserInfo; delegate to {@link #handleGet}.
     */
    @Override
    public Optional<MockResponse> handlePost(@NonNull RecordedRequest request) {
        return handleGet(request);
    }

    private String userInfo(String sub, String name, String email) {
        return "{\n" +
                "  \"sub\": \"" + sub + "\",\n" +
                "  \"name\": \"" + name + "\",\n" +
                "  \"email\": \"" + email + "\",\n" +
                "  \"email_verified\": true\n" +
                "}";
    }

    @Override
    public String getBaseUrl() {
        return LOCAL_PATH;
    }

    @Override
    public @NonNull Set<HttpMethodMapper> supportedMethods() {
        return Set.of(HttpMethodMapper.GET, HttpMethodMapper.POST);
    }

    /**
     * Verifies whether this endpoint was called the given times.
     *
     * @param expected count of calls
     */
    public void assertCallsAnswered(int expected) {
        assertEquals(expected, callCounter);
    }

    /**
     * Response strategies for the userinfo endpoint.
     */
    public enum ResponseStrategy {
        /** Valid userinfo document. */
        DEFAULT,
        /** Adversarial: tampered claim values. */
        TAMPERED_CLAIMS,
        /** Adversarial: {@code sub} does not match the expected subject. */
        SUB_MISMATCH,
        /** HTTP 401 invalid_token challenge. */
        ERROR,
        /** Adversarial: oversized body (DoS). */
        OVERSIZED_BODY
    }
}

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
 * MockWebServer dispatcher for the OAuth 2.0 token introspection endpoint (RFC 7662).
 * <p>
 * {@link ResponseStrategy#DEFAULT} reports an active token; {@link ResponseStrategy#INACTIVE}
 * reports {@code active:false}. Adversarial modes cover inconsistent metadata (e.g.
 * {@code active:true} with an {@code exp} in the past), an unauthorized error, and an
 * oversized body (DoS).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7662">RFC 7662 — OAuth 2.0 Token Introspection</a>
 */
@SuppressWarnings("UnusedReturnValue")
public class IntrospectionDispatcher implements ModuleDispatcherElement {

    /**
     * "/oidc/introspect"
     */
    public static final String LOCAL_PATH = "/oidc/introspect";

    @Getter
    @Setter
    private int callCounter = 0;
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;

    public IntrospectionDispatcher() {
        // No initialization needed
    }

    /**
     * Return an active-token introspection response (default).
     *
     * @return this instance for method chaining
     */
    public IntrospectionDispatcher returnDefault() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        return this;
    }

    /**
     * Return an {@code active:false} response (RFC 7662 §2.2).
     *
     * @return this instance for method chaining
     */
    public IntrospectionDispatcher returnInactive() {
        this.responseStrategy = ResponseStrategy.INACTIVE;
        return this;
    }

    /**
     * Adversarial: return inconsistent metadata ({@code active:true} but already expired).
     *
     * @return this instance for method chaining
     */
    public IntrospectionDispatcher returnTampered() {
        this.responseStrategy = ResponseStrategy.TAMPERED;
        return this;
    }

    /**
     * Return an HTTP 401 (introspection requires client authentication).
     *
     * @return this instance for method chaining
     */
    public IntrospectionDispatcher returnError() {
        this.responseStrategy = ResponseStrategy.ERROR;
        return this;
    }

    /**
     * Adversarial: return an oversized body to exercise response-size limits (DoS).
     *
     * @return this instance for method chaining
     */
    public IntrospectionDispatcher returnOversizedBody() {
        this.responseStrategy = ResponseStrategy.OVERSIZED_BODY;
        return this;
    }

    @Override
    public Optional<MockResponse> handlePost(@NonNull RecordedRequest request) {
        callCounter++;
        Headers json = Headers.of("Content-Type", "application/json");
        return switch (responseStrategy) {
            case INACTIVE -> Optional.of(new MockResponse(SC_OK, json, "{\"active\":false}"));
            case TAMPERED -> Optional.of(new MockResponse(SC_OK, json,
                    "{\"active\":true,\"sub\":\"test-subject\",\"exp\":1000000000}"));
            case ERROR -> Optional.of(new MockResponse(SC_UNAUTHORIZED, Headers.of(), ""));
            case OVERSIZED_BODY -> Optional.of(new MockResponse(SC_OK, json, AdversarialResponses.oversizedJson()));
            default -> Optional.of(new MockResponse(SC_OK, json, activeResponse()));
        };
    }

    private String activeResponse() {
        return """
                {
                  "active": true,
                  "scope": "openid profile email",
                  "client_id": "test-client",
                  "sub": "test-subject",
                  "token_type": "Bearer",
                  "exp": 9999999999
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
        assertEquals(expected, callCounter);
    }

    /**
     * Response strategies for the introspection endpoint.
     */
    public enum ResponseStrategy {
        /** Active-token response. */
        DEFAULT,
        /** {@code active:false} response. */
        INACTIVE,
        /** Adversarial: inconsistent metadata (active but expired). */
        TAMPERED,
        /** HTTP 401 unauthorized. */
        ERROR,
        /** Adversarial: oversized body (DoS). */
        OVERSIZED_BODY
    }
}

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

import static jakarta.servlet.http.HttpServletResponse.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * MockWebServer dispatcher for the OAuth 2.0 Pushed Authorization Requests (PAR) endpoint
 * (RFC 9126).
 * <p>
 * {@link ResponseStrategy#DEFAULT} returns an HTTP 201 with a {@code request_uri}. Adversarial
 * modes cover an RFC 9126 §2.3 error, a server error, and an oversized body (DoS).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126 — Pushed Authorization Requests</a>
 */
@SuppressWarnings("UnusedReturnValue")
public class ParDispatcher implements ModuleDispatcherElement {

    /**
     * "/oidc/par"
     */
    public static final String LOCAL_PATH = "/oidc/par";

    @Getter
    @Setter
    private int callCounter = 0;
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;

    public ParDispatcher() {
        // No initialization needed
    }

    /**
     * Return an RFC 9126 success (HTTP 201 with {@code request_uri}) — the default.
     *
     * @return this instance for method chaining
     */
    public ParDispatcher returnDefault() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        return this;
    }

    /**
     * Return an RFC 9126 §2.3 error (HTTP 400, {@code invalid_request}).
     *
     * @return this instance for method chaining
     */
    public ParDispatcher returnOAuthError() {
        this.responseStrategy = ResponseStrategy.OAUTH_ERROR;
        return this;
    }

    /**
     * Return an HTTP 500 server error.
     *
     * @return this instance for method chaining
     */
    public ParDispatcher returnError() {
        this.responseStrategy = ResponseStrategy.SERVER_ERROR;
        return this;
    }

    /**
     * Adversarial: return an oversized body to exercise response-size limits (DoS).
     *
     * @return this instance for method chaining
     */
    public ParDispatcher returnOversizedBody() {
        this.responseStrategy = ResponseStrategy.OVERSIZED_BODY;
        return this;
    }

    @Override
    public Optional<MockResponse> handlePost(@NonNull RecordedRequest request) {
        callCounter++;
        Headers json = Headers.of("Content-Type", "application/json");
        return switch (responseStrategy) {
            case OAUTH_ERROR -> Optional.of(new MockResponse(SC_BAD_REQUEST, json,
                    "{\"error\":\"invalid_request\",\"error_description\":\"The request is missing a required parameter.\"}"));
            case SERVER_ERROR -> Optional.of(new MockResponse(SC_INTERNAL_SERVER_ERROR, Headers.of(), ""));
            case OVERSIZED_BODY -> Optional.of(new MockResponse(SC_OK, json, AdversarialResponses.oversizedJson()));
            default -> Optional.of(new MockResponse(SC_CREATED, json,
                    """
                            {
                              "request_uri": "urn:ietf:params:oauth:request_uri:mock-par-reference",
                              "expires_in": 90
                            }\
                            """));
        };
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
     * Response strategies for the PAR endpoint.
     */
    public enum ResponseStrategy {
        /** RFC 9126 success (HTTP 201 with {@code request_uri}). */
        DEFAULT,
        /** RFC 9126 §2.3 error (HTTP 400). */
        OAUTH_ERROR,
        /** HTTP 500 server error. */
        SERVER_ERROR,
        /** Adversarial: oversized body (DoS). */
        OVERSIZED_BODY
    }
}

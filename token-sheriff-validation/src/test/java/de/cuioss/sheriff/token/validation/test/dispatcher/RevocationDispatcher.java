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
 * MockWebServer dispatcher for the OAuth 2.0 token revocation endpoint (RFC 7009).
 * <p>
 * A successful revocation returns HTTP 200 with an empty body ({@link ResponseStrategy#DEFAULT}).
 * Adversarial modes cover an RFC 7009 §2.2.1 error, a server error, and an oversized body (DoS).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009 — OAuth 2.0 Token Revocation</a>
 */
@SuppressWarnings("UnusedReturnValue")
public class RevocationDispatcher implements ModuleDispatcherElement {

    /**
     * "/oidc/revoke"
     */
    public static final String LOCAL_PATH = "/oidc/revoke";

    @Getter
    @Setter
    private int callCounter = 0;
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;

    public RevocationDispatcher() {
        // No initialization needed
    }

    /**
     * Return an RFC 7009 success (HTTP 200, empty body) — the default.
     *
     * @return this instance for method chaining
     */
    public RevocationDispatcher returnDefault() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        return this;
    }

    /**
     * Return an RFC 7009 §2.2.1 error (HTTP 400, {@code unsupported_token_type}).
     *
     * @return this instance for method chaining
     */
    public RevocationDispatcher returnOAuthError() {
        this.responseStrategy = ResponseStrategy.OAUTH_ERROR;
        return this;
    }

    /**
     * Return an HTTP 503 server error.
     *
     * @return this instance for method chaining
     */
    public RevocationDispatcher returnError() {
        this.responseStrategy = ResponseStrategy.SERVER_ERROR;
        return this;
    }

    /**
     * Adversarial: return an oversized body to exercise response-size limits (DoS).
     *
     * @return this instance for method chaining
     */
    public RevocationDispatcher returnOversizedBody() {
        this.responseStrategy = ResponseStrategy.OVERSIZED_BODY;
        return this;
    }

    @Override
    public Optional<MockResponse> handlePost(@NonNull RecordedRequest request) {
        callCounter++;
        Headers json = Headers.of("Content-Type", "application/json");
        return switch (responseStrategy) {
            case OAUTH_ERROR -> Optional.of(new MockResponse(SC_BAD_REQUEST, json,
                    "{\"error\":\"unsupported_token_type\"}"));
            case SERVER_ERROR -> Optional.of(new MockResponse(SC_SERVICE_UNAVAILABLE, Headers.of(), ""));
            case OVERSIZED_BODY -> Optional.of(new MockResponse(SC_OK, json, AdversarialResponses.oversizedJson()));
            default -> Optional.of(new MockResponse(SC_OK, Headers.of(), ""));
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
     * Response strategies for the revocation endpoint.
     */
    public enum ResponseStrategy {
        /** RFC 7009 success (HTTP 200, empty body). */
        DEFAULT,
        /** RFC 7009 §2.2.1 error (HTTP 400). */
        OAUTH_ERROR,
        /** HTTP 503 server error. */
        SERVER_ERROR,
        /** Adversarial: oversized body (DoS). */
        OVERSIZED_BODY
    }
}

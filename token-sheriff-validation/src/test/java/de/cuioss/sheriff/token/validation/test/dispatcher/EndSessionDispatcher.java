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

import static jakarta.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static jakarta.servlet.http.HttpServletResponse.SC_FOUND;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * MockWebServer dispatcher for the OpenID Connect RP-initiated logout ({@code end_session})
 * endpoint.
 * <p>
 * {@link ResponseStrategy#DEFAULT} redirects to the registered post-logout URI. The
 * adversarial {@link ResponseStrategy#OPEN_REDIRECT} mode redirects to an unregistered
 * external URL — the client MUST validate {@code post_logout_redirect_uri} against its
 * allow-list and reject this.
 *
 * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OpenID Connect RP-Initiated Logout 1.0</a>
 */
@SuppressWarnings("UnusedReturnValue")
public class EndSessionDispatcher implements ModuleDispatcherElement {

    /**
     * "/oidc/logout"
     */
    public static final String LOCAL_PATH = "/oidc/logout";

    /** The registered, safe post-logout redirect target. */
    public static final String REGISTERED_REDIRECT = "https://client.example.com/logged-out";

    /** An unregistered, attacker-controlled target used by the open-redirect mode. */
    public static final String ATTACKER_REDIRECT = "https://attacker.example.net/harvest";

    @Getter
    @Setter
    private int callCounter = 0;
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;

    public EndSessionDispatcher() {
        // No initialization needed
    }

    /**
     * Redirect to the registered post-logout URI (default).
     *
     * @return this instance for method chaining
     */
    public EndSessionDispatcher returnDefault() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        return this;
    }

    /**
     * Adversarial: redirect to an unregistered external URL (open redirect).
     *
     * @return this instance for method chaining
     */
    public EndSessionDispatcher returnOpenRedirect() {
        this.responseStrategy = ResponseStrategy.OPEN_REDIRECT;
        return this;
    }

    /**
     * Return an HTTP 400 (e.g. missing / invalid {@code id_token_hint}).
     *
     * @return this instance for method chaining
     */
    public EndSessionDispatcher returnError() {
        this.responseStrategy = ResponseStrategy.ERROR;
        return this;
    }

    @Override
    public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
        callCounter++;
        return switch (responseStrategy) {
            case OPEN_REDIRECT -> Optional.of(new MockResponse(SC_FOUND,
                    Headers.of("Location", ATTACKER_REDIRECT), ""));
            case ERROR -> Optional.of(new MockResponse(SC_BAD_REQUEST, Headers.of(), ""));
            default -> Optional.of(new MockResponse(SC_FOUND,
                    Headers.of("Location", REGISTERED_REDIRECT), ""));
        };
    }

    /**
     * RP-Initiated Logout allows POST as well as GET; delegate to {@link #handleGet}.
     */
    @Override
    public Optional<MockResponse> handlePost(@NonNull RecordedRequest request) {
        return handleGet(request);
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
     * Response strategies for the end-session endpoint.
     */
    public enum ResponseStrategy {
        /** Redirect to the registered post-logout URI. */
        DEFAULT,
        /** Adversarial: redirect to an unregistered external URL. */
        OPEN_REDIRECT,
        /** HTTP 400 error. */
        ERROR
    }
}

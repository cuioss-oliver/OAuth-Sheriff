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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression coverage for the M8 log-injection defense in {@link TokenEndpointClient}.
 * <p>
 * The token endpoint response body is authorization-server-controlled. When it is malformed, DSL-JSON
 * raises a parse error whose message echoes the offending fragment verbatim — including any raw
 * {@code CR}/{@code LF} the AS embedded. {@link TokenEndpointClient} must route that fragment through
 * {@code LogSanitizer.sanitize} (CWE-117) before it reaches the log appender or the
 * {@link TransportException} message, so the AS cannot forge a log line. This test drives a real
 * malformed response carrying an embedded {@code CR}/{@code LF} and asserts the raw control characters
 * are neutralized while their escaped, investigative form survives.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("TokenEndpointClient parse-error sanitization (M8)")
class TokenEndpointClientTest {

    @Getter
    private final MalformedBodyDispatcher moduleDispatcher = new MalformedBodyDispatcher();

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

    /** Serves a syntactically malformed token response whose parse error echoes an embedded CR/LF. */
    static final class MalformedBodyDispatcher implements ModuleDispatcherElement {

        // The unparseable numeric expires_in embeds a raw CR/LF the AS controls; DSL-JSON's parse error
        // echoes that fragment verbatim, so it exercises the sanitizer on the parse-error path.
        private static final String MALFORMED_BODY =
                "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":9\r\nINJECTED9}";

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
            return Optional.of(new MockResponse(200, Headers.of("Content-Type", "application/json"), MALFORMED_BODY));
        }
    }
}

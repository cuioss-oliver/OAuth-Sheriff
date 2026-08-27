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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.validation.test.dispatcher.UserInfoDispatcher;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.HttpMethodMapper;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import lombok.Getter;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("UserInfoClient userinfo fetch (OIDC Core §5.3)")
class UserInfoClientTest {

    private static final String APPLICATION_JWT = "application/jwt";

    @Getter
    private final UserInfoTestDispatcher moduleDispatcher = new UserInfoTestDispatcher();

    @BeforeEach
    void resetDispatcher() {
        moduleDispatcher.setCallCounter(0);
        moduleDispatcher.returnDefault();
    }

    private static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer("https://" + Generators.letterStrings(3, 10).next() + ".example.com")
                .clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .allowInsecureHttp(true)
                .build();
    }

    private static String userInfoEndpoint(URIBuilder uriBuilder) {
        return uriBuilder.addPathSegments("oidc", "userinfo").buildAsString();
    }

    private UserInfoClient userInfoClient() {
        return new UserInfoClient(config());
    }

    @Test
    @DisplayName("Should fetch and normalize the userinfo document")
    void shouldFetchUserInfo(URIBuilder uriBuilder) {
        UserInfoResponse userInfo = userInfoClient().fetchUserInfo(
                userInfoEndpoint(uriBuilder), Generators.nonBlankStrings().next());

        assertAll("userinfo response",
                () -> assertEquals(UserInfoDispatcher.DEFAULT_SUBJECT, userInfo.getSub().orElseThrow(),
                        "the sub is captured"),
                () -> assertEquals("test@example.com", userInfo.getEmail().orElseThrow(), "the email is captured"),
                () -> assertTrue(userInfo.isEmailVerified(), "the email_verified flag is captured"));
    }

    @Test
    @DisplayName("Should present the access token as an RFC 6750 Bearer credential")
    void shouldPresentBearerToken(URIBuilder uriBuilder, MockWebServer server) throws Exception {
        // A realistic access token: header-safe characters only. nonBlankStrings() may include
        // leading/trailing whitespace, which HTTP header canonicalization trims on the round-trip,
        // making the exact-equality assertion below flaky.
        String accessToken = Generators.letterStrings(20, 40).next();

        userInfoClient().fetchUserInfo(userInfoEndpoint(uriBuilder), accessToken);

        RecordedRequest request = server.takeRequest();
        assertEquals("Bearer " + accessToken, request.getHeaders().get("Authorization"),
                "the access token is presented as a Bearer credential");
    }

    @Test
    @DisplayName("Should surface a TransportException on an invalid_token (401) response")
    void shouldRejectUnauthorized(URIBuilder uriBuilder) {
        moduleDispatcher.returnError();
        var client = userInfoClient();
        var endpoint = userInfoEndpoint(uriBuilder);
        var token = Generators.nonBlankStrings().next();

        assertThrows(TransportException.class, () -> client.fetchUserInfo(endpoint, token));
    }

    @Test
    @DisplayName("Should reject an oversized response body (DoS guard)")
    void shouldRejectOversizedBody(URIBuilder uriBuilder) {
        moduleDispatcher.returnOversizedBody();
        var client = userInfoClient();
        var endpoint = userInfoEndpoint(uriBuilder);
        var token = Generators.nonBlankStrings().next();

        assertThrows(TransportException.class, () -> client.fetchUserInfo(endpoint, token));
    }

    @Test
    @DisplayName("Should return the (unbound) sub even when it does not match — binding is a separate step")
    void shouldReturnMismatchedSubForBindingStep(URIBuilder uriBuilder) {
        moduleDispatcher.returnSubMismatch();

        UserInfoResponse userInfo = userInfoClient().fetchUserInfo(
                userInfoEndpoint(uriBuilder), Generators.nonBlankStrings().next());

        assertEquals("other-subject", userInfo.getSub().orElseThrow(),
                "the transport returns the raw sub; SubBindingValidator is what rejects the mismatch");
    }

    @Test
    @DisplayName("Should advertise both application/json and application/jwt on the Accept header (M3)")
    void shouldAdvertiseJsonAndJwtAccept(URIBuilder uriBuilder, MockWebServer server) throws Exception {
        userInfoClient().fetchUserInfo(userInfoEndpoint(uriBuilder), Generators.nonBlankStrings().next());

        RecordedRequest request = server.takeRequest();
        String accept = request.getHeaders().get("Accept");
        assertAll("accept header",
                () -> assertNotNull(accept, "the request must advertise an Accept header"),
                () -> assertTrue(accept.contains("application/json"), "plain JSON userinfo must still be accepted"),
                () -> assertTrue(accept.contains(APPLICATION_JWT),
                        "a signed JWT userinfo response must be advertised as acceptable"));
    }

    @Test
    @DisplayName("Should validate a signed JWT userinfo response through the supplied validator (M3)")
    void shouldValidateSignedUserInfo(URIBuilder uriBuilder) {
        String signedJwt = "eyJhbGciOiJSUzI1NiJ9." + Generators.letterStrings(20, 40).next() + ".signature";
        moduleDispatcher.returnSigned(APPLICATION_JWT, signedJwt);
        String subject = Generators.nonBlankStrings().next();
        AtomicReference<String> received = new AtomicReference<>();

        UserInfoResponse userInfo = userInfoClient().fetchUserInfo(
                userInfoEndpoint(uriBuilder), Generators.nonBlankStrings().next(), null,
                body -> {
                    received.set(body);
                    UserInfoResponse validated = new UserInfoResponse();
                    validated.sub = subject;
                    return validated;
                });

        assertAll("signed userinfo",
                () -> assertEquals(signedJwt, received.get(),
                        "the raw signed JWT body must be handed to the validator, not parsed as JSON"),
                () -> assertEquals(subject, userInfo.getSub().orElseThrow(),
                        "the validated signed userinfo claims must be returned"));
    }

    @Test
    @DisplayName("Should fail closed on a signed userinfo response when no validator is configured (M3)")
    void shouldRejectSignedUserInfoWithoutValidator(URIBuilder uriBuilder) {
        moduleDispatcher.returnSigned(APPLICATION_JWT,
                "eyJhbGciOiJSUzI1NiJ9." + Generators.letterStrings(20, 40).next() + ".signature");
        var client = userInfoClient();
        var endpoint = userInfoEndpoint(uriBuilder);
        var token = Generators.nonBlankStrings().next();

        assertThrows(TransportException.class, () -> client.fetchUserInfo(endpoint, token, null, null));
    }

    @Test
    @DisplayName("Should sanitize an AS-controlled parse-error fragment carrying CR/LF (M8)")
    void shouldSanitizeParseErrorFragment(URIBuilder uriBuilder) {
        // The userinfo body is AS-controlled; a malformed value with an embedded CR/LF must not forge a
        // log line — the parse-error fragment must be routed through LogSanitizer before it is exposed.
        moduleDispatcher.returnMalformedJson("{\"sub\":\"a\",\"email_verified\":tru\r\nINJECTED}");
        var client = userInfoClient();
        var endpoint = userInfoEndpoint(uriBuilder);
        var token = Generators.nonBlankStrings().next();

        TransportException thrown = assertThrows(TransportException.class,
                () -> client.fetchUserInfo(endpoint, token),
                "a malformed userinfo response must surface as a TransportException");

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
    @DisplayName("Should reject a signed userinfo response whose validated claims omit the sub (M3)")
    void shouldRejectSignedUserInfoMissingSub(URIBuilder uriBuilder) {
        moduleDispatcher.returnSigned(APPLICATION_JWT,
                "eyJhbGciOiJSUzI1NiJ9." + Generators.letterStrings(20, 40).next() + ".signature");
        var client = userInfoClient();
        var endpoint = userInfoEndpoint(uriBuilder);
        var token = Generators.nonBlankStrings().next();

        assertThrows(TransportException.class,
                () -> client.fetchUserInfo(endpoint, token, null, body -> new UserInfoResponse()));
    }

    /**
     * Userinfo dispatcher that serves the {@link UserInfoDispatcher} JSON strategies by default and,
     * on demand, a signed JWT response (an {@code application/jwt} {@code Content-Type} with a JWT body)
     * so the signed-userinfo path (OIDC Core §5.3.2, M3) can be exercised end-to-end.
     */
    static final class UserInfoTestDispatcher implements ModuleDispatcherElement {

        private static final String APPLICATION_JSON = "application/json";

        private final UserInfoDispatcher json = new UserInfoDispatcher();
        private boolean signed;
        private String signedContentType = APPLICATION_JWT;
        private String signedBody = "";
        private boolean malformed;
        private String malformedBody = "";

        UserInfoTestDispatcher returnDefault() {
            signed = false;
            malformed = false;
            json.returnDefault();
            return this;
        }

        UserInfoTestDispatcher returnMalformedJson(String body) {
            signed = false;
            malformed = true;
            malformedBody = body;
            return this;
        }

        UserInfoTestDispatcher returnError() {
            signed = false;
            json.returnError();
            return this;
        }

        UserInfoTestDispatcher returnOversizedBody() {
            signed = false;
            json.returnOversizedBody();
            return this;
        }

        UserInfoTestDispatcher returnSubMismatch() {
            signed = false;
            json.returnSubMismatch();
            return this;
        }

        UserInfoTestDispatcher returnSigned(String contentType, String body) {
            signed = true;
            signedContentType = contentType;
            signedBody = body;
            return this;
        }

        void setCallCounter(int callCounter) {
            json.setCallCounter(callCounter);
        }

        @Override
        public String getBaseUrl() {
            return json.getBaseUrl();
        }

        @Override
        public Set<HttpMethodMapper> supportedMethods() {
            return json.supportedMethods();
        }

        @Override
        public Optional<MockResponse> handleGet(RecordedRequest request) {
            if (malformed) {
                return Optional.of(new MockResponse(200, Headers.of("Content-Type", APPLICATION_JSON), malformedBody));
            }
            if (signed) {
                return Optional.of(new MockResponse(200, Headers.of("Content-Type", signedContentType), signedBody));
            }
            return json.handleGet(request);
        }

        @Override
        public Optional<MockResponse> handlePost(RecordedRequest request) {
            return handleGet(request);
        }
    }
}

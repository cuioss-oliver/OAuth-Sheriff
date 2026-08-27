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
package de.cuioss.sheriff.token.client.auth;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.flow.TokenEndpointClient;
import de.cuioss.sheriff.token.validation.test.dispatcher.TokenDispatcher;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit and request-verification tests for the shared-secret client authentication strategies
 * {@link ClientSecretBasicAuth} ({@code client_secret_basic}) and {@link ClientSecretPostAuth}
 * ({@code client_secret_post}) — deliverable 3 (CLIENT-4).
 * <p>
 * The mechanics tests assert the pure {@link ClientAuthentication#decorate(Map, Map)} contract;
 * the request-verification tests drive a real {@link TokenEndpointClient} POST against MockWebServer
 * and confirm the credentials arrive on the wire (header vs form body) and never leak into the URL.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("Shared-secret client authentication (client_secret_basic / client_secret_post)")
class ClientSecretAuthTest {

    @Getter
    private final TokenDispatcher moduleDispatcher = new TokenDispatcher();

    @BeforeEach
    void resetDispatcher() {
        moduleDispatcher.reset();
    }

    private static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer("https://" + Generators.letterStrings(3, 10).next() + ".example.com")
                .clientId(Generators.letterStrings(5, 12).next())
                .clientSecret(Generators.letterStrings(8, 20).next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .allowInsecureHttp(true)
                .build();
    }

    private static String tokenEndpoint(URIBuilder uriBuilder) {
        return uriBuilder.addPathSegments("oidc", "token").buildAsString();
    }

    @Test
    @DisplayName("client_secret_basic should report the client_secret_basic method")
    void basicShouldReportMethod() {
        var auth = new ClientSecretBasicAuth(Generators.letterStrings(5, 12).next(),
                Generators.letterStrings(8, 20).next());

        assertEquals(ClientAuthMethod.CLIENT_SECRET_BASIC, auth.method(),
                "strategy must report client_secret_basic");
    }

    @Test
    @DisplayName("client_secret_basic should place credentials in an HTTP Basic Authorization header, not the form body")
    void basicShouldDecorateWithHeader() {
        String clientId = Generators.letterStrings(5, 12).next();
        String clientSecret = Generators.letterStrings(8, 20).next();
        var auth = new ClientSecretBasicAuth(clientId, clientSecret);
        Map<String, String> form = new HashMap<>();
        Map<String, String> headers = new HashMap<>();

        auth.decorate(form, headers);

        String authorization = headers.get("Authorization");
        assertNotNull(authorization, "Authorization header must be present");
        assertTrue(authorization.startsWith("Basic "), "must be an HTTP Basic header");
        String decoded = new String(Base64.getDecoder().decode(authorization.substring("Basic ".length())),
                StandardCharsets.UTF_8);
        String expected = URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + ":" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        assertAll("basic credentials",
                () -> assertEquals(expected, decoded, "credentials must be urlencoded(id):urlencoded(secret)"),
                () -> assertTrue(form.isEmpty(), "no shared secret must be placed in the form body"));
    }

    @Test
    @DisplayName("client_secret_basic should send the Basic header on the wire without leaking the secret into the URL")
    void basicShouldSendHeaderOnTheWire(URIBuilder uriBuilder, MockWebServer server) throws Exception {
        moduleDispatcher.returnDefault();
        String clientId = Generators.letterStrings(5, 12).next();
        String clientSecret = Generators.letterStrings(8, 20).next();
        var auth = new ClientSecretBasicAuth(clientId, clientSecret);
        Map<String, String> form = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        auth.decorate(form, headers);
        form.put("grant_type", "client_credentials");

        new TokenEndpointClient(config()).requestToken(tokenEndpoint(uriBuilder), form, headers);

        RecordedRequest request = server.takeRequest();
        String authorization = request.getHeaders().get("Authorization");
        String body = request.getBody() == null ? "" : request.getBody().utf8();
        assertAll("wire request",
                () -> assertNotNull(authorization, "Authorization header must reach the server"),
                () -> assertTrue(authorization.startsWith("Basic "), "must be an HTTP Basic header"),
                () -> assertFalse(request.getTarget().contains(clientSecret),
                        "secret must never appear in the request URL"),
                () -> assertFalse(body.contains(clientSecret),
                        "client_secret_basic must not place the secret in the form body"));
    }

    @Test
    @DisplayName("client_secret_basic should reject null constructor arguments")
    void basicShouldRejectNullArguments() {
        String secret = Generators.letterStrings(8, 20).next();
        String id = Generators.letterStrings(5, 12).next();
        assertAll("null rejection",
                () -> assertThrows(NullPointerException.class, () -> new ClientSecretBasicAuth(null, secret)),
                () -> assertThrows(NullPointerException.class, () -> new ClientSecretBasicAuth(id, null)));
    }

    @Test
    @DisplayName("client_secret_post should report the client_secret_post method")
    void postShouldReportMethod() {
        var auth = new ClientSecretPostAuth(Generators.letterStrings(5, 12).next(),
                Generators.letterStrings(8, 20).next());

        assertEquals(ClientAuthMethod.CLIENT_SECRET_POST, auth.method(),
                "strategy must report client_secret_post");
    }

    @Test
    @DisplayName("client_secret_post should place credentials in the form body, not an Authorization header")
    void postShouldDecorateWithFormParameters() {
        String clientId = Generators.letterStrings(5, 12).next();
        String clientSecret = Generators.letterStrings(8, 20).next();
        var auth = new ClientSecretPostAuth(clientId, clientSecret);
        Map<String, String> form = new HashMap<>();
        Map<String, String> headers = new HashMap<>();

        auth.decorate(form, headers);

        assertAll("post credentials",
                () -> assertEquals(clientId, form.get("client_id"), "client_id must be in the form body"),
                () -> assertEquals(clientSecret, form.get("client_secret"), "client_secret must be in the form body"),
                () -> assertNull(headers.get("Authorization"), "no Authorization header for client_secret_post"));
    }

    @Test
    @DisplayName("client_secret_post should send credentials in the form body without leaking the secret into the URL")
    void postShouldSendFormCredentialsOnTheWire(URIBuilder uriBuilder, MockWebServer server) throws Exception {
        moduleDispatcher.returnDefault();
        String clientId = Generators.letterStrings(5, 12).next();
        String clientSecret = Generators.letterStrings(8, 20).next();
        var auth = new ClientSecretPostAuth(clientId, clientSecret);
        Map<String, String> form = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        auth.decorate(form, headers);
        form.put("grant_type", "client_credentials");

        new TokenEndpointClient(config()).requestToken(tokenEndpoint(uriBuilder), form, headers);

        RecordedRequest request = server.takeRequest();
        String body = request.getBody() == null ? "" : request.getBody().utf8();
        String encodedSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        assertAll("wire request",
                () -> assertNull(request.getHeaders().get("Authorization"),
                        "client_secret_post must not send an Authorization header"),
                () -> assertTrue(body.contains("client_id="), "client_id must be in the form body"),
                () -> assertTrue(body.contains("client_secret=" + encodedSecret),
                        "client_secret must be form-encoded in the body"),
                () -> assertFalse(request.getTarget().contains(clientSecret),
                        "secret must never appear in the request URL"));
    }

    @Test
    @DisplayName("client_secret_post should reject null constructor arguments")
    void postShouldRejectNullArguments() {
        String secret = Generators.letterStrings(8, 20).next();
        String id = Generators.letterStrings(5, 12).next();
        assertAll("null rejection",
                () -> assertThrows(NullPointerException.class, () -> new ClientSecretPostAuth(null, secret)),
                () -> assertThrows(NullPointerException.class, () -> new ClientSecretPostAuth(id, null)));
    }
}

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

import de.cuioss.test.mockwebserver.dispatcher.CombinedDispatcher;
import mockwebserver3.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke tests for the extended IdP endpoint dispatchers (token / userinfo / revocation /
 * introspection / end-session / PAR), exercising both the default and an adversarial mode of
 * each against a real {@link MockWebServer}. Confirms the {@code generators} artifact's OP
 * simulation behaves as documented in {@code doc/commons/specification/transport.adoc}.
 */
@DisplayName("Extended IdP endpoint dispatchers")
class EndpointDispatchersTest {

    private final TokenDispatcher token = new TokenDispatcher();
    private final UserInfoDispatcher userInfo = new UserInfoDispatcher();
    private final RevocationDispatcher revocation = new RevocationDispatcher();
    private final IntrospectionDispatcher introspection = new IntrospectionDispatcher();
    private final EndSessionDispatcher endSession = new EndSessionDispatcher();
    private final ParDispatcher par = new ParDispatcher();

    private MockWebServer server;
    private HttpClient client;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.setDispatcher(new CombinedDispatcher(
                token, userInfo, revocation, introspection, endSession, par));
        server.start();
        client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    private URI uri(String path) {
        return server.url(path).uri();
    }

    private HttpResponse<String> get(String path) throws IOException, InterruptedException {
        return client.send(HttpRequest.newBuilder(uri(path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path) throws IOException, InterruptedException {
        return client.send(HttpRequest.newBuilder(uri(path))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    @DisplayName("Token endpoint: default grant and RFC 6749 §5.2 error")
    void tokenEndpoint() throws Exception {
        var ok = post(TokenDispatcher.LOCAL_PATH);
        assertEquals(200, ok.statusCode());
        assertTrue(ok.body().contains("access_token"));

        token.returnOAuthError();
        var err = post(TokenDispatcher.LOCAL_PATH);
        assertEquals(400, err.statusCode());
        assertTrue(err.body().contains("invalid_grant"));

        token.returnOversizedBody();
        var big = post(TokenDispatcher.LOCAL_PATH);
        assertEquals(200, big.statusCode());
        assertTrue(big.body().length() > 100_000);

        token.assertCallsAnswered(3);
    }

    @Test
    @DisplayName("UserInfo endpoint: default, sub mismatch and invalid_token")
    void userInfoEndpoint() throws Exception {
        var ok = get(UserInfoDispatcher.LOCAL_PATH);
        assertEquals(200, ok.statusCode());
        assertTrue(ok.body().contains(UserInfoDispatcher.DEFAULT_SUBJECT));

        userInfo.returnSubMismatch();
        var mismatch = get(UserInfoDispatcher.LOCAL_PATH);
        assertEquals(200, mismatch.statusCode());
        assertFalse(mismatch.body().contains("\"sub\": \"" + UserInfoDispatcher.DEFAULT_SUBJECT + "\""));

        userInfo.returnError();
        var err = get(UserInfoDispatcher.LOCAL_PATH);
        assertEquals(401, err.statusCode());

        userInfo.assertCallsAnswered(3);
    }

    @Test
    @DisplayName("Revocation endpoint: RFC 7009 success and error")
    void revocationEndpoint() throws Exception {
        var ok = post(RevocationDispatcher.LOCAL_PATH);
        assertEquals(200, ok.statusCode());
        assertTrue(ok.body().isEmpty());

        revocation.returnOAuthError();
        var err = post(RevocationDispatcher.LOCAL_PATH);
        assertEquals(400, err.statusCode());
        assertTrue(err.body().contains("unsupported_token_type"));

        revocation.assertCallsAnswered(2);
    }

    @Test
    @DisplayName("Introspection endpoint: active and inactive")
    void introspectionEndpoint() throws Exception {
        var active = post(IntrospectionDispatcher.LOCAL_PATH);
        assertEquals(200, active.statusCode());
        assertTrue(active.body().contains("\"active\": true"));

        introspection.returnInactive();
        var inactive = post(IntrospectionDispatcher.LOCAL_PATH);
        assertEquals(200, inactive.statusCode());
        assertTrue(inactive.body().contains("\"active\":false"));

        introspection.assertCallsAnswered(2);
    }

    @Test
    @DisplayName("End-session endpoint: registered redirect and open-redirect")
    void endSessionEndpoint() throws Exception {
        var ok = get(EndSessionDispatcher.LOCAL_PATH);
        assertEquals(302, ok.statusCode());
        assertEquals(EndSessionDispatcher.REGISTERED_REDIRECT, ok.headers().firstValue("Location").orElseThrow());

        endSession.returnOpenRedirect();
        var open = get(EndSessionDispatcher.LOCAL_PATH);
        assertEquals(302, open.statusCode());
        assertEquals(EndSessionDispatcher.ATTACKER_REDIRECT, open.headers().firstValue("Location").orElseThrow());

        endSession.assertCallsAnswered(2);
    }

    @Test
    @DisplayName("PAR endpoint: RFC 9126 request_uri and error")
    void parEndpoint() throws Exception {
        var ok = post(ParDispatcher.LOCAL_PATH);
        assertEquals(201, ok.statusCode());
        assertTrue(ok.body().contains("request_uri"));

        par.returnOAuthError();
        var err = post(ParDispatcher.LOCAL_PATH);
        assertEquals(400, err.statusCode());
        assertTrue(err.body().contains("invalid_request"));

        par.assertCallsAnswered(2);
    }
}

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
package de.cuioss.sheriff.token.integration.client;

import de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth;
import de.cuioss.sheriff.token.client.auth.ClientSecretPostAuth;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Increment-3 client-authentication spec against the real Keycloak container ({@code CLIENT-4}).
 * <p>
 * Exercises the production shared-secret client-authentication strategies
 * ({@link ClientSecretBasicAuth} and {@link ClientSecretPostAuth}) end-to-end against the
 * integration realm's token endpoint, confirming Keycloak accepts each wire form and issues a token.
 * The container uses a self-signed certificate, so the exchange runs against a trust-all TLS context
 * (integration-test scope only), mirroring {@link BaseIntegrationTest}'s relaxed HTTPS posture.
 */
@DisplayName("Client authentication against real Keycloak")
class ClientAuthSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(ClientAuthSpecIT.class);

    private static final String TOKEN_ENDPOINT =
            "https://localhost:1443/realms/integration/protocol/openid-connect/token";
    private static final String CLIENT_ID = "integration-client";
    private static final String CLIENT_SECRET = "integration-secret";

    @Test
    @DisplayName("Should authenticate with client_secret_basic (Authorization header) and issue a token")
    void shouldAuthenticateWithClientSecretBasic() throws Exception {
        var auth = new ClientSecretBasicAuth(CLIENT_ID, CLIENT_SECRET);
        Map<String, String> form = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        form.put("grant_type", "client_credentials");
        auth.decorate(form, headers);

        HttpResponse<String> response = send(form, headers);
        LOGGER.debug("client_secret_basic token response: %s", response.body());

        assertAll("client_secret_basic token response",
                () -> assertEquals(200, response.statusCode(), "Keycloak must accept client_secret_basic"),
                () -> assertTrue(response.body().contains("access_token"), "response carries an access_token"));
    }

    @Test
    @DisplayName("Should authenticate with client_secret_post (form body) and issue a token")
    void shouldAuthenticateWithClientSecretPost() throws Exception {
        var auth = new ClientSecretPostAuth(CLIENT_ID, CLIENT_SECRET);
        Map<String, String> form = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        form.put("grant_type", "client_credentials");
        auth.decorate(form, headers);

        HttpResponse<String> response = send(form, headers);
        LOGGER.debug("client_secret_post token response: %s", response.body());

        assertAll("client_secret_post token response",
                () -> assertEquals(200, response.statusCode(), "Keycloak must accept client_secret_post"),
                () -> assertTrue(response.body().contains("access_token"), "response carries an access_token"));
    }

    private static HttpResponse<String> send(Map<String, String> form, Map<String, String> headers) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(encodeForm(form)));
        headers.forEach(builder::header);
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String encodeForm(Map<String, String> form) {
        StringJoiner joiner = new StringJoiner("&");
        form.forEach((key, value) -> joiner.add(URLEncoder.encode(key, StandardCharsets.UTF_8)
                + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)));
        return joiner.toString();
    }

    private static SSLContext trustAllContext() throws Exception {
        TrustManager[] trustAll = {new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // integration-test trust-all
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // integration-test trust-all
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new SecureRandom());
        return context;
    }
}

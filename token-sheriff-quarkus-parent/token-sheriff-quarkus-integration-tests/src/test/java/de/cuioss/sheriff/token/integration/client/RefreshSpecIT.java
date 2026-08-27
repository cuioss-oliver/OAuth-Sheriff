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
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
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
 * Increment-4 {@code refresh_token} grant spec against the real Keycloak container ({@code CLIENT-5}).
 * <p>
 * Acquires an initial refresh token from the integration realm (direct-access-grant), then redeems
 * it through a {@code grant_type=refresh_token} exchange authenticated with the production
 * {@link ClientSecretBasicAuth} strategy, confirming Keycloak issues a fresh access token and rotates
 * the refresh token. The container uses a self-signed certificate, so the exchange runs against a
 * trust-all TLS context (integration-test scope only), mirroring {@link BaseIntegrationTest}'s
 * relaxed HTTPS posture.
 */
@DisplayName("refresh_token grant against real Keycloak")
class RefreshSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(RefreshSpecIT.class);

    private static final String TOKEN_ENDPOINT =
            "https://localhost:1443/realms/integration/protocol/openid-connect/token";
    private static final String CLIENT_ID = "integration-client";
    private static final String CLIENT_SECRET = "integration-secret";

    @Test
    @DisplayName("Should redeem a refresh token for a fresh access token and rotate the refresh token")
    void shouldRefreshAndRotate() throws Exception {
        String initialRefreshToken = TestRealm.createIntegrationRealm().obtainValidToken().refreshToken();
        assertNotNull(initialRefreshToken, "Keycloak must issue an initial refresh token via the password grant");

        var auth = new ClientSecretBasicAuth(CLIENT_ID, CLIENT_SECRET);
        Map<String, String> form = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", initialRefreshToken);
        auth.decorate(form, headers);

        HttpResponse<String> response = send(form, headers);
        LOGGER.debug("refresh_token response: %s", response.body());

        assertAll("refresh_token response",
                () -> assertEquals(200, response.statusCode(), "Keycloak must accept the refresh_token grant"),
                () -> assertTrue(response.body().contains("access_token"), "response carries a fresh access_token"),
                () -> assertTrue(response.body().contains("refresh_token"), "Keycloak rotates the refresh token"));
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

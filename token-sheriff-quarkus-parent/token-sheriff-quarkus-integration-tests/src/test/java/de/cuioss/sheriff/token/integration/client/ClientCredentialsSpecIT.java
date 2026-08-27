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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Increment-2 {@code client_credentials} spec against the real Keycloak container ({@code CLIENT-3}).
 * <p>
 * Verifies that the integration realm issues an access token for the {@code client_credentials}
 * grant. The container uses a self-signed certificate, so the exchange runs against a trust-all TLS
 * context (integration-test scope only), mirroring {@link BaseIntegrationTest}'s relaxed HTTPS
 * posture.
 */
@DisplayName("client_credentials grant against real Keycloak")
class ClientCredentialsSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(ClientCredentialsSpecIT.class);

    private static final String TOKEN_ENDPOINT =
            "https://localhost:1443/realms/integration/protocol/openid-connect/token";
    private static final String CLIENT_ID = "integration-client";
    private static final String CLIENT_SECRET = "integration-secret";

    @Test
    @DisplayName("Should issue an access token for the client_credentials grant")
    void shouldIssueClientCredentialsToken() throws Exception {
        String form = param("grant_type", "client_credentials")
                + "&" + param("client_id", CLIENT_ID)
                + "&" + param("client_secret", CLIENT_SECRET);

        HttpClient client = HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        LOGGER.debug("client_credentials token response: %s", response.body());

        assertAll("client_credentials token response",
                () -> assertEquals(200, response.statusCode(), "token endpoint should issue a token"),
                () -> assertTrue(response.body().contains("access_token"), "response carries an access_token"));
    }

    private static String param(String key, String value) {
        return URLEncoder.encode(key, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8);
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

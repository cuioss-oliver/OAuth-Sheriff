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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Increment-9 RFC 7009 revocation spec against the real Keycloak container ({@code CLIENT-13}).
 * <p>
 * Acquires a refresh token from the integration realm, then revokes it at the revocation endpoint
 * authenticated with the production {@link ClientSecretBasicAuth} strategy, confirming Keycloak
 * returns {@code 200} for the revocation (RFC 7009 §2.2). The container uses a self-signed
 * certificate, so the exchange runs against a trust-all TLS context (integration-test scope only),
 * mirroring {@link BaseIntegrationTest}.
 */
@DisplayName("RFC 7009 revocation against real Keycloak")
class RevocationSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(RevocationSpecIT.class);

    private static final String REVOCATION_ENDPOINT =
            "https://localhost:1443/realms/integration/protocol/openid-connect/revoke";
    private static final String CLIENT_ID = "integration-client";
    private static final String CLIENT_SECRET = "integration-secret";

    @Test
    @DisplayName("Should revoke a refresh token and receive HTTP 200 from the revocation endpoint")
    void shouldRevokeRefreshToken() throws Exception {
        String refreshToken = TestRealm.createIntegrationRealm().obtainValidToken().refreshToken();
        assertNotNull(refreshToken, "Keycloak must issue a refresh token to revoke");

        Map<String, String> form = new HashMap<>();
        form.put("token", refreshToken);
        form.put("token_type_hint", "refresh_token");
        Map<String, String> headers = new HashMap<>();
        new ClientSecretBasicAuth(CLIENT_ID, CLIENT_SECRET).decorate(form, headers);

        HttpResponse<String> response = send(form, headers);
        LOGGER.debug("revocation response status=%s", response.statusCode());

        assertEquals(200, response.statusCode(),
                "RFC 7009 revocation returns 200 for a successful revocation");
    }

    private static HttpResponse<String> send(Map<String, String> form, Map<String, String> headers) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(REVOCATION_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
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

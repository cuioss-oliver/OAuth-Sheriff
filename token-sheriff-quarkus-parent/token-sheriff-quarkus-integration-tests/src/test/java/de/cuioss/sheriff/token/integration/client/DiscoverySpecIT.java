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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Increment-1 discovery spec against the real Keycloak container ({@code CLIENT-14}).
 * <p>
 * Verifies that the integration realm serves a well-formed OpenID Connect discovery document with
 * the endpoints and PKCE {@code S256} capability the client engine consumes. The container uses a
 * self-signed certificate, so the request runs against a trust-all TLS context (integration-test
 * scope only), mirroring {@link BaseIntegrationTest}'s relaxed HTTPS posture.
 */
@DisplayName("OIDC discovery against real Keycloak")
class DiscoverySpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(DiscoverySpecIT.class);

    // The discovery document is fetched over the host-mapped external base (reachable from the CI
    // runner), but Keycloak advertises the issuer under the realm frontendUrl (Docker-internal base).
    private static final String WELL_KNOWN =
            KeycloakUrlSupport.EXTERNAL_BASE + "/realms/integration/.well-known/openid-configuration";
    private static final String EXPECTED_ISSUER = KeycloakUrlSupport.INTERNAL_ISSUER;

    @Test
    @DisplayName("Should serve a discovery document with the expected endpoints and S256 support")
    void shouldServeDiscoveryDocument() throws Exception {
        var response = fetch(WELL_KNOWN);

        assertEquals(200, response.statusCode(), "discovery document should be served");
        String body = response.body();
        LOGGER.debug("Resolved discovery document: %s", body);

        assertAll("discovery document contents",
                () -> assertTrue(body.contains("\"issuer\""), "issuer present"),
                () -> assertTrue(body.contains(EXPECTED_ISSUER),
                        "issuer matches the integration realm frontendUrl (" + EXPECTED_ISSUER + ")"),
                () -> assertTrue(body.contains("\"token_endpoint\""), "token_endpoint present"),
                () -> assertTrue(body.contains("\"authorization_endpoint\""), "authorization_endpoint present"),
                () -> assertTrue(body.contains("\"jwks_uri\""), "jwks_uri present"),
                () -> assertTrue(body.contains("S256"), "PKCE S256 advertised (CLIENT-2 groundwork)"));
    }

    private static HttpResponse<String> fetch(String url) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", "application/json")
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
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

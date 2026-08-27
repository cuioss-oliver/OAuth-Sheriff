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
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Increment-6 RFC 9126 pushed-authorization-request (PAR) spec against the real Keycloak container
 * ({@code CLIENT-10}).
 * <p>
 * Capability-gated: the test resolves the {@code pushed_authorization_request_endpoint} from the
 * Keycloak discovery document and skips gracefully when the realm does not advertise one. When PAR is
 * advertised, it pushes an authorization request over the authenticated back channel
 * ({@code client_secret_basic}) and asserts Keycloak returns an opaque single-use {@code request_uri}
 * — proving the raw authorization parameters never need to traverse the front channel
 * ({@code T-PARAM-INTEGRITY}). The container uses a self-signed certificate, so the exchange runs
 * against a trust-all TLS context (integration-test scope only), mirroring
 * {@link BaseIntegrationTest}'s relaxed HTTPS posture.
 */
@DisplayName("RFC 9126 pushed authorization requests against real Keycloak")
class ParSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(ParSpecIT.class);

    private static final String ISSUER = "https://localhost:1443/realms/integration";
    private static final String WELL_KNOWN = ISSUER + "/.well-known/openid-configuration";
    private static final String CLIENT_ID = "integration-client";
    private static final String CLIENT_SECRET = "integration-secret";
    private static final String REDIRECT_URI = "https://localhost/callback";

    @Test
    @DisplayName("Should push an authorization request and receive an opaque request_uri")
    void shouldPushAuthorizationRequest() throws Exception {
        String discovery = discoveryDocument();
        String advertisedParEndpoint = extractStringField(discovery, "pushed_authorization_request_endpoint");
        assumeTrue(advertisedParEndpoint != null,
                "Keycloak realm does not advertise a PAR endpoint — skipping capability-gated PAR spec");
        // Keycloak advertises the PAR endpoint under its realm frontendUrl (https://keycloak:8443),
        // which is unreachable from the CI runner. Rewrite it to the host-mapped external base.
        String parEndpoint = KeycloakUrlSupport.toExternal(advertisedParEndpoint);
        LOGGER.debug("Keycloak PAR endpoint: advertised=%s, reachable=%s", advertisedParEndpoint, parEndpoint);

        String basic = Base64.getEncoder().encodeToString(
                (CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        String form = param("response_type", "code")
                + "&" + param("redirect_uri", REDIRECT_URI)
                + "&" + param("scope", "openid")
                + "&" + param("state", "it-state")
                + "&" + param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                + "&" + param("code_challenge_method", "S256");

        HttpClient client = HttpClient.newBuilder().sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5)).build();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(parEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("Authorization", "Basic " + basic)
                .POST(HttpRequest.BodyPublishers.ofString(form)).build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        LOGGER.debug("PAR response (%s): %s", response.statusCode(), response.body());

        assertAll("PAR response",
                () -> assertEquals(201, response.statusCode(), "Keycloak must accept the PAR push with HTTP 201"),
                () -> assertTrue(response.body().contains("request_uri"),
                        "the PAR response carries an opaque request_uri"));
    }

    private String discoveryDocument() throws Exception {
        HttpClient client = HttpClient.newBuilder().sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5)).build();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(WELL_KNOWN))
                .header("Accept", "application/json").GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    private static String extractStringField(String json, String field) {
        int key = json.indexOf("\"" + field + "\"");
        if (key < 0) {
            return null;
        }
        int colon = json.indexOf(':', key);
        int firstQuote = json.indexOf('"', colon + 1);
        int secondQuote = json.indexOf('"', firstQuote + 1);
        return json.substring(firstQuote + 1, secondQuote);
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

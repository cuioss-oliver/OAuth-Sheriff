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

import de.cuioss.sheriff.token.client.dpop.DpopProofGenerator;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Increment-8 DPoP sender-constraining spec against the real Keycloak container ({@code CLIENT-11}).
 * <p>
 * Drives the <em>production</em> {@link DpopProofGenerator}: it builds a DPoP proof for the token
 * request, POSTs a direct-access grant to the DPoP-enabled {@code dpop-client} carrying that proof,
 * and confirms Keycloak issues a token bound to the proof key via {@code cnf.jkt} — the jkt the
 * generator advertises. The container uses a self-signed certificate, so the exchange runs against a
 * trust-all TLS context (integration-test scope only), mirroring {@link BaseIntegrationTest}.
 */
@DisplayName("DPoP sender-constrained token against real Keycloak")
class DpopBoundSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(DpopBoundSpecIT.class);

    private static final String TOKEN_ENDPOINT =
            "https://localhost:1443/realms/integration/protocol/openid-connect/token";
    private static final String DPOP_CLIENT_ID = "dpop-client";
    private static final String DPOP_CLIENT_SECRET = "dpop-secret";
    private static final String USERNAME = "integration-user";
    private static final String PASSWORD = "integration-password";

    @Test
    @DisplayName("Should obtain a DPoP-bound token whose cnf.jkt matches the production proof key")
    void shouldObtainDpopBoundToken() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        var proofGenerator = new DpopProofGenerator(keyPair, "RS256");
        String proof = proofGenerator.generateProof("POST", TOKEN_ENDPOINT);

        Map<String, String> form = new HashMap<>();
        form.put("grant_type", "password");
        form.put("client_id", DPOP_CLIENT_ID);
        form.put("client_secret", DPOP_CLIENT_SECRET);
        form.put("username", USERNAME);
        form.put("password", PASSWORD);
        form.put("scope", "openid");
        Map<String, String> headers = new HashMap<>();
        headers.put("DPoP", proof);

        HttpResponse<String> response = send(form, headers);
        LOGGER.debug("DPoP token response status=%s", response.statusCode());

        assertEquals(200, response.statusCode(), "Keycloak must accept the production DPoP proof");
        String accessToken = extractAccessToken(response.body());
        String claims = decodePayload(accessToken);
        assertAll("DPoP binding",
                () -> assertTrue(claims.contains("\"cnf\""), "the issued token carries a cnf confirmation claim"),
                () -> assertTrue(claims.contains("\"jkt\":\"" + proofGenerator.jkt() + "\""),
                        "cnf.jkt must equal the production proof-key thumbprint"));
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

    private static String extractAccessToken(String body) {
        String marker = "\"access_token\":\"";
        int start = body.indexOf(marker) + marker.length();
        int end = body.indexOf('"', start);
        return body.substring(start, end);
    }

    private static String decodePayload(String jwt) {
        String[] segments = jwt.split("\\.");
        return new String(Base64.getUrlDecoder().decode(segments[1]), StandardCharsets.UTF_8);
    }

    private static String encodeForm(Map<String, String> form) {
        StringJoiner joiner = new StringJoiner("&");
        form.forEach((key, value) -> joiner.add(URLEncoder.encode(key, StandardCharsets.UTF_8)
                + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)));
        return joiner.toString();
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
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
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, trustAll, new SecureRandom());
        return context;
    }
}

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

import de.cuioss.sheriff.token.client.flow.CallbackParameters;
import de.cuioss.sheriff.token.client.flow.IssValidator;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
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
 * Increment-6 authorization-server mix-up spec against the real Keycloak container ({@code CLIENT-8}).
 * <p>
 * Resolves the real issuer identifier the Keycloak integration realm advertises in its discovery
 * document, then exercises the production {@link IssValidator}: a callback stamped with Keycloak's own
 * {@code iss} is accepted, while a callback stamped with a foreign authorization server's {@code iss}
 * (a second, distinct realm on the same Keycloak) is rejected fail-closed before any code redemption.
 * The container uses a self-signed certificate, so discovery runs against a trust-all TLS context
 * (integration-test scope only), mirroring {@link BaseIntegrationTest}'s relaxed HTTPS posture.
 */
@DisplayName("RFC 9207 mix-up defence against real Keycloak issuers")
class MixUpSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(MixUpSpecIT.class);

    private static final String INTEGRATION_ISSUER = "https://localhost:1443/realms/integration";
    private static final String FOREIGN_ISSUER = "https://localhost:1443/realms/benchmark";

    private final IssValidator validator = new IssValidator();

    @Test
    @DisplayName("Should accept Keycloak's own iss and reject a foreign realm's iss")
    void shouldEnforceIssuerBinding() throws Exception {
        String advertisedIssuer = discoveredIssuer(INTEGRATION_ISSUER);
        assertNotNull(advertisedIssuer, "Keycloak must advertise its issuer in the discovery document");
        LOGGER.debug("Keycloak integration realm issuer: %s", advertisedIssuer);

        var honestCallback = new CallbackParameters("code-abc", "state-xyz", null, null, advertisedIssuer);
        var mixedUpCallback = new CallbackParameters("code-abc", "state-xyz", null, null, FOREIGN_ISSUER);

        assertDoesNotThrow(() -> validator.validate(advertisedIssuer, honestCallback, true),
                "a callback stamped with the initiating realm's iss is accepted");
        assertThrows(ClientProtocolException.class,
                () -> validator.validate(advertisedIssuer, mixedUpCallback, true),
                "a callback stamped with a foreign realm's iss is rejected (mix-up defence)");
    }

    @Test
    @DisplayName("Should confirm the two realms advertise distinct issuer identifiers")
    void shouldHaveDistinctIssuers() throws Exception {
        String integration = discoveredIssuer(INTEGRATION_ISSUER);
        String foreign = discoveredIssuer(FOREIGN_ISSUER);

        assertTrue(integration != null && foreign != null && !integration.equals(foreign),
                "the integration and benchmark realms must present distinct issuer identifiers");
    }

    private String discoveredIssuer(String issuerBase) throws Exception {
        HttpClient client = HttpClient.newBuilder().sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5)).build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(issuerBase + "/.well-known/openid-configuration"))
                .header("Accept", "application/json").GET().build();
        String body = client.send(request, HttpResponse.BodyHandlers.ofString()).body();
        return extractIssuer(body);
    }

    private static String extractIssuer(String discoveryJson) {
        int key = discoveryJson.indexOf("\"issuer\"");
        if (key < 0) {
            return null;
        }
        int colon = discoveryJson.indexOf(':', key);
        int firstQuote = discoveryJson.indexOf('"', colon + 1);
        int secondQuote = discoveryJson.indexOf('"', firstQuote + 1);
        return discoveryJson.substring(firstQuote + 1, secondQuote);
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

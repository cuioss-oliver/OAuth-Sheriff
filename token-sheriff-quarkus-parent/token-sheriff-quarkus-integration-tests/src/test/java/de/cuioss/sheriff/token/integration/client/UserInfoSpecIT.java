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

import de.cuioss.sheriff.token.client.token.SubBindingValidator;
import de.cuioss.sheriff.token.client.token.UserInfoResponse;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Increment-7 userinfo + {@code sub}-binding spec against the real Keycloak container
 * ({@code CLIENT-16}).
 * <p>
 * Obtains a real access token and ID token from the Keycloak integration realm, fetches the userinfo
 * document with that access token, and confirms Keycloak's userinfo {@code sub} equals the ID token
 * {@code sub}. The production {@link SubBindingValidator} then accepts the genuine pair and rejects a
 * forged foreign {@code sub}, proving the OIDC Core §5.3.2 binding against a real provider. The
 * container uses a self-signed certificate, so the exchange runs against a trust-all TLS context
 * (integration-test scope only), mirroring {@link BaseIntegrationTest}'s relaxed HTTPS posture.
 */
@DisplayName("userinfo + sub binding against real Keycloak")
class UserInfoSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(UserInfoSpecIT.class);

    private static final String USERINFO_ENDPOINT =
            "https://localhost:1443/realms/integration/protocol/openid-connect/userinfo";

    private final SubBindingValidator subBindingValidator = new SubBindingValidator();

    @Test
    @DisplayName("Should bind Keycloak's userinfo sub to the ID token sub and reject a foreign sub")
    void shouldBindUserInfoSubToIdToken() throws Exception {
        TestRealm.TokenResponse tokens = TestRealm.createIntegrationRealm().obtainValidToken();
        assertNotNull(tokens.accessToken(), "Keycloak must issue an access token");
        assertNotNull(tokens.idToken(), "Keycloak must issue an ID token for the openid scope");

        String userInfoSub = fetchUserInfoSub(tokens.accessToken());
        String idTokenSub = subjectOf(tokens.idToken());
        LOGGER.debug("Keycloak userinfo sub=%s, id_token sub=%s", userInfoSub, idTokenSub);

        assertEquals(idTokenSub, userInfoSub, "Keycloak's userinfo sub must equal the ID token sub");

        var boundUserInfo = new UserInfoResponse();
        boundUserInfo.sub = userInfoSub;
        var foreignUserInfo = new UserInfoResponse();
        foreignUserInfo.sub = "attacker-subject";

        assertAll("production sub binding against real identities",
                () -> assertDoesNotThrow(() -> subBindingValidator.validate(idTokenSub, boundUserInfo),
                        "the genuine userinfo sub is bound to the ID token"),
                () -> assertThrows(IllegalStateException.class,
                        () -> subBindingValidator.validate(idTokenSub, foreignUserInfo),
                        "a forged foreign userinfo sub is rejected"));
    }

    private String fetchUserInfoSub(String accessToken) throws Exception {
        HttpClient client = HttpClient.newBuilder().sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5)).build();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(USERINFO_ENDPOINT))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json").GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "Keycloak must serve the userinfo document");
        return extractStringField(response.body(), "sub");
    }

    private static String subjectOf(String jwt) {
        String[] segments = jwt.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(segments[1]), StandardCharsets.UTF_8);
        return extractStringField(payload, "sub");
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

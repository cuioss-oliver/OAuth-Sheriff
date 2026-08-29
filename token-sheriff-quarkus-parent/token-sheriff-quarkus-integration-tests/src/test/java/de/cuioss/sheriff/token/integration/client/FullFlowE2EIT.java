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

import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.logout.EndSessionFlow;
import de.cuioss.sheriff.token.client.logout.PostLogoutRedirectValidator;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.SubBindingValidator;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
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
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Increment-11 full-flow end-to-end spec against the real Keycloak container — the complete
 * confidential-client lifecycle wired together: login &rarr; token &rarr; userinfo &rarr; refresh
 * &rarr; logout ({@code CLIENT-1..22}, {@code closes PR batch 2}).
 * <p>
 * This is the in-repo E2E proof that the whole engine composes against a genuine provider, not a mock:
 * <ol>
 *     <li><strong>login &rarr; token</strong> — the direct-access grant yields a real access token, ID
 *         token, and refresh token from the integration realm;</li>
 *     <li><strong>userinfo</strong> — the userinfo document's {@code sub} is bound to the ID token
 *         {@code sub} through the production {@link SubBindingValidator}, and a forged foreign
 *         {@code sub} is rejected (OIDC Core §5.3.2);</li>
 *     <li><strong>refresh</strong> — the refresh token is redeemed through the production
 *         {@link de.cuioss.sheriff.token.client.flow.RefreshFlow}, and Keycloak issues a fresh access
 *         token and rotates the refresh token (RFC 6749 §6, OAuth 2.0 Security BCP);</li>
 *     <li><strong>logout</strong> — the production {@link EndSessionFlow} builds an RP-initiated logout
 *         with the {@code id_token_hint}, an exact-matched {@code post_logout_redirect_uri}, and a
 *         session-bound {@code state}, which Keycloak accepts (RFC RP-Initiated Logout,
 *         {@code CLIENT-13}).</li>
 * </ol>
 * The container uses a self-signed certificate, so every exchange runs against a trust-all TLS context
 * (integration-test scope only), mirroring {@link BaseIntegrationTest}'s relaxed HTTPS posture.
 */
@DisplayName("Full confidential-client flow against real Keycloak")
class FullFlowE2EIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(FullFlowE2EIT.class);

    private static final String BASE = "https://localhost:1443/realms/integration/protocol/openid-connect";
    private static final String USERINFO_ENDPOINT = BASE + "/userinfo";
    private static final String END_SESSION_ENDPOINT = BASE + "/logout";
    private static final String POST_LOGOUT_REDIRECT_URI = "https://localhost/callback";
    private static final String CLIENT_ID = "integration-client";
    private static final String CLIENT_SECRET = "integration-secret";

    @Test
    @DisplayName("Should run login -> token -> userinfo -> refresh -> logout end-to-end")
    void shouldRunFullConfidentialClientFlow() throws Exception {
        // 1. login -> token (direct-access grant)
        TestRealm.TokenResponse tokens = TestRealm.createIntegrationRealm().obtainValidToken();
        assertAll("login yields a full token bundle",
                () -> assertNotNull(tokens.accessToken(), "Keycloak must issue an access token"),
                () -> assertNotNull(tokens.idToken(), "Keycloak must issue an ID token for the openid scope"),
                () -> assertNotNull(tokens.refreshToken(), "Keycloak must issue a refresh token"));

        // 2. userinfo -> sub binding through the production validator
        String userInfoSub = fetchUserInfoSub(tokens.accessToken());
        String idTokenSub = subjectOf(tokens.idToken());
        LOGGER.debug("userinfo sub=%s, id_token sub=%s", userInfoSub, idTokenSub);
        assertEquals(idTokenSub, userInfoSub, "Keycloak's userinfo sub must equal the ID token sub");

        SubBindingValidator subBindingValidator = new SubBindingValidator();
        UserInfoResponse boundUserInfo = new UserInfoResponse();
        boundUserInfo.sub = userInfoSub;
        UserInfoResponse foreignUserInfo = new UserInfoResponse();
        foreignUserInfo.sub = "attacker-subject";
        assertAll("production sub binding against real identities",
                () -> assertDoesNotThrow(() -> subBindingValidator.validate(idTokenSub, boundUserInfo),
                        "the genuine userinfo sub is bound to the ID token"),
                () -> assertThrows(IllegalStateException.class,
                        () -> subBindingValidator.validate(idTokenSub, foreignUserInfo),
                        "a forged foreign userinfo sub is rejected"));

        // 3. refresh -> fresh access token + rotated refresh token through the production RefreshFlow
        ClientConfiguration configuration = RefreshEngineSupport.clientConfiguration(CLIENT_ID, CLIENT_SECRET);
        TokenValidationBridge accessBridge =
                RefreshEngineSupport.accessTokenBridge(RefreshEngineSupport.tokenValidator());
        RefreshFlow refreshFlow = RefreshEngineSupport.refreshFlow(configuration, accessBridge);

        RotationResult rotation =
                refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), tokens.refreshToken());
        LOGGER.debug("refresh rotated=%s", rotation.rotated());
        assertAll("refresh_token grant through the production RefreshFlow",
                () -> assertTrue(rotation.rotated(), "Keycloak must rotate the refresh token on redemption"),
                () -> assertNotEquals(tokens.refreshToken(), rotation.refreshToken(),
                        "the rotated refresh token differs from the original"),
                () -> assertFalse(rotation.accessToken().getRawToken().isBlank(),
                        "the rotation carries a fresh, non-blank access token"));

        // 4. logout -> RP-initiated end-session through the production flow
        EndSessionFlow endSessionFlow =
                new EndSessionFlow(new PostLogoutRedirectValidator(Set.of(POST_LOGOUT_REDIRECT_URI)));
        String state = UUID.randomUUID().toString();
        String logoutUrl = endSessionFlow.buildLogoutRedirect(
                END_SESSION_ENDPOINT, tokens.idToken(), POST_LOGOUT_REDIRECT_URI, state);

        HttpResponse<String> logoutResponse = get(logoutUrl);
        LOGGER.debug("logout response status=%s", logoutResponse.statusCode());
        assertTrue(logoutResponse.statusCode() == 200 || logoutResponse.statusCode() == 302,
                "Keycloak must accept the RP-initiated logout (200 confirmation or 302 redirect), got "
                        + logoutResponse.statusCode());
    }

    private static String fetchUserInfoSub(String accessToken) throws Exception {
        HttpResponse<String> response = client().send(HttpRequest.newBuilder()
                .uri(URI.create(USERINFO_ENDPOINT))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "Keycloak must serve the userinfo document");
        return extractStringField(response.body(), "sub");
    }

    private static HttpResponse<String> get(String url) throws Exception {
        return HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build()
                .send(HttpRequest.newBuilder().uri(URI.create(url)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
    }

    private static HttpClient client() throws Exception {
        return HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5))
                .build();
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

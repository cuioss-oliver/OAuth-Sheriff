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

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.AuthorizationRequestBuilder;
import de.cuioss.sheriff.token.client.flow.CallbackHandler;
import de.cuioss.sheriff.token.client.flow.CallbackParameters;
import de.cuioss.sheriff.token.client.flow.FlowContext;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.CookieManager;
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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Increment-5 {@code authorization_code} + PKCE {@code S256} spec against the real Keycloak container
 * ({@code CLIENT-2}).
 * <p>
 * Drives a headless {@code authorization_code} flow end-to-end: the production
 * {@link AuthorizationRequestBuilder} composes the PKCE-protected authorization request, the test logs
 * the integration user in through Keycloak's login-actions endpoint to obtain a real authorization
 * code, the production {@link CallbackHandler} validates the redirect (CSRF {@code state} binding),
 * and the code is redeemed at the token endpoint with the PKCE {@code code_verifier}. Keycloak issues
 * an ID token only when the verifier matches the challenge, proving the PKCE binding end-to-end. The
 * container uses a self-signed certificate, so the exchange runs against a trust-all TLS context
 * (integration-test scope only), mirroring {@link BaseIntegrationTest}'s relaxed HTTPS posture.
 */
@DisplayName("authorization_code + PKCE S256 against real Keycloak")
class AuthCodePkceSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(AuthCodePkceSpecIT.class);

    private static final String ISSUER = "https://localhost:1443/realms/integration";
    private static final String WELL_KNOWN = ISSUER + "/.well-known/openid-configuration";
    private static final String AUTH_ENDPOINT = ISSUER + "/protocol/openid-connect/auth";
    private static final String TOKEN_ENDPOINT = ISSUER + "/protocol/openid-connect/token";
    private static final String CLIENT_ID = "integration-client";
    private static final String CLIENT_SECRET = "integration-secret";
    private static final String REDIRECT_URI = "https://localhost/callback";
    private static final String USERNAME = "integration-user";
    private static final String PASSWORD = "integration-password";

    private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+)\"");

    @Test
    @DisplayName("Should complete a headless authorization_code + PKCE exchange and receive an ID token")
    void shouldCompleteAuthCodePkceExchange() throws Exception {
        assertTrue(discoveryDocument().contains("S256"),
                "Keycloak must advertise PKCE S256 in its discovery document (CLIENT-2 precondition)");

        var configuration = ClientConfiguration.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .allowInsecureHttp(false)
                .build();
        var metadata = new ProviderMetadata();
        metadata.issuer = ISSUER;
        metadata.authorizationEndpoint = AUTH_ENDPOINT;
        metadata.codeChallengeMethodsSupported = List.of("S256");

        FlowContext context = FlowContext.create(REDIRECT_URI);
        String authorizationUrl = new AuthorizationRequestBuilder().build(configuration, metadata, context);

        HttpClient client = HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        String callbackQuery = login(client, authorizationUrl);
        CallbackParameters callback = CallbackParameters.parse(callbackQuery);

        String code = new CallbackHandler().handle(context, callback);
        assertNotNull(code, "the validated authorization code must be present after the callback");

        HttpResponse<String> tokenResponse = redeem(client, code, context.pkceChallenge().codeVerifier());
        LOGGER.debug("authorization_code token response: %s", tokenResponse.body());

        assertAll("authorization_code + PKCE token response",
                () -> assertEquals(200, tokenResponse.statusCode(),
                        "Keycloak must accept the code with the matching PKCE verifier"),
                () -> assertTrue(tokenResponse.body().contains("access_token"), "response carries an access_token"),
                () -> assertTrue(tokenResponse.body().contains("id_token"),
                        "the OIDC authorization_code exchange yields an id_token"));
    }

    @Test
    @DisplayName("Should be rejected when the code is redeemed with a mismatched PKCE verifier")
    void shouldRejectMismatchedVerifier() throws Exception {
        var configuration = ClientConfiguration.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .build();
        var metadata = new ProviderMetadata();
        metadata.issuer = ISSUER;
        metadata.authorizationEndpoint = AUTH_ENDPOINT;
        metadata.codeChallengeMethodsSupported = List.of("S256");

        FlowContext context = FlowContext.create(REDIRECT_URI);
        String authorizationUrl = new AuthorizationRequestBuilder().build(configuration, metadata, context);

        HttpClient client = HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        String callbackQuery = login(client, authorizationUrl);
        String code = new CallbackHandler().handle(context, CallbackParameters.parse(callbackQuery));

        String wrongVerifier = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(freshEntropy());
        HttpResponse<String> tokenResponse = redeem(client, code, wrongVerifier);

        assertEquals(400, tokenResponse.statusCode(),
                "Keycloak must reject a code redeemed with a PKCE verifier that does not match the challenge");
    }

    private String discoveryDocument() throws Exception {
        HttpClient client = HttpClient.newBuilder().sslContext(trustAllContext())
                .connectTimeout(Duration.ofSeconds(5)).build();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(WELL_KNOWN))
                .header("Accept", "application/json").GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    private String login(HttpClient client, String authorizationUrl) throws Exception {
        HttpRequest authRequest = HttpRequest.newBuilder().uri(URI.create(authorizationUrl))
                .header("Accept", "text/html").GET().build();
        HttpResponse<String> loginPage = client.send(authRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, loginPage.statusCode(), "Keycloak must serve the login form for the PKCE request");

        Matcher matcher = FORM_ACTION.matcher(loginPage.body());
        assertTrue(matcher.find(), "the Keycloak login page must expose a form action URL");
        // Keycloak builds the login-actions action URL from the realm frontendUrl
        // (https://keycloak:8443), which is unreachable from the CI runner. Rewrite it to the
        // host-mapped external base so the login POST reaches Keycloak (and keeps the localhost
        // session cookies valid).
        String actionUrl = KeycloakUrlSupport.toExternal(matcher.group(1).replace("&amp;", "&"));

        String form = param("username", USERNAME) + "&" + param("password", PASSWORD);
        HttpRequest loginRequest = HttpRequest.newBuilder().uri(URI.create(actionUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build();
        HttpResponse<String> loginResult = client.send(loginRequest, HttpResponse.BodyHandlers.ofString());

        // C1 emits response_mode=form_post on the authorization request, so a successful login no
        // longer 302-redirects with the code in the Location query. Keycloak instead returns HTTP 200
        // with an auto-submitting HTML form whose action is the registered redirect_uri and whose
        // hidden inputs carry the authorization-response parameters (code, state, and the RFC 9207
        // iss). Reduce that form back to the callback query string the caller expects.
        assertEquals(200, loginResult.statusCode(),
                "a successful login must return the form_post auto-submit document");
        FormPostSupport.FormPost callback = FormPostSupport.parse(loginResult.body());
        assertTrue(callback.action().startsWith(REDIRECT_URI),
                "the form_post target must be the exact registered redirect_uri");
        assertTrue(callback.query().contains("code="),
                "the form_post document must carry the authorization code");
        return callback.query();
    }

    private HttpResponse<String> redeem(HttpClient client, String code, String codeVerifier) throws Exception {
        String basic = Base64.getEncoder().encodeToString(
                (CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        String form = param("grant_type", "authorization_code")
                + "&" + param("code", code)
                + "&" + param("redirect_uri", REDIRECT_URI)
                + "&" + param("code_verifier", codeVerifier);
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(TOKEN_ENDPOINT))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("Authorization", "Basic " + basic)
                .POST(HttpRequest.BodyPublishers.ofString(form)).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static byte[] freshEntropy() {
        byte[] entropy = new byte[32];
        new SecureRandom().nextBytes(entropy);
        return entropy;
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

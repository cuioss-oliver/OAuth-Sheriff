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
import de.cuioss.sheriff.token.client.flow.CallbackHandler;
import de.cuioss.sheriff.token.client.flow.CallbackParameters;
import de.cuioss.sheriff.token.client.flow.StepUpChallengeParser;
import de.cuioss.sheriff.token.client.flow.StepUpChallengeParser.StepUpChallenge;
import de.cuioss.sheriff.token.client.flow.StepUpHandler;
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
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Increment-5 RFC 9470 step-up spec against the real Keycloak container ({@code CLIENT-2}).
 * <p>
 * Parses a resource server's {@code insufficient_user_authentication} challenge with the production
 * {@link StepUpChallengeParser}, drives the production {@link StepUpHandler} to mint an elevated
 * {@code authorization_code} request carrying the challenge {@code acr_values}, and confirms the real
 * Keycloak authorization endpoint honours the elevated request end-to-end: it serves the login form
 * for the {@code acr_values}-carrying request and completes the headless login back to the client
 * callback. The container uses a self-signed certificate, so the exchange runs against a trust-all TLS
 * context (integration-test scope only), mirroring {@link BaseIntegrationTest}'s relaxed HTTPS posture.
 */
@DisplayName("RFC 9470 step-up authorization request against real Keycloak")
class StepUpSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(StepUpSpecIT.class);

    private static final String ISSUER = "https://localhost:1443/realms/integration";
    private static final String AUTH_ENDPOINT = ISSUER + "/protocol/openid-connect/auth";
    private static final String CLIENT_ID = "integration-client";
    private static final String CLIENT_SECRET = "integration-secret";
    private static final String REDIRECT_URI = "https://localhost/callback";
    private static final String USERNAME = "integration-user";
    private static final String PASSWORD = "integration-password";
    private static final String STEP_UP_ACR = "1";

    private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+)\"");

    @Test
    @DisplayName("Should mint an elevated request from a step-up challenge and complete it against Keycloak")
    void shouldCompleteStepUpAuthorizationRequest() throws Exception {
        String wwwAuthenticate = "Bearer error=\"insufficient_user_authentication\", acr_values=\""
                + STEP_UP_ACR + "\", max_age=\"0\"";
        Optional<StepUpChallenge> challenge = new StepUpChallengeParser().parse(wwwAuthenticate);
        assertTrue(challenge.isPresent(), "the production parser must recognise the RFC 9470 step-up challenge");

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

        StepUpHandler.StepUpRequest stepUp =
                new StepUpHandler().initiate(configuration, metadata, challenge.get());
        assertTrue(stepUp.authorizationUrl().contains("acr_values=" + STEP_UP_ACR),
                "the elevated request must carry the challenge acr_values to the authorization server");

        HttpClient client = HttpClient.newBuilder()
                .sslContext(trustAllContext())
                .cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        String callbackQuery = login(client, stepUp.authorizationUrl());
        CallbackParameters callback = CallbackParameters.parse(callbackQuery);
        String code = new CallbackHandler().handle(stepUp.context(), callback);
        LOGGER.debug("step-up authorization code obtained: present=%s", code != null);

        assertAll("step-up round trip",
                () -> assertTrue(code != null && !code.isBlank(),
                        "the elevated flow yields an authorization code bound to the fresh step-up context"),
                () -> assertEquals(stepUp.context().state(), callback.state(),
                        "the callback state must echo the fresh step-up context state"));
    }

    private String login(HttpClient client, String authorizationUrl) throws Exception {
        HttpRequest authRequest = HttpRequest.newBuilder().uri(URI.create(authorizationUrl))
                .header("Accept", "text/html").GET().build();
        HttpResponse<String> loginPage = client.send(authRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, loginPage.statusCode(),
                "Keycloak must serve the login form for the acr_values-carrying step-up request");

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

        // C1 emits response_mode=form_post on the elevated authorization request, so a successful
        // step-up login no longer 302-redirects with the code in the Location query. Keycloak instead
        // returns HTTP 200 with an auto-submitting HTML form whose action is the registered
        // redirect_uri and whose hidden inputs carry the authorization-response parameters (code,
        // state, and the RFC 9207 iss). Reduce that form back to the callback query string.
        assertEquals(200, loginResult.statusCode(),
                "a successful step-up login must return the form_post auto-submit document");
        FormPostSupport.FormPost callback = FormPostSupport.parse(loginResult.body());
        assertTrue(callback.action().startsWith(REDIRECT_URI),
                "the form_post target must be the exact registered redirect_uri");
        assertTrue(callback.query().contains("code="),
                "the step-up form_post document must carry the authorization code");
        return callback.query();
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

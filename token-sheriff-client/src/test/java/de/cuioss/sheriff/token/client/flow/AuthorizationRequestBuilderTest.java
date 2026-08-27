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
package de.cuioss.sheriff.token.client.flow;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("AuthorizationRequestBuilder authorization_code + PKCE S256 request")
class AuthorizationRequestBuilderTest {

    private static final String REDIRECT_URI = "https://rp.example.com/callback";
    private static final String AUTH_ENDPOINT = "https://issuer.example.com/authorize";
    private static final String RESPONSE_MODE_FORM_POST = "form_post";

    private final AuthorizationRequestBuilder builder = new AuthorizationRequestBuilder();

    private static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer("https://issuer.example.com")
                .clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .scope("profile")
                .redirectUri(REDIRECT_URI)
                .build();
    }

    private static ProviderMetadata metadataWithS256(String authorizationEndpoint) {
        var metadata = new ProviderMetadata();
        metadata.issuer = "https://issuer.example.com";
        metadata.authorizationEndpoint = authorizationEndpoint;
        metadata.codeChallengeMethodsSupported = List.of("S256");
        return metadata;
    }

    private static Map<String, String> queryParams(String url) {
        Map<String, String> params = new HashMap<>();
        String query = URI.create(url).getRawQuery();
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            params.put(key, value);
        }
        return params;
    }

    @Nested
    @DisplayName("Happy path")
    class HappyPath {

        @Test
        @DisplayName("Should carry every mandatory authorization_code + PKCE parameter")
        void shouldCarryMandatoryParameters() {
            var configuration = config();
            var context = FlowContext.create(REDIRECT_URI);

            String url = builder.build(configuration, metadataWithS256(AUTH_ENDPOINT), context);
            Map<String, String> params = queryParams(url);

            assertAll("authorization request parameters",
                    () -> assertTrue(url.startsWith(AUTH_ENDPOINT + "?"), "URL starts at the authorization endpoint"),
                    () -> assertEquals("code", params.get("response_type"), "response_type is 'code'"),
                    () -> assertEquals(configuration.getClientId(), params.get("client_id"), "client_id is carried"),
                    () -> assertEquals(REDIRECT_URI, params.get("redirect_uri"), "exact redirect_uri is carried"),
                    () -> assertEquals("openid profile", params.get("scope"), "space-delimited scopes are carried"),
                    () -> assertEquals(context.state(), params.get("state"), "state is carried"),
                    () -> assertEquals(context.nonce(), params.get("nonce"), "nonce is carried"),
                    () -> assertEquals(context.pkceChallenge().codeChallenge(), params.get("code_challenge"),
                            "PKCE code_challenge is carried"),
                    () -> assertEquals("S256", params.get("code_challenge_method"),
                            "PKCE method is always S256"));
        }

        @Test
        @DisplayName("Should request response_mode=form_post so the response is not leaked in the redirect URL")
        void shouldRequestFormPostResponseMode() {
            var context = FlowContext.create(REDIRECT_URI);

            String url = builder.build(config(), metadataWithS256(AUTH_ENDPOINT), context);

            assertEquals(RESPONSE_MODE_FORM_POST, queryParams(url).get("response_mode"),
                    "response_mode=form_post keeps code/state/iss out of the redirect URL (T-URL-LEAK)");
        }

        @Test
        @DisplayName("Should never leak the secret PKCE code_verifier into the front-channel URL")
        void shouldNotLeakVerifier() {
            var context = FlowContext.create(REDIRECT_URI);

            String url = builder.build(config(), metadataWithS256(AUTH_ENDPOINT), context);

            assertFalse(url.contains(context.pkceChallenge().codeVerifier()),
                    "the code_verifier is a secret and must never appear on the authorization request");
        }

        @Test
        @DisplayName("Should append acr_values when the flow context requests step-up")
        void shouldAppendAcrValues() {
            String acr = "urn:mace:incommon:iap:silver";
            var context = FlowContext.create(REDIRECT_URI, acr);

            String url = builder.build(config(), metadataWithS256(AUTH_ENDPOINT), context);

            assertEquals(acr, queryParams(url).get("acr_values"), "requested acr_values are appended");
        }

        @Test
        @DisplayName("Should omit acr_values when step-up is not requested")
        void shouldOmitAcrValues() {
            var context = FlowContext.create(REDIRECT_URI);

            String url = builder.build(config(), metadataWithS256(AUTH_ENDPOINT), context);

            assertFalse(queryParams(url).containsKey("acr_values"), "acr_values is absent without step-up");
        }

        @Test
        @DisplayName("Should omit scope when no scopes are configured")
        void shouldOmitScopeWhenEmpty() {
            var configuration = ClientConfiguration.builder()
                    .issuer("https://issuer.example.com")
                    .clientId(Generators.nonBlankStrings().next())
                    .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                    .redirectUri(REDIRECT_URI)
                    .build();
            var context = FlowContext.create(REDIRECT_URI);

            String url = builder.build(configuration, metadataWithS256(AUTH_ENDPOINT), context);

            assertFalse(queryParams(url).containsKey("scope"), "scope is omitted when no scopes are configured");
        }

        @Test
        @DisplayName("Should join with '&' when the authorization endpoint already carries a query string")
        void shouldJoinWithAmpersandWhenEndpointHasQuery() {
            var context = FlowContext.create(REDIRECT_URI);

            String url = builder.build(config(), metadataWithS256(AUTH_ENDPOINT + "?ui_locales=de"), context);

            assertAll("query joining",
                    () -> assertTrue(url.startsWith(AUTH_ENDPOINT + "?ui_locales=de&"),
                            "existing query is preserved and joined with '&'"),
                    () -> assertEquals("de", queryParams(url).get("ui_locales"), "the pre-existing parameter survives"));
        }
    }

    @Nested
    @DisplayName("Fail-closed")
    class FailClosed {

        @Test
        @DisplayName("Should reject a metadata document without an authorization endpoint")
        void shouldRejectMissingAuthorizationEndpoint() {
            var metadata = new ProviderMetadata();
            metadata.codeChallengeMethodsSupported = List.of("S256");
            var context = FlowContext.create(REDIRECT_URI);
            var configuration = config();

            assertThrows(ClientProtocolException.class,
                    () -> builder.build(configuration, metadata, context));
        }

        @Test
        @DisplayName("Should reject null arguments")
        void shouldRejectNullArguments() {
            var metadata = metadataWithS256(AUTH_ENDPOINT);
            var context = FlowContext.create(REDIRECT_URI);
            var configuration = config();

            assertAll("null-guards",
                    () -> assertThrows(NullPointerException.class,
                            () -> builder.build(null, metadata, context)),
                    () -> assertThrows(NullPointerException.class,
                            () -> builder.build(configuration, null, context)),
                    () -> assertThrows(NullPointerException.class,
                            () -> builder.build(configuration, metadata, null)));
        }
    }

    @Nested
    @DisplayName("Endpoint-scheme enforcement (L5)")
    class SchemeEnforcement {

        private static final String HTTP_ENDPOINT = "http://issuer.example.com/authorize";

        private static ClientConfiguration config(boolean allowInsecureHttp) {
            return ClientConfiguration.builder()
                    .issuer("https://issuer.example.com")
                    .clientId(Generators.nonBlankStrings().next())
                    .clientSecret(Generators.nonBlankStrings().next())
                    .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                    .scope("openid")
                    .redirectUri(REDIRECT_URI)
                    .allowInsecureHttp(allowInsecureHttp)
                    .build();
        }

        @Test
        @DisplayName("Should always accept an https endpoint, whether or not insecure http is allowed")
        void shouldAcceptHttpsRegardlessOfInsecureFlag() {
            var context = FlowContext.create(REDIRECT_URI);

            assertAll("https always allowed",
                    () -> assertTrue(builder.build(config(false), metadataWithS256(AUTH_ENDPOINT), context)
                            .startsWith(AUTH_ENDPOINT + "?"), "https accepted when insecure http is not allowed"),
                    () -> assertTrue(builder.build(config(true), metadataWithS256(AUTH_ENDPOINT), context)
                            .startsWith(AUTH_ENDPOINT + "?"), "https accepted when insecure http is allowed"));
        }

        @Test
        @DisplayName("Should accept a cleartext http endpoint only when insecure http is explicitly allowed")
        void shouldAcceptHttpOnlyWhenAllowed() {
            var context = FlowContext.create(REDIRECT_URI);

            String url = builder.build(config(true), metadataWithS256(HTTP_ENDPOINT), context);

            assertTrue(url.startsWith(HTTP_ENDPOINT + "?"),
                    "a cleartext http endpoint is permitted for a local test setup when allowInsecureHttp is set");
        }

        @Test
        @DisplayName("Should reject a cleartext http endpoint when insecure http is not allowed")
        void shouldRejectHttpWhenNotAllowed() {
            var configuration = config(false);
            var metadata = metadataWithS256(HTTP_ENDPOINT);
            var context = FlowContext.create(REDIRECT_URI);

            assertThrows(ClientProtocolException.class,
                    () -> builder.build(configuration, metadata, context),
                    "a non-TLS endpoint must be refused unless insecure http is explicitly allowed");
        }

        @Test
        @DisplayName("Should reject a non-http(s) scheme even when insecure http is allowed")
        void shouldRejectForeignSchemeEvenWhenInsecureAllowed() {
            var configuration = config(true);
            var context = FlowContext.create(REDIRECT_URI);
            var ftp = metadataWithS256("ftp://issuer.example.com/authorize");
            var file = metadataWithS256("file:///etc/passwd");

            assertAll("only literal http is tolerated under allowInsecureHttp",
                    () -> assertThrows(ClientProtocolException.class,
                            () -> builder.build(configuration, ftp, context),
                            "an ftp endpoint is never a valid authorization endpoint"),
                    () -> assertThrows(ClientProtocolException.class,
                            () -> builder.build(configuration, file, context),
                            "a file endpoint is never a valid authorization endpoint"));
        }

        @Test
        @DisplayName("Should reject an endpoint with no scheme (relative URL) even when insecure http is allowed")
        void shouldRejectSchemelessEndpoint() {
            var configuration = config(true);
            var metadata = metadataWithS256("/authorize");
            var context = FlowContext.create(REDIRECT_URI);

            assertThrows(ClientProtocolException.class,
                    () -> builder.build(configuration, metadata, context),
                    "a schemeless (relative) authorization endpoint must be rejected");
        }
    }
}

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

import de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.dispatcher.TokenDispatcher;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("RefreshFlow refresh_token exchange with rotation")
class RefreshFlowTest {

    @Getter
    private final TokenDispatcher moduleDispatcher = new TokenDispatcher();

    private TestTokenHolder holder;
    private TokenValidationBridge bridge;

    @BeforeEach
    void setUp() {
        holder = TestTokenGenerators.accessTokens().next();
        TokenValidator validator = TokenValidator.builder().issuerConfig(holder.getIssuerConfig()).build();
        bridge = new TokenValidationBridge(validator);
        moduleDispatcher.reset();
    }

    private static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer("https://" + Generators.letterStrings(3, 10).next() + ".example.com")
                .clientId(Generators.letterStrings(5, 12).next())
                .clientSecret(Generators.letterStrings(8, 20).next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .allowInsecureHttp(true)
                .build();
    }

    private static ClientConfiguration configWithScopes(String... scopes) {
        var builder = ClientConfiguration.builder()
                .issuer("https://" + Generators.letterStrings(3, 10).next() + ".example.com")
                .clientId(Generators.letterStrings(5, 12).next())
                .clientSecret(Generators.letterStrings(8, 20).next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .allowInsecureHttp(true);
        for (String scope : scopes) {
            builder.scope(scope);
        }
        return builder.build();
    }

    private static ProviderMetadata metadata(URIBuilder uriBuilder) {
        var metadata = new ProviderMetadata();
        metadata.tokenEndpoint = uriBuilder.addPathSegments("oidc", "token").buildAsString();
        return metadata;
    }

    private RefreshFlow flow(ClientConfiguration config) {
        return new RefreshFlow(config, new TokenEndpointClient(config), bridge,
                new ClientSecretBasicAuth(config.getClientId(), config.getClientSecret()));
    }

    @Test
    @DisplayName("Should refresh and report a rotated refresh token when the AS issues a new one")
    void shouldRefreshAndReportRotation(URIBuilder uriBuilder) {
        String rotated = Generators.letterStrings(20, 40).next();
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(holder.getRawToken(), rotated, null, 300));
        String presented = Generators.letterStrings(20, 40).next();

        RotationResult result = flow(config()).refresh(metadata(uriBuilder), presented);

        assertAll("rotation result",
                () -> assertNotNull(result.accessToken(), "a validated access token must be returned"),
                () -> assertTrue(result.rotated(), "a newly issued refresh token must be reported as rotated"),
                () -> assertEquals(rotated, result.refreshToken(), "the rotated refresh token must be surfaced"),
                () -> assertEquals(300, result.accessTokenExpiresInSeconds(), "the access token lifetime must be surfaced"));
    }

    @Test
    @DisplayName("Should report no rotation and reuse the presented token when the AS omits a new refresh token")
    void shouldReportNoRotationWhenServerOmitsRefreshToken(URIBuilder uriBuilder) {
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(holder.getRawToken(), null, null, 120));
        String presented = Generators.letterStrings(20, 40).next();

        RotationResult result = flow(config()).refresh(metadata(uriBuilder), presented);

        assertAll("no rotation",
                () -> assertFalse(result.rotated(), "an omitted refresh token must not be reported as rotated"),
                () -> assertEquals(presented, result.refreshToken(),
                        "the still-valid presented token must be reused when the AS omits rotation"));
    }

    @Test
    @DisplayName("Should carry the refreshed ID token through the rotation result for the §12.2 consistency check")
    void shouldCarryRefreshedIdToken(URIBuilder uriBuilder) {
        String refreshedIdToken = Generators.letterStrings(20, 40).next();
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(holder.getRawToken(),
                Generators.letterStrings(20, 40).next(), refreshedIdToken, 300));
        String presented = Generators.letterStrings(20, 40).next();

        RotationResult result = flow(config()).refresh(metadata(uriBuilder), presented);

        assertEquals(refreshedIdToken, result.idToken(),
                "a refreshed ID token must be surfaced for the lifecycle §12.2 consistency check");
    }

    @Test
    @DisplayName("Should surface a null ID token when the AS omits one on refresh")
    void shouldReportNoIdTokenWhenServerOmitsIt(URIBuilder uriBuilder) {
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(holder.getRawToken(),
                Generators.letterStrings(20, 40).next(), null, 300));
        String presented = Generators.letterStrings(20, 40).next();

        RotationResult result = flow(config()).refresh(metadata(uriBuilder), presented);

        assertNull(result.idToken(), "an omitted ID token must be surfaced as null (OIDC Core §12.2 permits it)");
    }

    @Test
    @DisplayName("Should send a refresh_token grant carrying the presented token and client authentication")
    void shouldSendRefreshTokenGrantOnTheWire(URIBuilder uriBuilder, MockWebServer server) throws Exception {
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(holder.getRawToken(),
                Generators.letterStrings(20, 40).next(), null, 300));
        String presented = Generators.letterStrings(20, 40).next();

        flow(config()).refresh(metadata(uriBuilder), presented);

        RecordedRequest request = server.takeRequest();
        String body = request.getBody() == null ? "" : request.getBody().utf8();
        assertAll("wire request",
                () -> assertTrue(body.contains("grant_type=refresh_token"), "grant_type must be refresh_token"),
                () -> assertTrue(body.contains("refresh_token=" + presented),
                        "the presented refresh token must be sent"),
                () -> assertNotNull(request.getHeaders().get("Authorization"),
                        "client authentication must decorate the request"));
    }

    @Test
    @DisplayName("Should surface a TransportException on a token-endpoint error response")
    void shouldSurfaceTransportException(URIBuilder uriBuilder) {
        moduleDispatcher.returnOAuthError();
        var flow = flow(config());
        var metadata = metadata(uriBuilder);
        String presented = Generators.letterStrings(20, 40).next();

        assertThrows(TransportException.class, () -> flow.refresh(metadata, presented));
    }

    @Test
    @DisplayName("Should reject a refreshed token that fails pipeline validation")
    void shouldRejectTamperedToken(URIBuilder uriBuilder) {
        holder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString("https://attacker.example.com"));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(holder.getRawToken(),
                Generators.letterStrings(20, 40).next(), null, 300));
        var flow = flow(config());
        var metadata = metadata(uriBuilder);
        String presented = Generators.letterStrings(20, 40).next();

        assertThrows(TokenValidationException.class, () -> flow.refresh(metadata, presented));
    }

    @Test
    @DisplayName("Should reject null metadata and null or blank refresh tokens")
    void shouldRejectInvalidArguments(URIBuilder uriBuilder) {
        var flow = flow(config());
        var metadata = metadata(uriBuilder);
        var refreshToken = Generators.letterStrings(20, 40).next();
        assertAll("argument validation",
                () -> assertThrows(NullPointerException.class,
                        () -> flow.refresh(null, refreshToken)),
                () -> assertThrows(NullPointerException.class, () -> flow.refresh(metadata, null)),
                () -> assertThrows(IllegalArgumentException.class, () -> flow.refresh(metadata, "   ")));
    }

    @Test
    @DisplayName("Should send the configured scopes as a space-delimited scope parameter")
    void shouldSendConfiguredScopesOnTheWire(URIBuilder uriBuilder, MockWebServer server) throws Exception {
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(holder.getRawToken(),
                Generators.letterStrings(20, 40).next(), null, 300));
        ClientConfiguration config = configWithScopes("openid", "profile");

        flow(config).refresh(metadata(uriBuilder), Generators.letterStrings(20, 40).next());

        RecordedRequest request = server.takeRequest();
        String body = request.getBody() == null ? "" : request.getBody().utf8();
        assertTrue(body.contains("scope=openid+profile"),
                "configured scopes must be sent space-delimited as the scope parameter, but body was: " + body);
    }

    @Test
    @DisplayName("Should reuse the presented token when the AS returns a blank refresh token")
    void shouldReusePresentedTokenWhenServerReturnsBlankRefreshToken(URIBuilder uriBuilder) {
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(holder.getRawToken(), "", null, 300));
        String presented = Generators.letterStrings(20, 40).next();

        RotationResult result = flow(config()).refresh(metadata(uriBuilder), presented);

        assertAll("blank rotated token",
                () -> assertEquals(presented, result.refreshToken(),
                        "a blank refresh token is no rotation — the presented token stays in use"),
                () -> assertFalse(result.rotated(),
                        "a blank refresh token must not be reported as a rotation"));
    }
}

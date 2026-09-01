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
import de.cuioss.sheriff.token.client.token.RotationResult.ScopeDelta;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
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
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

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

    /** The scope set this client requests throughout the reconciliation matrix. */
    private static final List<String> REQUESTED_SCOPES = List.of("openid", "profile");

    /** The rendering of {@link #REQUESTED_SCOPES} the reconciliation WARN records interpolate. */
    private static final String REQUESTED_RENDERED = "openid profile";

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

    // --- Scope reconciliation matrix (RFC 6749 §3.3 / §5.1) -------------------------------------
    //
    // The reconciliation is anomaly reporting, not compliance enforcement: RFC 6749 §3.3 permits the
    // authorization server to grant a scope other than the one requested provided it discloses the
    // result, so the lenient default accepts every outcome and only reports it. The matrix therefore
    // pins mode x outcome rather than a single matched pair: the strict posture is exercised as its
    // own negative control, and the three outcomes that behave identically in both postures are
    // parameterized over the mode so the both-modes obligation stays explicit.

    /**
     * A client requesting {@link #REQUESTED_SCOPES}, in the supplied reconciliation posture.
     *
     * @param strictScopeReconciliation whether a broadened grant is refused rather than reported
     */
    private static ClientConfiguration scopedConfig(boolean strictScopeReconciliation) {
        return ClientConfiguration.builder()
                .issuer("https://" + Generators.letterStrings(3, 10).next() + ".example.com")
                .clientId(Generators.letterStrings(5, 12).next())
                .clientSecret(Generators.letterStrings(8, 20).next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .allowInsecureHttp(true)
                .scopes(REQUESTED_SCOPES)
                .strictScopeReconciliation(strictScopeReconciliation)
                .build();
    }

    /**
     * An RFC 6749 §5.1 success body carrying the supplied granted {@code scope}. Composed here rather
     * than through {@link TokenDispatcher#tokenResponse} because that shared builder carries no
     * {@code scope} member. A {@code null} {@code grantedScope} omits the parameter entirely, which
     * §5.1 defines as identical to the requested scope.
     *
     * @param grantedScope the {@code scope} value to return, or {@code null} to omit the parameter
     */
    private String scopedTokenResponse(String grantedScope) {
        StringBuilder json = new StringBuilder("{\"access_token\":\"").append(holder.getRawToken())
                .append("\",\"token_type\":\"Bearer\",\"expires_in\":300,\"refresh_token\":\"")
                .append(Generators.letterStrings(20, 40).next()).append('"');
        if (grantedScope != null) {
            json.append(",\"scope\":\"").append(grantedScope).append('"');
        }
        return json.append('}').toString();
    }

    @Test
    @DisplayName("Should accept and report a broadened grant in the default lenient mode")
    void shouldAcceptAndReportBroadenedGrantWhenLenient(URIBuilder uriBuilder) {
        String granted = "openid profile email";
        moduleDispatcher.respondWith(scopedTokenResponse(granted));

        RotationResult result = flow(scopedConfig(false))
                .refresh(metadata(uriBuilder), Generators.letterStrings(20, 40).next());

        assertAll("broadened grant, lenient",
                () -> assertNotNull(result.accessToken(), "a broadened grant must still be accepted"),
                () -> assertEquals(ScopeDelta.BROADENED, result.scopeDelta(),
                        "an unrequested scope must be classified BROADENED"),
                () -> assertEquals(granted, result.grantedScope(),
                        "the raw server-granted scope must be surfaced for the caller to act on"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                "granted a broader scope than requested on refresh; granted '" + granted
                        + "', requested '" + REQUESTED_RENDERED + "'");
    }

    @Test
    @DisplayName("Should refuse a broadened grant with ClientProtocolException under strict reconciliation")
    void shouldRefuseBroadenedGrantWhenStrict(URIBuilder uriBuilder) {
        String granted = "openid profile email";
        moduleDispatcher.respondWith(scopedTokenResponse(granted));
        var flow = flow(scopedConfig(true));
        var metadata = metadata(uriBuilder);
        String presented = Generators.letterStrings(20, 40).next();

        var exception = assertThrows(ClientProtocolException.class, () -> flow.refresh(metadata, presented),
                "strict reconciliation must refuse a broadened grant");

        assertAll("refusal reason",
                () -> assertTrue(exception.getMessage()
                                .contains("granted a broader scope than requested on refresh; granted '" + granted
                                        + "', requested '" + REQUESTED_RENDERED + "'"),
                        "the refusal must name the granted and requested scopes, not merely fail"),
                () -> assertTrue(exception.getMessage().contains("strictScopeReconciliation is enabled"),
                        "the refusal must name the opt-in flag that caused it"));
    }

    @ParameterizedTest(name = "strictScopeReconciliation={0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Should accept an equal grant silently in both reconciliation modes")
    void shouldAcceptEqualGrantSilently(boolean strict, URIBuilder uriBuilder) {
        moduleDispatcher.respondWith(scopedTokenResponse(REQUESTED_RENDERED));

        RotationResult result = flow(scopedConfig(strict))
                .refresh(metadata(uriBuilder), Generators.letterStrings(20, 40).next());

        assertEquals(ScopeDelta.EQUAL, result.scopeDelta(),
                "a grant matching the request must be classified EQUAL");
        LogAsserts.assertNoLogMessagePresent(TestLogLevel.WARN, RefreshFlow.class);
    }

    @ParameterizedTest(name = "strictScopeReconciliation={0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Should accept and report a narrowed grant in both reconciliation modes")
    void shouldAcceptAndReportNarrowedGrant(boolean strict, URIBuilder uriBuilder) {
        String granted = "openid";
        moduleDispatcher.respondWith(scopedTokenResponse(granted));

        RotationResult result = flow(scopedConfig(strict))
                .refresh(metadata(uriBuilder), Generators.letterStrings(20, 40).next());

        assertAll("narrowed grant",
                () -> assertEquals(ScopeDelta.NARROWED, result.scopeDelta(),
                        "a withheld requested scope must be classified NARROWED"),
                () -> assertEquals(granted, result.grantedScope(), "the narrowed grant must be surfaced"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                "granted a narrower scope than requested on refresh; granted '" + granted
                        + "', requested '" + REQUESTED_RENDERED + "'");
    }

    @ParameterizedTest(name = "strictScopeReconciliation={0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Should accept an absent scope parameter silently in both reconciliation modes")
    void shouldAcceptAbsentScopeSilently(boolean strict, URIBuilder uriBuilder) {
        moduleDispatcher.respondWith(scopedTokenResponse(null));

        RotationResult result = flow(scopedConfig(strict))
                .refresh(metadata(uriBuilder), Generators.letterStrings(20, 40).next());

        assertAll("absent scope",
                () -> assertEquals(ScopeDelta.UNDECLARED, result.scopeDelta(),
                        "an omitted scope is 'as requested' (RFC 6749 §5.1), never a broadening signal"),
                () -> assertNull(result.grantedScope(), "an omitted scope must be surfaced as null"));
        LogAsserts.assertNoLogMessagePresent(TestLogLevel.WARN, RefreshFlow.class);
    }
}

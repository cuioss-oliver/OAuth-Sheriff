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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.dispatcher.TokenDispatcher;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The fail-closed contract for refusals raised <em>inside</em> {@link RefreshFlow#refresh} — the three
 * paths that throw after the authorization server has answered {@code 2xx}, and therefore after it has
 * redeemed and possibly rotated the presented refresh token, but before any
 * {@link RotationResult} exists for the caller to test rotation against.
 * <p>
 * Each of the three is pinned as its own positive case, because each carries a different amount of
 * knowledge about rotation and the correct disposition differs accordingly:
 * <ul>
 *   <li>access-token validation failure — rotation known, successor revoked;</li>
 *   <li>strict scope-reconciliation refusal on a broadened grant — rotation known, successor revoked.
 *       This path exists only because the strict posture was added; enabling it must not reintroduce
 *       the very leak the quarantine exists to close;</li>
 *   <li>an unparseable success response — rotation <em>not computable at all</em>, so the presented
 *       token is presumed burned and the session cleared without inventing a token to revoke.</li>
 * </ul>
 * <p>
 * The matched negative control is what proves the distinction survived: a failure raised
 * <em>before</em> redemption leaves the stored bundle intact. Without it, an implementation that
 * quarantines on every refresh failure — destroying a working session over a transient network fault —
 * would look identical to a correct one.
 * <p>
 * Held in its own class rather than folded into {@link RefreshAdversarialTest}, per the
 * {@link RefreshTestSupport} precedent of splitting the wired refresh contract by behaviour cluster
 * instead of growing one class past the module's 400-line budget.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("Wired refresh: post-redemption refusals fail closed, pre-redemption failures do not")
class RefreshPostRedemptionQuarantineTest extends RefreshTestSupport {

    /** The scope set the strict-posture client requests. */
    private static final List<String> REQUESTED_SCOPES = List.of("openid", "profile");

    @BeforeEach
    void setUp() {
        initRefreshFixture();
    }

    @Test
    @DisplayName("Should quarantine the rotated session when the refreshed access token fails validation")
    void shouldQuarantineWhenRefreshedAccessTokenFailsValidation(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, null));

        // The AS rotates — burning rt1 — and issues an access token from a foreign issuer, so the
        // refusal comes from the client-side pipeline after the redemption has already happened.
        accessHolder.withClaim(ClaimName.ISSUER.getName(),
                ClaimValue.forPlainString("https://attacker.example.com"));
        String rotatedToken = Generators.letterStrings(20, 40).next();
        getModuleDispatcher().respondWith(
                TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rotatedToken, null, 300));
        var clientAuth = clientAuth(config);

        assertThrows(TokenValidationException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("validation refusal quarantines the redeemed session",
                () -> assertTrue(manager.get(session).isEmpty(),
                        "the session is cleared rather than left holding the AS-burned rt1"),
                () -> assertTrue(revocationClient.revoked(rotatedToken),
                        "the AS-issued successor is revoked at the AS (RFC 7009)"),
                () -> assertFalse(revocationClient.revoked(rt1),
                        "the already-burned presented token is not what gets revoked"));
    }

    @Test
    @DisplayName("Should quarantine the rotated session when strict reconciliation refuses a broadened grant")
    void shouldQuarantineWhenStrictReconciliationRefusesBroadenedGrant(URIBuilder uriBuilder) {
        ClientConfiguration config = strictScopedConfig();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, null));

        // The AS rotates and grants a scope that was never requested. Under the opt-in strict posture
        // the flow refuses — after the redemption — so the refusal must fail the session closed rather
        // than leave rt1 in the store, which is the defect this posture would otherwise reintroduce.
        String rotatedToken = Generators.letterStrings(20, 40).next();
        getModuleDispatcher().respondWith(scopedTokenResponse(rotatedToken, "openid profile email"));
        var clientAuth = clientAuth(config);

        var thrown = assertThrows(ClientProtocolException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("strict scope refusal quarantines the redeemed session",
                () -> assertTrue(thrown.getMessage().contains("strictScopeReconciliation is enabled"),
                        "the refusal must be the strict-posture one, not an unrelated failure"),
                () -> assertTrue(manager.get(session).isEmpty(),
                        "the session is cleared rather than left holding the AS-burned rt1"),
                () -> assertTrue(revocationClient.revoked(rotatedToken),
                        "the AS-issued successor is revoked at the AS (RFC 7009)"));
    }

    @ParameterizedTest(name = "body={0}")
    @ValueSource(strings = {
            "{ not json",
            "{\"token_type\":\"Bearer\",\"expires_in\":300}",
            "{\"access_token\":\"a\",\"token_type\":\"Newfangled\",\"expires_in\":300}"})
    @DisplayName("Should presume rotation and clear without revocation when the success response is unusable")
    void shouldQuarantineWithoutRevocationWhenSuccessResponseIsUnusable(String body, URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, null));

        // HTTP 200 whose body cannot be turned into a TokenResponse — unparseable, missing the
        // access_token, or carrying an unrecognized token_type. The AS accepted and processed the
        // grant, so rt1 may already be burned, but no TokenResponse is ever built and its rotation
        // decision cannot be recovered. There is consequently no successor on this side to revoke.
        getModuleDispatcher().respondWith(200, body);
        var clientAuth = clientAuth(config);

        assertThrows(TransportException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("unparseable success fails closed on a presumed rotation",
                () -> assertTrue(manager.get(session).isEmpty(),
                        "the session is cleared on the presumption that rt1 was rotated and burned"),
                () -> assertFalse(revocationClient.revokedAny(),
                        "no token is invented to revoke when the successor is unknown"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                "cleared without revocation");
    }

    @ParameterizedTest(name = "HTTP {0}")
    @ValueSource(ints = {400, 500})
    @DisplayName("Should leave the stored bundle intact when the server never redeemed the presented token")
    void shouldKeepStoredBundleWhenRequestFailsBeforeRedemption(int status, URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, null));

        // The matched negative control. A non-success status means the AS refused the request outright,
        // so rt1 was never redeemed and is still usable: quarantining here would destroy a working
        // session over a transient fault, which is exactly the over-correction this control detects.
        getModuleDispatcher().respondWith(status, "{\"error\":\"invalid_grant\"}");
        var clientAuth = clientAuth(config);

        assertThrows(TransportException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("a pre-redemption failure leaves the session usable",
                () -> assertEquals(rt1, manager.get(session).orElseThrow().refreshToken(),
                        "the still-valid presented refresh token must survive a failure the AS never processed"),
                () -> assertFalse(revocationClient.revokedAny(),
                        "nothing is revoked for a request the AS never processed"));
        LogAsserts.assertNoLogMessagePresent(TestLogLevel.WARN, TokenLifecycleManager.class);
    }

    @Test
    @DisplayName("Should leave the stored bundle intact when a redeemed refresh was refused but never rotated")
    void shouldKeepStoredBundleWhenRedeemedWithoutRotation(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, null));

        // The second half of the control pair: the refusal IS post-redemption, but the AS omitted a new
        // refresh token (RFC 6749 §6 permits that), so rt1 survived the exchange and stays usable. Only
        // rotation — not the mere fact of redemption — may quarantine, and this is what pins that.
        accessHolder.withClaim(ClaimName.ISSUER.getName(),
                ClaimValue.forPlainString("https://attacker.example.com"));
        getModuleDispatcher().respondWith(
                TokenDispatcher.tokenResponse(accessHolder.getRawToken(), null, null, 300));
        var clientAuth = clientAuth(config);

        assertThrows(TokenValidationException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("a refused but non-rotating redemption leaves the session usable",
                () -> assertEquals(rt1, manager.get(session).orElseThrow().refreshToken(),
                        "a refresh token the AS did not rotate is still valid and must be kept"),
                () -> assertFalse(revocationClient.revokedAny(),
                        "nothing is revoked while the presented token is still live"));
    }

    /** A client requesting {@link #REQUESTED_SCOPES} that refuses a broadened grant. */
    private static ClientConfiguration strictScopedConfig() {
        return ClientConfiguration.builder()
                .issuer("https://" + Generators.letterStrings(3, 10).next() + ".example.com")
                .clientId(Generators.letterStrings(5, 12).next())
                .clientSecret(Generators.letterStrings(8, 20).next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .allowInsecureHttp(true)
                .scopes(REQUESTED_SCOPES)
                .strictScopeReconciliation(true)
                .build();
    }

    /**
     * An RFC 6749 §5.1 success body carrying an explicit granted {@code scope}, composed here because
     * the shared {@link TokenDispatcher#tokenResponse} builder carries no {@code scope} member.
     *
     * @param refreshToken the rotated {@code refresh_token} to return
     * @param grantedScope the {@code scope} value to return
     */
    private String scopedTokenResponse(String refreshToken, String grantedScope) {
        return "{\"access_token\":\"" + accessHolder.getRawToken()
                + "\",\"token_type\":\"Bearer\",\"expires_in\":300,\"refresh_token\":\"" + refreshToken
                + "\",\"scope\":\"" + grantedScope + "\"}";
    }
}

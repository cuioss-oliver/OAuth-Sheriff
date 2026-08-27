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
import de.cuioss.sheriff.token.client.dpop.DpopProofGenerator;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import de.cuioss.sheriff.token.integration.security.DpopProofHelper;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.function.Supplier;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Drives the production {@link RefreshFlow} against the real Keycloak container through an assembled
 * client engine — the surface a BFF consumes.
 * <p>
 * Every other refresh-facing spec in this module reaches the token endpoint with a hand-rolled
 * {@code HttpRequest}, which proves Keycloak's behaviour but leaves the engine's own refresh path
 * unexercised against a real authorization server. This spec closes that gap: the refresh legs run
 * through {@link RefreshFlow#refresh}, so the transport, the client authentication, the DPoP proof
 * generation, and the validation bridge are all the production implementations.
 * <p>
 * A failure is deliberately surfaced with the production stack frame that raised it (see
 * {@link #productionFrame}), so a red run names the engine class at fault instead of collapsing into
 * an opaque transport error.
 */
@DisplayName("Production RefreshFlow against real Keycloak")
class RefreshProductionPathSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(RefreshProductionPathSpecIT.class);

    /** Package prefix identifying a frame inside the production client engine. */
    private static final String PRODUCTION_PACKAGE = "de.cuioss.sheriff.token.client.";

    private static final String INTEGRATION_CLIENT_ID = "integration-client";
    private static final String INTEGRATION_CLIENT_SECRET = "integration-secret";
    private static final String DPOP_CLIENT_ID = "dpop-client";
    private static final String DPOP_CLIENT_SECRET = "dpop-secret";
    private static final String FAST_CLIENT_ID = "refresh-fast-client";
    private static final String FAST_CLIENT_SECRET = "refresh-fast-secret";

    /**
     * Bounded wait for the {@code refresh-fast-client}'s 35-second access token to actually expire.
     * Generous enough to absorb container and CI jitter, still far below the refresh token's own
     * 1800-second lifetime, so the refresh leg that follows is genuinely redeemable.
     */
    private static final Duration EXPIRY_BUDGET = Duration.ofSeconds(90);

    @Test
    @DisplayName("Should rotate the refresh token and return a validated access token through RefreshFlow")
    void shouldRotateThroughProductionRefreshFlow() {
        String initialRefreshToken = TestRealm.createIntegrationRealm().obtainValidToken().refreshToken();
        assertNotNull(initialRefreshToken, "Keycloak must issue an initial refresh token via the password grant");

        ClientConfiguration configuration =
                RefreshEngineSupport.clientConfiguration(INTEGRATION_CLIENT_ID, INTEGRATION_CLIENT_SECRET);
        TokenValidator validator = RefreshEngineSupport.tokenValidator();
        TokenValidationBridge accessBridge = RefreshEngineSupport.accessTokenBridge(validator);
        IdTokenValidationBridge idBridge = RefreshEngineSupport.idTokenBridge(validator);
        RefreshFlow refreshFlow = RefreshEngineSupport.refreshFlow(configuration, accessBridge);

        RotationResult rotation = drive("refresh_token exchange",
                () -> refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), initialRefreshToken));

        assertAll("production refresh",
                () -> assertTrue(rotation.rotated(), "Keycloak rotates the refresh token on redemption"),
                () -> assertNotEquals(initialRefreshToken, rotation.refreshToken(),
                        "the rotated refresh token must differ from the redeemed one"),
                () -> assertFalse(rotation.accessToken().getRawToken().isBlank(),
                        "the rotation must carry a non-blank access token"),
                () -> assertEquals(KeycloakUrlSupport.INTERNAL_ISSUER, rotation.accessToken().getIssuer(),
                        "the validated access token must carry the realm's issuer identity"),
                () -> assertTrue(rotation.accessToken().getSubject().isPresent(),
                        "the validated access token must be subject bound"));

        if (rotation.idToken() != null) {
            var refreshedIdToken = drive("refreshed ID token validation",
                    () -> idBridge.validateRefreshedIdToken(rotation.idToken()));
            assertEquals(rotation.accessToken().getSubject(), refreshedIdToken.getSubject(),
                    "the refreshed ID token must describe the same subject as the access token");
        }
    }

    @Test
    @DisplayName("Should preserve the DPoP sender constraint across a production refresh")
    void shouldPreserveDpopSenderConstraintAcrossRefresh() {
        KeyPair proofKey = generateRsaKeyPair();
        DpopProofGenerator proofGenerator = RefreshEngineSupport.dpopProofGenerator(proofKey);

        TestRealm.TokenResponse acquired =
                TestRealm.createDpopRealm().obtainDpopBoundToken(new DpopProofHelper(proofKey));
        assertNotNull(acquired.refreshToken(), "the DPoP-bound acquisition must issue a refresh token");
        assertTrue(claimsOf(acquired.accessToken()).contains(jktClaim(proofGenerator)),
                "the acquired access token must already be bound to the test-owned proof key");

        ClientConfiguration configuration =
                RefreshEngineSupport.clientConfiguration(DPOP_CLIENT_ID, DPOP_CLIENT_SECRET);
        TokenValidationBridge accessBridge =
                RefreshEngineSupport.accessTokenBridge(RefreshEngineSupport.tokenValidator());
        RefreshFlow refreshFlow =
                RefreshEngineSupport.dpopRefreshFlow(configuration, accessBridge, proofKey);

        RotationResult rotation = drive("DPoP-constrained refresh_token exchange",
                () -> refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), acquired.refreshToken()));

        assertTrue(claimsOf(rotation.accessToken().getRawToken()).contains(jktClaim(proofGenerator)),
                "the rotated access token must stay bound to the same proof key (cnf.jkt continuity)");
    }

    @Test
    @DisplayName("Should redeem a refresh token whose access token has already expired")
    void shouldRefreshAfterTheAccessTokenHasExpired() {
        TestRealm.TokenResponse acquired = TestRealm.createFastRefreshRealm().obtainValidToken();
        assertNotNull(acquired.refreshToken(), "the fast-expiry client must issue a refresh token");
        assertNotNull(acquired.expiresInSeconds(), "Keycloak must report the access-token lifetime");

        StoredToken bundle = new StoredToken(acquired.accessToken(), acquired.refreshToken(),
                acquired.idToken(), null, Instant.now().plusSeconds(acquired.expiresInSeconds()));
        RefreshScheduler scheduler = new RefreshScheduler();

        assertFalse(scheduler.needsRefresh(bundle, Instant.now()),
                "a freshly issued 35-second token is not yet inside the 30-second refresh lead");

        await("access token expiry")
                .atMost(EXPIRY_BUDGET)
                .pollInterval(Duration.ofSeconds(1))
                .until(() -> bundle.isExpired(Instant.now()));

        ClientConfiguration configuration =
                RefreshEngineSupport.clientConfiguration(FAST_CLIENT_ID, FAST_CLIENT_SECRET);
        TokenValidationBridge accessBridge =
                RefreshEngineSupport.accessTokenBridge(RefreshEngineSupport.tokenValidator());
        RefreshFlow refreshFlow = RefreshEngineSupport.refreshFlow(configuration, accessBridge);

        RotationResult rotation = drive("expiry-driven refresh_token exchange",
                () -> refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), acquired.refreshToken()));

        assertAll("expiry-driven refresh",
                () -> assertTrue(scheduler.needsRefresh(bundle, Instant.now()),
                        "the presented bundle must have been past its refresh window at redemption time"),
                () -> assertTrue(rotation.rotated(), "the expired-access-token refresh must still rotate"),
                () -> assertNotEquals(acquired.accessToken(), rotation.accessToken().getRawToken(),
                        "the rotation must replace the expired access token"),
                () -> assertNotEquals(acquired.refreshToken(), rotation.refreshToken(),
                        "the rotated refresh token must differ from the redeemed one"),
                () -> assertTrue(rotation.accessTokenExpiresInSeconds() > 0,
                        "the refreshed access token must carry a fresh, positive lifetime"));
    }

    /**
     * Runs one leg of the production path, converting any engine failure into an assertion failure that
     * names the production frame that raised it. Without this, a transport or validation failure inside
     * the engine surfaces as an opaque exception and the test reports no actionable outcome.
     *
     * @param leg    a short description of the leg being driven, used in the failure message
     * @param action the production-path invocation
     * @param <T>    the leg's result type
     * @return the leg's result
     */
    private static <T> T drive(String leg, Supplier<T> action) {
        try {
            return action.get();
        }
        /*TODO: Catch specific not RuntimeException. Suppress: // cui-rewrite:disable InvalidExceptionUsageRecipe*/
        catch (RuntimeException e) {
            LOGGER.debug(e, "Production refresh path failed during %s", leg);
            throw new AssertionError("Production refresh path failed during " + leg
                    + "; production frame: " + productionFrame(e), e);
        }
    }

    /**
     * @param failure the captured engine failure
     * @return the first {@code de.cuioss.sheriff.token.client.*} frame on the failure's cause chain, or
     *         an explicit marker when no production frame is present
     */
    private static String productionFrame(Throwable failure) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            for (StackTraceElement element : current.getStackTrace()) {
                if (element.getClassName().startsWith(PRODUCTION_PACKAGE)) {
                    return element.toString();
                }
            }
        }
        return "<no " + PRODUCTION_PACKAGE + "* frame on the stack>";
    }

    /**
     * @param proofGenerator the production proof generator over the test-owned key
     * @return the exact {@code jkt} JSON fragment a bound token must carry
     */
    private static String jktClaim(DpopProofGenerator proofGenerator) {
        return "\"jkt\":\"" + proofGenerator.jkt() + "\"";
    }

    private static String claimsOf(String jwt) {
        String[] segments = jwt.split("\\.");
        return new String(Base64.getUrlDecoder().decode(segments[1]), StandardCharsets.UTF_8);
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA not available", e);
        }
    }
}

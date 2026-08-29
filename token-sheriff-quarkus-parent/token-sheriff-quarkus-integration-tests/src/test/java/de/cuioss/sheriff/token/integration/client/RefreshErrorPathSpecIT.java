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
import de.cuioss.sheriff.token.client.lifecycle.RevocationClient;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Drives the authorization server's <em>rejection</em> responses through the production
 * {@link RefreshFlow} against the real Keycloak container.
 * <p>
 * Every other 2a spec in this module observes a happy-path redemption. This one presents refresh
 * tokens the authorization server refuses — an unknown token and an explicitly revoked one — and pins
 * that the engine surfaces the refusal as a typed {@link TransportException} raised from a
 * {@code de.cuioss.sheriff.token.client.*} frame, rather than leaking an opaque transport error or,
 * worse, returning a {@link RotationResult} built from an error body.
 * <p>
 * It also records what the AS does with a <em>superseded</em> refresh token presented through the bare
 * 2a surface. {@link RefreshFlow} keeps no rotation-family bookkeeping of its own — reuse detection
 * lives one layer up — so the outcome here is a property of the realm's configuration, not of the
 * engine. See {@link #shouldRecordThatTheRealmAcceptsASupersededRefreshToken()}.
 */
@DisplayName("RefreshFlow error responses against real Keycloak")
class RefreshErrorPathSpecIT extends BaseIntegrationTest {

    private static final String FAST_CLIENT_ID = "refresh-fast-client";
    private static final String FAST_CLIENT_SECRET = "refresh-fast-secret";

    /**
     * A structurally well-formed but entirely unknown refresh token: three base64url segments with a
     * {@code "typ":"Refresh"} payload the realm has never issued. Using a JWT-shaped value rather than
     * an arbitrary string keeps the test on the "unknown grant" branch instead of a parse rejection.
     */
    private static final String UNKNOWN_REFRESH_TOKEN =
            "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIn0"
                    + ".eyJleHAiOjk5OTk5OTk5OTksImp0aSI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsInR5cCI6IlJlZnJlc2gifQ"
                    + ".AAAA";

    private ClientConfiguration configuration;
    private RefreshFlow refreshFlow;

    @BeforeEach
    void assembleEngine() {
        configuration = RefreshEngineSupport.clientConfiguration(FAST_CLIENT_ID, FAST_CLIENT_SECRET);
        TokenValidationBridge accessBridge =
                RefreshEngineSupport.accessTokenBridge(RefreshEngineSupport.tokenValidator());
        refreshFlow = RefreshEngineSupport.refreshFlow(configuration, accessBridge);
    }

    @Test
    @DisplayName("Should surface an unknown refresh token as a typed engine failure")
    void shouldSurfaceUnknownRefreshTokenAsTypedFailure() {
        TransportException failure = assertThrows(TransportException.class,
                () -> refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), UNKNOWN_REFRESH_TOKEN),
                "an unknown refresh token must be refused, never turned into a RotationResult");

        assertAll("typed refusal of an unknown refresh token",
                () -> assertTrue(failure.getMessage().contains("400"),
                        "the failure must report the authorization server's 400 status, was: "
                                + failure.getMessage()),
                () -> assertTrue(RefreshEngineSupport.productionFrame(failure).isPresent(),
                        "the refusal must be raised from a " + RefreshEngineSupport.PRODUCTION_PACKAGE
                                + "* frame, not from transport code outside the engine"));
    }

    @Test
    @DisplayName("Should surface a revoked refresh token as a typed engine failure")
    void shouldSurfaceRevokedRefreshTokenAsTypedFailure() {
        TestRealm.TokenResponse acquired = TestRealm.createFastRefreshRealm().obtainValidToken();
        assertNotNull(acquired.refreshToken(), "the fast-expiry client must issue a refresh token");

        new RevocationClient(configuration).revoke(RefreshEngineSupport.REVOCATION_ENDPOINT,
                acquired.refreshToken(), "refresh_token",
                RefreshEngineSupport.clientAuthentication(configuration));

        TransportException failure = assertThrows(TransportException.class,
                () -> refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), acquired.refreshToken()),
                "a refresh token revoked through the production RevocationClient must no longer redeem");

        assertAll("typed refusal of a revoked refresh token",
                () -> assertTrue(failure.getMessage().contains("400"),
                        "the failure must report the authorization server's 400 status, was: "
                                + failure.getMessage()),
                () -> assertTrue(RefreshEngineSupport.productionFrame(failure).isPresent(),
                        "the refusal must be raised from a " + RefreshEngineSupport.PRODUCTION_PACKAGE
                                + "* frame"));
    }

    /**
     * Records the realm's actual behaviour when a superseded refresh token is replayed through the bare
     * {@link RefreshFlow} surface, with no {@code TokenLifecycleManager} above it.
     * <p>
     * <strong>This documents an authorization-server configuration property, not an engine guarantee.</strong>
     * The {@code integration} realm sets neither {@code revokeRefreshToken} nor
     * {@code refreshTokenMaxReuse}, so Keycloak accepts a token it has already rotated away from. The
     * client-side defence against exactly this is {@code RefreshTokenFamily}, driven by
     * {@code TokenLifecycleManager} — it is pinned by
     * {@code RefreshLifecycleSpecIT#shouldDetectRefreshTokenReuse}, not here. If this test ever turns
     * red, the realm gained single-use refresh tokens; that is a fixture change to record, not an
     * engine regression.
     */
    @Test
    @DisplayName("Should record that the realm accepts a superseded refresh token replayed through RefreshFlow")
    void shouldRecordThatTheRealmAcceptsASupersededRefreshToken() {
        TestRealm.TokenResponse acquired = TestRealm.createFastRefreshRealm().obtainValidToken();
        assertNotNull(acquired.refreshToken(), "the fast-expiry client must issue a refresh token");

        RotationResult first =
                refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), acquired.refreshToken());
        assertTrue(first.rotated(),
                "the first redemption must rotate, so the presented token is genuinely superseded");

        RotationResult replay =
                refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), acquired.refreshToken());

        assertAll("superseded-token replay is accepted by this realm",
                () -> assertNotEquals(first.refreshToken(), replay.refreshToken(),
                        "the replay is redeemed independently and yields its own rotated token"),
                () -> assertFalse(replay.accessToken().getRawToken().isBlank(),
                        "the replay yields a fully validated access token — RefreshFlow alone refuses "
                                + "nothing, because it holds no rotation-family bookkeeping"));
    }
}

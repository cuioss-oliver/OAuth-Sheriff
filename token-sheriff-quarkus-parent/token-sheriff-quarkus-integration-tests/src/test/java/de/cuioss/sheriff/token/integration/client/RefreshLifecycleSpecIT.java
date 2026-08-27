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

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.dpop.ConstraintBinding;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.RevocationClient;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import de.cuioss.sheriff.token.validation.TokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the session-scoped {@link TokenLifecycleManager} refresh path against the real Keycloak
 * container, over the production engine assembled by {@link RefreshEngineSupport}.
 * <p>
 * The lifecycle manager is where refresh stops being a single token exchange and becomes session
 * state: the proactive-refresh window, rotation applied to the stored bundle, the OIDC Core §12.2
 * ID-token carry-forward, client-side refresh-token reuse detection with RFC 7009 revocation, and the
 * bearer-downgrade fail-close for a sender-constrained bundle. Each of those is exercised here
 * against a live authorization server rather than a stubbed token endpoint.
 * <p>
 * The realm's {@code refresh-fast-client} issues a 35-second access token, which is inside the
 * scheduler's 30-second refresh lead within ~5 seconds of issue — short enough for the proactive
 * window to be observed under a bounded wait, long enough that it is not already due at store time.
 */
@DisplayName("TokenLifecycleManager refresh against real Keycloak")
class RefreshLifecycleSpecIT extends BaseIntegrationTest {

    private static final String FAST_CLIENT_ID = "refresh-fast-client";
    private static final String FAST_CLIENT_SECRET = "refresh-fast-secret";

    /** Bounded wait for the proactive-refresh window; the 35 s token becomes due after ~5 s. */
    private static final Duration PROACTIVE_WINDOW_BUDGET = Duration.ofSeconds(15);

    private ClientConfiguration configuration;
    private ClientAuthentication clientAuthentication;
    private TokenValidationBridge accessBridge;
    private IdTokenValidationBridge idBridge;
    private RefreshFlow refreshFlow;
    private RecordingRevocationClient revocationClient;
    private TokenLifecycleManager manager;

    @BeforeEach
    void assembleEngine() {
        configuration = RefreshEngineSupport.clientConfiguration(FAST_CLIENT_ID, FAST_CLIENT_SECRET);
        clientAuthentication = RefreshEngineSupport.clientAuthentication(configuration);
        TokenValidator validator = RefreshEngineSupport.tokenValidator();
        accessBridge = RefreshEngineSupport.accessTokenBridge(validator);
        idBridge = RefreshEngineSupport.idTokenBridge(validator);
        refreshFlow = RefreshEngineSupport.refreshFlow(configuration, accessBridge);
        revocationClient = new RecordingRevocationClient(configuration);
        manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
    }

    @Test
    @DisplayName("Should enter the proactive-refresh window within the fast-expiry lifetime")
    void shouldEnterProactiveRefreshWindow() {
        String sessionId = newSessionId();
        manager.store(sessionId, acquireBundle(null));

        assertFalse(manager.needsRefresh(sessionId, Instant.now()),
                "a freshly issued 35-second token is not yet inside the 30-second refresh lead");

        await("proactive refresh window")
                .atMost(PROACTIVE_WINDOW_BUDGET)
                .pollInterval(Duration.ofSeconds(1))
                .until(() -> manager.needsRefresh(sessionId, Instant.now()));
    }

    @Test
    @DisplayName("Should apply the rotation to the session and carry the refreshed ID token forward")
    void shouldApplyRotationToTheSession() {
        String sessionId = newSessionId();
        StoredToken original = acquireBundle(null);
        manager.store(sessionId, original);

        StoredToken refreshed = refreshSession(sessionId).orElseThrow(
                () -> new AssertionError("the lifecycle manager must return the refreshed bundle"));

        assertAll("rotation applied to the session",
                () -> assertNotEquals(original.accessToken(), refreshed.accessToken(),
                        "the session must hold the refreshed access token"),
                () -> assertNotEquals(original.refreshToken(), refreshed.refreshToken(),
                        "the session must hold the rotated refresh token"),
                () -> assertNotNull(refreshed.idToken(),
                        "the session must keep an ID token across the refresh (OIDC Core 12.2)"),
                () -> assertNotNull(refreshed.expiresAt(),
                        "the refreshed bundle must record the new access-token expiry"));
    }

    @Test
    @DisplayName("Should detect refresh-token reuse, revoke the family, and clear the session")
    void shouldDetectRefreshTokenReuse() {
        String sessionId = newSessionId();
        StoredToken original = acquireBundle(null);
        manager.store(sessionId, original);

        assertTrue(refreshSession(sessionId).isPresent(), "the first refresh must succeed");

        // Re-storing the original bundle leaves the seeded family intact, so the already-superseded
        // refresh token is presented again — the reuse the family exists to detect.
        manager.store(sessionId, original);

        assertThrows(ClientProtocolException.class, () -> refreshSession(sessionId),
                "replaying a superseded refresh token must surface as a protocol-level reuse");

        assertAll("fail-closed reuse handling",
                () -> assertTrue(manager.get(sessionId).isEmpty(),
                        "the session must be cleared after a detected reuse"),
                () -> assertEquals(List.of("refresh_token"), revocationClient.recordedTokenTypeHints(),
                        "exactly one RFC 7009 revocation must be issued, hinted as a refresh token"));
    }

    @Test
    @DisplayName("Should fail closed when a sender-constrained session refreshes to a bearer token")
    void shouldFailCloseOnBearerDowngrade() {
        String sessionId = newSessionId();
        manager.store(sessionId, acquireBundle(ConstraintBinding.dpop("a-stored-proof-key-thumbprint")));

        assertThrows(IllegalStateException.class, () -> refreshSession(sessionId),
                "a sender-constrained bundle must refuse a refreshed token that carries no cnf binding");
    }

    /**
     * Acquires a real token bundle from the fast-expiry client and wraps it as a stored session bundle.
     *
     * @param constraintBinding the sender-constraint to record on the bundle, or {@code null} for a
     *                          plain bearer session
     * @return the stored bundle, with the expiry derived from the provider's {@code expires_in}
     */
    private static StoredToken acquireBundle(ConstraintBinding constraintBinding) {
        TestRealm.TokenResponse acquired = TestRealm.createFastRefreshRealm().obtainValidToken();
        assertNotNull(acquired.refreshToken(), "the fast-expiry client must issue a refresh token");
        assertNotNull(acquired.expiresInSeconds(), "Keycloak must report the access-token lifetime");
        return new StoredToken(acquired.accessToken(), acquired.refreshToken(), acquired.idToken(),
                constraintBinding, Instant.now().plusSeconds(acquired.expiresInSeconds()));
    }

    private Optional<StoredToken> refreshSession(String sessionId) {
        return manager.refresh(sessionId, RefreshEngineSupport.providerMetadata(), refreshFlow,
                revocationClient, idBridge, clientAuthentication);
    }

    private static String newSessionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Revocation client that records every RFC 7009 call before delegating to the production
     * implementation, so the reuse path's revocation is observed as an actual call rather than assumed.
     */
    private static final class RecordingRevocationClient extends RevocationClient {

        private final List<String> tokenTypeHints = new ArrayList<>();

        RecordingRevocationClient(ClientConfiguration configuration) {
            super(configuration);
        }

        @Override
        public void revoke(String revocationEndpoint, String token, String tokenTypeHint,
                ClientAuthentication clientAuthentication) {
            tokenTypeHints.add(tokenTypeHint);
            super.revoke(revocationEndpoint, token, tokenTypeHint, clientAuthentication);
        }

        List<String> recordedTokenTypeHints() {
            return List.copyOf(tokenTypeHints);
        }
    }
}

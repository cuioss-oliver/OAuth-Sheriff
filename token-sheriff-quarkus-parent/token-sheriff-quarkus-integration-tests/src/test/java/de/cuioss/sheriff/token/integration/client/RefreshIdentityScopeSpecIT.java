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
import de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.RevocationClient;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.RotationResult.ScopeDelta;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import de.cuioss.sheriff.token.validation.TokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves the two refresh-path defences of this plan against a <em>real</em> authorization server,
 * rather than only against a mock token endpoint.
 * <ul>
 *   <li><strong>Identity binding:</strong> a session stored with the subject the acquisition actually
 *       named is refreshed successfully, and the bound subject survives the rotation unchanged. The
 *       substituted-subject negative stays at the unit level (deliverable 4): a real AS will not issue
 *       a token for another principal on demand, and driving the realm into doing so would pin fixture
 *       configuration rather than an engine guarantee — the same distinction
 *       {@link RefreshErrorPathSpecIT} documents.</li>
 *   <li><strong>Scope reconciliation:</strong> whatever scope Keycloak actually grants is reconciled
 *       against the configured scope, classified into a {@link ScopeDelta}, and surfaced on the
 *       {@link RotationResult}. Because the default posture is <em>lenient</em>, this spec deliberately
 *       does <strong>not</strong> assert that any real-AS grant is refused — reconciliation is anomaly
 *       reporting (RFC 6749 §3.3), not compliance enforcement. It asserts the delta is classified and
 *       that the classification agrees with the granted value actually returned.</li>
 * </ul>
 * The engine is assembled through {@link RefreshEngineSupport} exactly as an application would wire it,
 * and the bundle is a genuine container acquisition rather than a fabricated token.
 */
@DisplayName("Refresh identity binding and scope reconciliation against real Keycloak")
class RefreshIdentityScopeSpecIT extends BaseIntegrationTest {

    private static final String INTEGRATION_CLIENT_ID = "integration-client";
    private static final String INTEGRATION_CLIENT_SECRET = "integration-secret";

    /** The {@code scope} response parameter is a space-delimited list (RFC 6749 §3.3). */
    private static final String SCOPE_SPLIT_PATTERN = "\\s+";

    private ClientConfiguration configuration;
    private TokenValidationBridge accessBridge;
    private IdTokenValidationBridge idBridge;
    private RefreshFlow refreshFlow;
    private TokenLifecycleManager manager;

    @BeforeEach
    void assembleEngine() {
        configuration =
                RefreshEngineSupport.clientConfiguration(INTEGRATION_CLIENT_ID, INTEGRATION_CLIENT_SECRET);
        TokenValidator validator = RefreshEngineSupport.tokenValidator();
        accessBridge = RefreshEngineSupport.accessTokenBridge(validator);
        idBridge = RefreshEngineSupport.idTokenBridge(validator);
        refreshFlow = RefreshEngineSupport.refreshFlow(configuration, accessBridge);
        manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
    }

    @Test
    @DisplayName("Should accept the refresh of a subject-bound session and carry the subject through the rotation")
    void shouldPreserveTheBoundSubjectAcrossRefresh() {
        String sessionId = UUID.randomUUID().toString();
        TestRealm.TokenResponse acquired = TestRealm.createIntegrationRealm().obtainValidToken();
        assertNotNull(acquired.refreshToken(), "Keycloak must issue a refresh token via the password grant");

        String acquiredSubject = accessBridge.validateAccessToken(acquired.accessToken()).getSubject()
                .orElseThrow(() -> new AssertionError("the acquired access token must be subject bound"));
        manager.store(sessionId, new StoredToken(acquired.accessToken(), acquired.refreshToken(),
                acquired.idToken(), null, Instant.now().plusSeconds(acquired.expiresInSeconds()),
                acquiredSubject));

        StoredToken refreshed = assertDoesNotThrow(
                () -> manager.refresh(sessionId, RefreshEngineSupport.providerMetadata(), refreshFlow,
                        new RevocationClient(configuration), idBridge,
                        RefreshEngineSupport.clientAuthentication(configuration)),
                "a refresh naming the same subject the session is bound to must be accepted")
                .orElseThrow(() -> new AssertionError("the session must still hold a bundle after the refresh"));

        assertAll("identity survives the rotation",
                () -> assertEquals(acquiredSubject, refreshed.subject(),
                        "the refreshed bundle must stay bound to the subject the session was established for"),
                () -> assertEquals(Optional.of(acquiredSubject),
                        manager.get(sessionId).map(StoredToken::subject),
                        "the binding must be visible through the store, not only on the returned bundle"),
                () -> assertEquals(acquiredSubject,
                        accessBridge.validateAccessToken(refreshed.accessToken()).getSubject().orElse(null),
                        "the refreshed access token itself must name the same principal"));
    }

    @Test
    @DisplayName("Should classify and surface the scope Keycloak actually grants, without refusing it")
    void shouldReportTheGrantedScopeDelta() {
        String initialRefreshToken = TestRealm.createIntegrationRealm().obtainValidToken().refreshToken();
        assertNotNull(initialRefreshToken, "Keycloak must issue an initial refresh token via the password grant");

        RotationResult rotation = assertDoesNotThrow(
                () -> refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), initialRefreshToken),
                "the lenient default posture must never refuse a real-AS grant");

        assertAll("granted scope reported",
                () -> assertNotNull(rotation.scopeDelta(), "every rotation must carry a reconciliation outcome"),
                () -> assertFalse(rotation.accessToken().getRawToken().isBlank(),
                        "the accepted rotation must still carry a validated access token"),
                () -> assertScopeDeltaAgreesWithGrant(rotation));
    }

    /**
     * Asserts the reported {@link ScopeDelta} agrees with the {@code scope} value the authorization
     * server actually returned, checked against the scope this client requested.
     * <p>
     * This deliberately verifies the report against observable evidence rather than pinning one
     * expected outcome: the realm's default client scopes decide whether the grant comes back equal or
     * broadened, and pinning either would assert fixture configuration instead of the engine's
     * reconciliation contract.
     */
    private void assertScopeDeltaAgreesWithGrant(RotationResult rotation) {
        Set<String> requested = new HashSet<>(configuration.getScopes());
        String grantedScope = rotation.grantedScope();
        if (grantedScope == null || grantedScope.isBlank()) {
            assertEquals(ScopeDelta.UNDECLARED, rotation.scopeDelta(),
                    "an omitted scope is 'as requested' (RFC 6749 §5.1), never a broadening signal");
            return;
        }
        Set<String> granted = new HashSet<>(Arrays.asList(grantedScope.trim().split(SCOPE_SPLIT_PATTERN)));
        switch (rotation.scopeDelta()) {
            case EQUAL -> assertEquals(requested, granted,
                    "EQUAL must mean the granted set is exactly the requested set, granted was: " + grantedScope);
            case NARROWED -> assertTrue(requested.containsAll(granted) && !requested.equals(granted),
                    "NARROWED must mean a strict subset of the requested set, granted was: " + grantedScope);
            case BROADENED -> assertFalse(requested.containsAll(granted),
                    "BROADENED must mean at least one unrequested scope was granted, granted was: " + grantedScope);
            case UNDECLARED -> assertTrue(configuration.getScopes().isEmpty(),
                    "UNDECLARED alongside a returned scope is only valid when nothing was requested, granted was: "
                            + grantedScope);
        }
    }
}

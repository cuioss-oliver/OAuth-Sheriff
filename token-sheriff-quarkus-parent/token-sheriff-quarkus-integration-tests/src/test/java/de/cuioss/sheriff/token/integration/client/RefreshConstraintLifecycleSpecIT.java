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
import de.cuioss.sheriff.token.client.dpop.ConstraintBinding;
import de.cuioss.sheriff.token.client.dpop.DpopProofGenerator;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.RevocationClient;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import de.cuioss.sheriff.token.integration.security.DpopProofHelper;
import de.cuioss.sheriff.token.validation.TokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pins both halves of the {@code CLIENT-18} sender-constraint contract at the
 * {@link TokenLifecycleManager} layer, against a real DPoP-bound session acquired from the container.
 * <p>
 * The two halves are deliberately separate entry points on the same class, and the distinction is the
 * point of this spec:
 * <ul>
 *   <li>{@link #shouldPreserveTheSenderConstraintThroughConfirmedBindingApplyRefresh()} drives the
 *       <em>documented</em> sender-constrained path: the caller has {@link RefreshFlow} perform the
 *       DPoP-constrained rotation, extracts the {@code cnf} binding the refreshed token actually
 *       carries, and applies it through the six-argument
 *       {@link TokenLifecycleManager#applyRefresh(String, String, String, Instant, ConstraintBinding, String)}
 *       overload. The stored bundle keeps its binding and nothing throws.</li>
 *   <li>{@link #shouldRefuseCoordinatorRefreshThatAppliesNoConfirmedBinding()} drives the
 *       {@link TokenLifecycleManager#refresh} coordinator over the same kind of session. That
 *       coordinator hard-codes a {@code null} refreshed binding, so a sender-constrained bundle fails
 *       closed — <strong>regardless of what the authorization server returned</strong>. It is not
 *       detecting a server-side downgrade; the AS here in fact returns a still-bound token, as the
 *       first test proves.</li>
 * </ul>
 * Both start from a genuine {@code dpop-client} acquisition with a real {@code cnf.jkt}, never from a
 * fabricated thumbprint stapled onto a plain bearer token.
 */
@DisplayName("Sender-constrained refresh through TokenLifecycleManager against real Keycloak")
class RefreshConstraintLifecycleSpecIT extends BaseIntegrationTest {

    private static final String DPOP_CLIENT_ID = "dpop-client";
    private static final String DPOP_CLIENT_SECRET = "dpop-secret";

    /** Extracts the {@code cnf.jkt} confirmation value from a decoded JWT claims set. */
    private static final Pattern JKT_CLAIM = Pattern.compile("\"jkt\"\\s*:\\s*\"([^\"]+)\"");

    private KeyPair proofKey;
    private ConstraintBinding acquiredBinding;
    private ClientConfiguration configuration;
    private TokenValidationBridge accessBridge;
    private IdTokenValidationBridge idBridge;
    private RefreshFlow dpopRefreshFlow;
    private TokenLifecycleManager manager;

    @BeforeEach
    void assembleEngine() {
        proofKey = generateRsaKeyPair();
        DpopProofGenerator proofGenerator = RefreshEngineSupport.dpopProofGenerator(proofKey);
        acquiredBinding = ConstraintBinding.dpop(proofGenerator.jkt());

        configuration = RefreshEngineSupport.clientConfiguration(DPOP_CLIENT_ID, DPOP_CLIENT_SECRET);
        TokenValidator validator = RefreshEngineSupport.tokenValidator();
        accessBridge = RefreshEngineSupport.accessTokenBridge(validator);
        idBridge = RefreshEngineSupport.idTokenBridge(validator);
        dpopRefreshFlow = RefreshEngineSupport.dpopRefreshFlow(configuration, accessBridge, proofKey);
        manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
    }

    @Test
    @DisplayName("Should preserve the sender constraint when the confirmed binding is applied")
    void shouldPreserveTheSenderConstraintThroughConfirmedBindingApplyRefresh() {
        String sessionId = newSessionId();
        StoredToken stored = storeBoundSession(sessionId);

        RotationResult rotation =
                dpopRefreshFlow.refresh(RefreshEngineSupport.providerMetadata(), stored.refreshToken());
        ConstraintBinding confirmedBinding = confirmedBindingOf(rotation.accessToken().getRawToken())
                .orElse(null);

        StoredToken refreshed = assertDoesNotThrow(() -> manager.applyRefresh(sessionId,
                        rotation.accessToken().getRawToken(), rotation.refreshToken(),
                        Instant.now().plusSeconds(rotation.accessTokenExpiresInSeconds()), confirmedBinding,
                        rotation.idToken()),
                "applying the binding the refreshed token actually carries must not be read as a downgrade")
                .orElseThrow(() -> new AssertionError("the session must still hold a bundle after applyRefresh"));

        assertAll("sender constraint preserved across the refresh",
                () -> assertEquals(Optional.of(acquiredBinding), refreshed.binding(),
                        "the stored bundle must still carry the original cnf.jkt"),
                () -> assertNotEquals(stored.accessToken(), refreshed.accessToken(),
                        "the session must hold the refreshed access token"),
                () -> assertNotEquals(stored.refreshToken(), refreshed.refreshToken(),
                        "the session must hold the rotated refresh token"),
                () -> assertEquals(Optional.of(acquiredBinding), manager.get(sessionId).flatMap(StoredToken::binding),
                        "the binding must be visible through the store, not only on the returned bundle"));
    }

    @Test
    @DisplayName("Should refuse the coordinator refresh, which applies no confirmed binding at all")
    void shouldRefuseCoordinatorRefreshThatAppliesNoConfirmedBinding() {
        String sessionId = newSessionId();
        StoredToken stored = storeBoundSession(sessionId);

        IllegalStateException refusal = assertThrows(IllegalStateException.class,
                () -> manager.refresh(sessionId, RefreshEngineSupport.providerMetadata(), dpopRefreshFlow,
                        new RevocationClient(configuration), idBridge,
                        RefreshEngineSupport.clientAuthentication(configuration)),
                "the plain-bearer coordinator must fail closed on a sender-constrained bundle");

        assertAll("fail-closed coordinator refusal",
                () -> assertTrue(refusal.getMessage().contains("cnf binding"),
                        "the refusal must name the stale cnf binding it refused to preserve, was: "
                                + refusal.getMessage()),
                () -> assertEquals(Optional.of(acquiredBinding),
                        manager.get(sessionId).flatMap(StoredToken::binding),
                        "the refused refresh must leave the original bound bundle untouched"),
                () -> assertEquals(Optional.of(stored.accessToken()),
                        manager.get(sessionId).map(StoredToken::accessToken),
                        "no refreshed material may be written when the transform refused"));
    }

    /**
     * Acquires a genuinely DPoP-bound bundle from {@code dpop-client} over the test-owned proof key and
     * stores it under {@code sessionId} with the binding the acquired token actually confirms.
     *
     * @param sessionId the session to seed
     * @return the stored bundle
     */
    private StoredToken storeBoundSession(String sessionId) {
        TestRealm.TokenResponse acquired =
                TestRealm.createDpopRealm().obtainDpopBoundToken(new DpopProofHelper(proofKey));
        assertNotNull(acquired.refreshToken(), "the DPoP-bound acquisition must issue a refresh token");
        assertEquals(Optional.of(acquiredBinding), confirmedBindingOf(acquired.accessToken()),
                "the acquisition must yield a token genuinely bound to the test-owned proof key");

        StoredToken stored = new StoredToken(acquired.accessToken(), acquired.refreshToken(),
                acquired.idToken(), acquiredBinding,
                Instant.now().plusSeconds(acquired.expiresInSeconds()));
        manager.store(sessionId, stored);
        return stored;
    }

    /**
     * Reads the sender-constraint a token actually confirms, rather than assuming the one the client
     * asked for. An empty result means the authorization server issued a plain bearer token — which is
     * precisely the downgrade {@code StoredToken.refreshed} exists to refuse.
     *
     * @param jwt the raw, signed JWT to inspect
     * @return the DPoP binding carried in {@code cnf.jkt}, or empty when the token carries none
     */
    private static Optional<ConstraintBinding> confirmedBindingOf(String jwt) {
        String[] segments = jwt.split("\\.");
        String claims = new String(Base64.getUrlDecoder().decode(segments[1]), StandardCharsets.UTF_8);
        Matcher matcher = JKT_CLAIM.matcher(claims);
        return matcher.find() ? Optional.of(ConstraintBinding.dpop(matcher.group(1))) : Optional.empty();
    }

    private static String newSessionId() {
        return UUID.randomUUID().toString();
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

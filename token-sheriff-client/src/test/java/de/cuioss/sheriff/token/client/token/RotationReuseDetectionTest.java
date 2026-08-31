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

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.flow.TokenEndpointClient;
import de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.RevocationClient;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wired reuse-detection / revoke-on-reuse / single-flight / ID-token-consistency contract for the
 * lifecycle refresh path ({@code CLIENT-5} / {@code CLIENT-22}, OIDC Core §12.2) — deliverable 7.
 * <p>
 * Where {@link RefreshConcurrencyTest} pins the {@link RefreshTokenFamily} primitive in isolation,
 * this test drives {@link TokenLifecycleManager#refresh} end to end over the real
 * {@link RefreshFlow} (a mock token endpoint serving pipeline-validatable JWTs) and asserts the wired
 * behaviour the deliverable adds: a replayed superseded token drives RFC 7009 revocation and a
 * fail-closed store clear; a benign concurrent refresh collapses onto a single redeem instead of
 * self-classifying as reuse; and a refreshed ID token inconsistent with the refreshed access token is
 * refused rather than carried forward.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("Wired refresh: reuse revocation, single-flight, and ID-token consistency")
class RotationReuseDetectionTest {

    private static final int SINGLE_FLIGHT_THREADS = 8;

    @Getter
    private final TokenDispatcher moduleDispatcher = new TokenDispatcher();

    private TestTokenHolder accessHolder;
    private TestTokenHolder idHolder;
    private TokenValidationBridge accessBridge;
    private IdTokenValidationBridge idBridge;

    @BeforeEach
    void setUp() {
        accessHolder = TestTokenGenerators.accessTokens().next();
        idHolder = TestTokenGenerators.idTokens().next();
        TokenValidator validator = TokenValidator.builder().issuerConfig(accessHolder.getIssuerConfig()).build();
        accessBridge = new TokenValidationBridge(validator);
        idBridge = new IdTokenValidationBridge(validator);
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

    private static ProviderMetadata metadata(URIBuilder uriBuilder) {
        var metadata = new ProviderMetadata();
        metadata.tokenEndpoint = uriBuilder.addPathSegments("oidc", "token").buildAsString();
        metadata.revocationEndpoint = uriBuilder.addPathSegment("revoke").buildAsString();
        return metadata;
    }

    private RefreshFlow refreshFlow(ClientConfiguration config) {
        return new RefreshFlow(config, new TokenEndpointClient(config), accessBridge, clientAuth(config));
    }

    private static ClientSecretBasicAuth clientAuth(ClientConfiguration config) {
        return new ClientSecretBasicAuth(config.getClientId(), config.getClientSecret());
    }

    private static TokenLifecycleManager manager() {
        return new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
    }

    private static StoredToken bearerBundle(String refreshToken, String idToken) {
        return new StoredToken(Generators.letterStrings(20, 40).next(), refreshToken, idToken, null, null, null);
    }

    @Test
    @DisplayName("Should revoke the family at the AS and clear the store when a superseded token is replayed")
    void shouldRevokeAndClearOnReuse(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        String rt2 = Generators.letterStrings(20, 40).next();

        manager.store(session, bearerBundle(rt1, null));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));
        manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config));

        // Roll the store back to the now-superseded token while the family stays at rt2, then present it.
        manager.store(session, bearerBundle(rt1, null));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
                Generators.letterStrings(20, 40).next(), null, 300));
        var clientAuth = clientAuth(config);

        assertThrows(ClientProtocolException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("reuse response",
                () -> assertTrue(revocationClient.revoked(rt1),
                        "the reused refresh token is revoked at the AS (RFC 7009)"),
                () -> assertTrue(manager.get(session).isEmpty(),
                        "the store is cleared fail-closed on detected reuse"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                "revoking the family at the authorization server");
    }

    @Test
    @DisplayName("Should still fail closed and propagate reuse when the AS revocation itself throws")
    void shouldFailClosedWhenRevocationThrows(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new ThrowingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        String rt2 = Generators.letterStrings(20, 40).next();

        manager.store(session, bearerBundle(rt1, null));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));
        manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config));

        // Roll the store back to the now-superseded token while the family stays at rt2, then present it.
        manager.store(session, bearerBundle(rt1, null));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
                Generators.letterStrings(20, 40).next(), null, 300));
        var clientAuth = clientAuth(config);

        assertThrows(ClientProtocolException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth),
                "a best-effort revocation failure must not mask the reuse signal to the caller");

        assertAll("fail-closed despite revocation failure",
                () -> assertTrue(revocationClient.attempted(rt1),
                        "the RFC 7009 revocation of the reused token was attempted"),
                () -> assertTrue(manager.get(session).isEmpty(),
                        "the store is still cleared fail-closed when the AS revocation throws"));
    }

    @Test
    @DisplayName("Should collapse a concurrent refresh onto one redeem without revoking the family")
    void shouldNotMisclassifyBenignRaceAsReuse(URIBuilder uriBuilder) throws Exception {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        String rt2 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, null));

        CountDownLatch allStarted = new CountDownLatch(SINGLE_FLIGHT_THREADS);
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));
        moduleDispatcher.blockUntil(allStarted);

        ExecutorService pool = Executors.newFixedThreadPool(SINGLE_FLIGHT_THREADS);
        List<Future<Optional<StoredToken>>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < SINGLE_FLIGHT_THREADS; i++) {
                futures.add(pool.submit(() -> {
                    allStarted.countDown();
                    return manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config));
                }));
            }
            for (Future<Optional<StoredToken>> future : futures) {
                Optional<StoredToken> result = future.get(10, TimeUnit.SECONDS);
                assertEquals(rt2, result.orElseThrow().refreshToken(),
                        "every concurrent caller observes the single rotated bundle, not a reuse failure");
            }
        } finally {
            pool.shutdownNow();
        }

        assertAll("single-flight outcome",
                () -> assertEquals(1, moduleDispatcher.getCallCounter(),
                        "the concurrent refresh redeems the token exactly once (single-flight)"),
                () -> assertFalse(revocationClient.revokedAny(),
                        "a benign race must not trigger a revocation"),
                () -> assertEquals(rt2, manager.get(session).orElseThrow().refreshToken(),
                        "the session holds the single rotated token"));
    }

    @Test
    @DisplayName("Should refuse the refresh and keep the stored bundle when the refreshed ID token sub differs")
    void shouldRejectInconsistentRefreshedIdToken(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String subject = Generators.letterStrings(10, 15).next();
        String otherSubject = subject + Generators.letterStrings(3, 5).next();
        accessHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString(subject));
        idHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString(otherSubject));
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        String originalIdToken = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, originalIdToken));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
                Generators.letterStrings(20, 40).next(), idHolder.getRawToken(), 300));
        var clientAuth = clientAuth(config);

        assertThrows(IllegalStateException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("rejected refresh keeps the pre-refresh state",
                () -> assertEquals(rt1, manager.get(session).orElseThrow().refreshToken(),
                        "the pre-refresh token is kept when the refreshed ID token is refused"),
                () -> assertEquals(originalIdToken, manager.get(session).orElseThrow().idToken(),
                        "the pre-refresh ID token is not replaced by an inconsistent one"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                "inconsistent with the refreshed access token");
    }

    @Test
    @DisplayName("Should carry a consistent refreshed ID token forward, replacing the pre-refresh one")
    void shouldCarryConsistentRefreshedIdTokenForward(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String subject = Generators.letterStrings(10, 15).next();
        accessHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString(subject));
        idHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString(subject));
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, Generators.letterStrings(20, 40).next()));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
                Generators.letterStrings(20, 40).next(), idHolder.getRawToken(), 300));

        StoredToken refreshed = manager
                .refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config))
                .orElseThrow();

        assertEquals(idHolder.getRawToken(), refreshed.idToken(),
                "a §12.2-consistent refreshed ID token replaces the pre-refresh one");
    }

    @Test
    @DisplayName("Should advance the current token across a successful family rotation")
    void shouldAdvanceOnRotation() {
        String initial = Generators.letterStrings(20, 40).next();
        String next = Generators.letterStrings(20, 40).next();
        var family = new RefreshTokenFamily(initial);

        family.rotate(initial, next);

        assertAll("after rotation",
                () -> assertFalse(family.isRevoked(), "a valid rotation must not revoke the family"),
                () -> assertEquals(next, family.currentToken(), "the rotated token must become current"));
    }

    @Test
    @DisplayName("Should revoke the family and fail closed when a superseded token is replayed against it")
    void shouldRevokeFamilyOnReuse() {
        String initial = Generators.letterStrings(20, 40).next();
        String next = Generators.letterStrings(20, 40).next();
        String attackerNext = Generators.letterStrings(20, 40).next();
        var family = new RefreshTokenFamily(initial);
        family.rotate(initial, next);

        assertThrows(ClientProtocolException.class, () -> family.rotate(initial, attackerNext),
                "replaying the superseded token must fail closed");
        assertAll("post-reuse state",
                () -> assertTrue(family.isRevoked(), "reuse must revoke the family"),
                () -> assertThrows(ClientProtocolException.class, family::currentToken,
                        "a revoked family must not expose a current token"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Refresh token reuse detected");
    }

    @Test
    @DisplayName("Should reject invalid tokens and non-rotating successors on the family primitive")
    void shouldRejectInvalidTokens() {
        var family = new RefreshTokenFamily(Generators.letterStrings(20, 40).next());
        var presented = Generators.letterStrings(20, 40).next();
        var freshFamily = new RefreshTokenFamily(presented);
        var rotationSuccessor = Generators.letterStrings(20, 40).next();
        assertAll("token validation",
                () -> assertThrows(NullPointerException.class, () -> new RefreshTokenFamily(null)),
                () -> assertThrows(IllegalArgumentException.class, () -> new RefreshTokenFamily("  ")),
                () -> assertThrows(NullPointerException.class,
                        () -> family.rotate(null, rotationSuccessor)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> freshFamily.rotate(presented, presented)));
    }

    /**
     * Records the tokens passed to {@link RevocationClient#revoke} without issuing any HTTP, so a
     * wired reuse test asserts the RFC 7009 revocation was driven without standing up a second live
     * endpoint.
     */
    static final class RecordingRevocationClient extends RevocationClient {

        private final List<String> revokedTokens = Collections.synchronizedList(new ArrayList<>());

        RecordingRevocationClient(ClientConfiguration configuration) {
            super(configuration);
        }

        @Override
        public void revoke(String revocationEndpoint, String token, String tokenTypeHint,
                ClientAuthentication clientAuthentication) {
            revokedTokens.add(token);
        }

        boolean revoked(String token) {
            return revokedTokens.contains(token);
        }

        boolean revokedAny() {
            return !revokedTokens.isEmpty();
        }
    }

    /**
     * Records the attempted revocation and then throws, so a wired reuse test can assert the
     * best-effort {@code catch (RuntimeException)} in {@code revokeReusedFamily} still fails closed:
     * the reuse signal propagates and the store is cleared even when the RFC 7009 revocation fails.
     */
    static final class ThrowingRevocationClient extends RevocationClient {

        private final List<String> attemptedTokens = Collections.synchronizedList(new ArrayList<>());

        ThrowingRevocationClient(ClientConfiguration configuration) {
            super(configuration);
        }

        @Override
        public void revoke(String revocationEndpoint, String token, String tokenTypeHint,
                ClientAuthentication clientAuthentication) {
            attemptedTokens.add(token);
            throw new IllegalStateException("simulated AS revocation failure");
        }

        boolean attempted(String token) {
            return attemptedTokens.contains(token);
        }
    }

}

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

import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
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

import java.util.ArrayList;
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
 * lifecycle refresh path ({@code CLIENT-5} / {@code CLIENT-22}, OIDC Core §12.2).
 * <p>
 * Where {@link RotationReuseDetectionTest} pins the {@link RefreshTokenFamily} primitive in
 * isolation, this test drives {@link TokenLifecycleManager#refresh} end to end over the real
 * {@link RefreshFlow} (a mock token endpoint serving pipeline-validatable JWTs) and asserts the wired
 * behaviour: a replayed superseded token drives RFC 7009 revocation and a fail-closed store clear; a
 * benign concurrent refresh collapses onto a single redeem instead of self-classifying as reuse; and
 * a refreshed ID token inconsistent with the refreshed access token is refused rather than carried
 * forward.
 * <p>
 * It also carries the matched control pair for the refresh-path identity binding: a refresh whose
 * access token substitutes the principal is refused and leaves the stored bundle intact, while a
 * refresh naming the bound principal is accepted and rotates it. The pair is matched by construction,
 * so deleting the guard turns the negative control red rather than leaving both green.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("Wired refresh: identity binding, reuse revocation, single-flight, and ID-token consistency")
class RefreshAdversarialTest extends RefreshTestSupport {

    private static final int SINGLE_FLIGHT_THREADS = 8;

    @BeforeEach
    void setUp() {
        initRefreshFixture();
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
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));
        manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config));

        // Roll the store back to the now-superseded token while the family stays at rt2, then present it.
        manager.store(session, bearerBundle(rt1, null));
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
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
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));
        manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config));

        // Roll the store back to the now-superseded token while the family stays at rt2, then present it.
        manager.store(session, bearerBundle(rt1, null));
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
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
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));
        getModuleDispatcher().blockUntil(allStarted);

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
                () -> assertEquals(1, getModuleDispatcher().getCallCounter(),
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
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
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
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
                Generators.letterStrings(20, 40).next(), idHolder.getRawToken(), 300));

        StoredToken refreshed = manager
                .refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config))
                .orElseThrow();

        assertEquals(idHolder.getRawToken(), refreshed.idToken(),
                "a §12.2-consistent refreshed ID token replaces the pre-refresh one");
    }

    @Test
    @DisplayName("Should refuse the refresh and keep the stored bundle when the refreshed access token names another principal")
    void shouldRefuseRefreshThatSubstitutesTheSubject(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String boundSubject = Generators.letterStrings(10, 15).next();
        accessHolder.withClaim(ClaimName.SUBJECT.getName(),
                ClaimValue.forPlainString(boundSubject + Generators.letterStrings(3, 5).next()));
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        manager.store(session, boundBundle(rt1, boundSubject));
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
                Generators.letterStrings(20, 40).next(), null, 300));
        var clientAuth = clientAuth(config);

        var thrown = assertThrows(IllegalStateException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("substituted principal is refused before it reaches the store",
                () -> assertTrue(thrown.getMessage().contains("refusing to re-point a live session at another subject"),
                        "the refusal must name the identity binding, not merely throw"),
                () -> assertEquals(rt1, manager.get(session).orElseThrow().refreshToken(),
                        "the pre-refresh bundle is kept when the refreshed principal differs"),
                () -> assertEquals(boundSubject, manager.get(session).orElseThrow().subject(),
                        "the session stays bound to its original principal"));
    }

    @Test
    @DisplayName("Should accept the refresh and rotate the bundle when the refreshed access token names the bound principal")
    void shouldAcceptRefreshThatKeepsTheSubject(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String boundSubject = Generators.letterStrings(10, 15).next();
        accessHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString(boundSubject));
        String session = Generators.letterStrings(10, 20).next();
        String rt2 = Generators.letterStrings(20, 40).next();
        manager.store(session, boundBundle(Generators.letterStrings(20, 40).next(), boundSubject));
        getModuleDispatcher().respondWith(
                TokenDispatcher.tokenResponse(accessHolder.getRawToken(), rt2, null, 300));

        StoredToken refreshed = manager
                .refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config))
                .orElseThrow();

        assertAll("matching principal rotates the bundle",
                () -> assertEquals(rt2, refreshed.refreshToken(),
                        "a refresh naming the bound principal rotates the credentials"),
                () -> assertEquals(boundSubject, refreshed.subject(),
                        "the bound principal survives the rotation unchanged"));
    }

    @Test
    @DisplayName("Should refuse the refresh when the refreshed ID token issuer differs from the refreshed access token")
    void shouldRejectRefreshedIdTokenFromAnotherIssuer(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String subject = Generators.letterStrings(10, 15).next();
        accessHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString(subject));
        idHolder.withClaim(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString(subject));
        idHolder.withClaim(ClaimName.ISSUER.getName(),
                ClaimValue.forPlainString("https://sibling-issuer.example.com"));
        // Both issuers are registered, so the ID token passes pipeline validation on its own merits and
        // the refusal can only come from the §12.2 'iss' cross-check against the refreshed access token.
        var crossIssuerBridge = new IdTokenValidationBridge(TokenValidator.builder()
                .issuerConfig(accessHolder.getIssuerConfig())
                .issuerConfig(idHolder.getIssuerConfig())
                .build());
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        String originalIdToken = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(rt1, originalIdToken));
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
                Generators.letterStrings(20, 40).next(), idHolder.getRawToken(), 300));
        var clientAuth = clientAuth(config);

        var thrown = assertThrows(IllegalStateException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, crossIssuerBridge, clientAuth));

        assertAll("cross-issuer refreshed ID token is refused",
                () -> assertTrue(thrown.getMessage().contains("OIDC Core §12.2"),
                        "the refusal must name the §12.2 consistency check, not merely throw"),
                () -> assertEquals(originalIdToken, manager.get(session).orElseThrow().idToken(),
                        "the pre-refresh ID token is not replaced by a foreign-issuer one"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                "inconsistent with the refreshed access token");
    }

    @Test
    @DisplayName("Should treat a blank refreshed id_token as absent rather than validating it")
    void shouldTreatBlankRefreshedIdTokenAsAbsent(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadata(uriBuilder);
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        TokenLifecycleManager manager = manager();
        String session = Generators.letterStrings(10, 20).next();
        String originalIdToken = Generators.letterStrings(20, 40).next();
        manager.store(session, bearerBundle(Generators.letterStrings(20, 40).next(), originalIdToken));
        // A blank id_token would fail pipeline validation outright; the refresh succeeding is the proof
        // that the isBlank branch short-circuits before the bridge is ever consulted.
        getModuleDispatcher().respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(),
                Generators.letterStrings(20, 40).next(), "", 300));

        StoredToken refreshed = manager
                .refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config))
                .orElseThrow();

        assertEquals(originalIdToken, refreshed.idToken(),
                "a blank refreshed id_token is treated as omitted, so the stored ID token is kept");
        LogAsserts.assertNoLogMessagePresent(TestLogLevel.WARN, TokenLifecycleManager.class);
    }

    /** A bundle bound to {@code subject}, so the refresh-path identity check has a baseline to enforce. */
    private static StoredToken boundBundle(String refreshToken, String subject) {
        return new StoredToken(Generators.letterStrings(20, 40).next(), refreshToken, null, null, null,
                subject);
    }
}

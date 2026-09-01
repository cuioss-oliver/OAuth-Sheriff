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

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.dpop.DpopProofGenerator;
import de.cuioss.sheriff.token.client.dpop.SenderConstraint;
import de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.RevocationClient;
import de.cuioss.sheriff.token.client.lifecycle.StoredToken;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wired-flow scaffold ({@code S0}) plus the DPoP wiring negative/positive path cases ({@code H3}):
 * proves the {@link WiredFlowTestSupport} harness drives the real flow orchestrators end to end
 * through the recording dispatcher, exactly as the CDI-produced bean graph would.
 * <p>
 * It carries the shapes the per-defence wiring deliverables build on:
 * <ul>
 *   <li>a <strong>guarded exchange</strong> that redeems a valid callback and returns validated,
 *       nonce-bound tokens — the token endpoint is called exactly once;</li>
 *   <li>a <strong>negative path</strong> where a tampered callback is refused <em>before</em> the
 *       token endpoint is ever called ({@link WiredFlowTestSupport#assertRefusedBeforeTokenEndpoint}),
 *       so a defence deleted from the wired path would fail here;</li>
 *   <li>the <strong>DPoP wiring</strong> ({@code H3}) that attaches a proof to the token request on the
 *       executable refresh path and retries a {@code use_dpop_nonce} challenge — so a DPoP binding
 *       deleted from the wired transport, or a nonce challenge surfaced as an opaque failure, fails
 *       here.</li>
 * </ul>
 * Named {@code *IT} so it runs in the integration-test phase.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("Wired-flow scaffold: real flows driven end to end, incl. DPoP wiring")
class WiredFlowNegativePathIT extends WiredFlowTestSupport {

    @BeforeEach
    void setUp() {
        initWiredFlow();
    }

    /**
     * Redeclares the recording dispatcher accessor on this concrete test class so
     * {@code @EnableMockWebServer} discovers it — the framework resolves {@code getModuleDispatcher()}
     * from the test class's own declared methods and does not walk up to the abstract
     * {@link WiredFlowTestSupport} base, so the inherited accessor alone would leave the mock server
     * dispatcher unregistered (every {@code /token} call would return HTTP 418).
     *
     * @return the shared recording token-endpoint dispatcher
     */
    @Override
    public RecordingTokenEndpointDispatcher getModuleDispatcher() {
        return super.getModuleDispatcher();
    }

    @Test
    @DisplayName("Should drive a guarded exchange end to end and call the token endpoint exactly once")
    void shouldDriveGuardedExchange(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        FlowContext context = FlowContext.create(REDIRECT_URI);
        idHolder.withClaim("nonce", ClaimValue.forPlainString(context.nonce()));
        getModuleDispatcher().success(accessHolder.getRawToken(), idHolder.getRawToken(), null, 300);
        String code = Generators.letterStrings(20, 40).next();
        var callback = new CallbackParameters(code, context.state(), null, null, null);

        AuthorizationCodeFlow.AuthenticationResult result =
                authorizationCodeFlow(config).exchange(metadataWithTokenEndpoint(uriBuilder), context, callback,
                        clientAuth(config));

        assertAll("guarded exchange",
                () -> assertNotNull(result.accessToken(), "a validated access token must be returned"),
                () -> assertNotNull(result.idToken(), "a validated, nonce-bound ID token must be returned"),
                () -> getModuleDispatcher().assertCalled(1));
    }

    @Test
    @DisplayName("Should refuse a state-mismatched callback before the token endpoint is called")
    void shouldRefuseStateMismatchBeforeTokenCall(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        FlowContext context = FlowContext.create(REDIRECT_URI);
        getModuleDispatcher().success(accessHolder.getRawToken(), idHolder.getRawToken(), null, 300);
        var forgedCallback = new CallbackParameters(Generators.letterStrings(20, 40).next(),
                Generators.letterStrings(20, 40).next(), null, null, null);
        var flow = authorizationCodeFlow(config);
        var metadata = metadataWithTokenEndpoint(uriBuilder);
        var clientAuth = clientAuth(config);

        assertRefusedBeforeTokenEndpoint(ClientProtocolException.class,
                () -> flow.exchange(metadata, context, forgedCallback, clientAuth));
    }

    @Test
    @DisplayName("Should refuse to redeem the code when the callback iss is another AS (RFC 9207 mix-up, T-MIXUP)")
    void shouldRefuseIssMismatchBeforeTokenCall(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        FlowContext context = FlowContext.create(REDIRECT_URI);
        getModuleDispatcher().success(accessHolder.getRawToken(), idHolder.getRawToken(), null, 300);
        var mixedUpCallback = new CallbackParameters(Generators.letterStrings(20, 40).next(), context.state(),
                null, null, "https://attacker.example.com");
        var flow = authorizationCodeFlow(config);
        var metadata = metadataWithTokenEndpoint(uriBuilder);
        var clientAuth = clientAuth(config);

        assertRefusedBeforeTokenEndpoint(ClientProtocolException.class,
                () -> flow.exchange(metadata, context, mixedUpCallback, clientAuth));
    }

    @Test
    @DisplayName("Should refuse redemption when the AS advertises iss support but the callback omits it")
    void shouldRefuseMissingRequiredIssBeforeTokenCall(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        FlowContext context = FlowContext.create(REDIRECT_URI);
        getModuleDispatcher().success(accessHolder.getRawToken(), idHolder.getRawToken(), null, 300);
        ProviderMetadata metadata = metadataWithTokenEndpoint(uriBuilder);
        metadata.authorizationResponseIssParameterSupported = true;
        var callbackWithoutIss = new CallbackParameters(Generators.letterStrings(20, 40).next(), context.state(),
                null, null, null);
        var flow = authorizationCodeFlow(config);
        var clientAuth = clientAuth(config);

        assertRefusedBeforeTokenEndpoint(ClientProtocolException.class,
                () -> flow.exchange(metadata, context, callbackWithoutIss, clientAuth));
    }

    @Test
    @DisplayName("Should attach a DPoP proof to the wired refresh request so a deleted binding is observable")
    void shouldAttachDpopProofToWiredRefresh(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        getModuleDispatcher().success(accessHolder.getRawToken(), null,
                Generators.letterStrings(20, 40).next(), 300);
        RefreshFlow flow = dpopRefreshFlow(config);

        flow.refresh(metadataWithTokenEndpoint(uriBuilder), Generators.letterStrings(20, 40).next());

        String proof = getModuleDispatcher().lastRecordedDpopHeader();
        assertAll("wired DPoP refresh",
                () -> getModuleDispatcher().assertCalled(1),
                () -> assertNotNull(proof, "the wired refresh request carries a DPoP proof header"),
                () -> assertEquals(3, proof.split("\\.").length, "the DPoP header is a compact proof JWT"));
    }

    @Test
    @DisplayName("Should retry the wired token request with the DPoP-Nonce echoed on a use_dpop_nonce challenge")
    void shouldRetryWiredRefreshWithChallengedNonce(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        String nonce = Generators.letterStrings(20, 40).next();
        getModuleDispatcher().success(accessHolder.getRawToken(), null,
                Generators.letterStrings(20, 40).next(), 300);
        getModuleDispatcher().challengeWithNonceOnce(nonce);
        RefreshFlow flow = dpopRefreshFlow(config);

        flow.refresh(metadataWithTokenEndpoint(uriBuilder), Generators.letterStrings(20, 40).next());

        String retriedProof = getModuleDispatcher().lastRecordedDpopHeader();
        assertAll("nonce-challenged retry",
                () -> getModuleDispatcher().assertCalled(2),
                () -> assertNotNull(retriedProof, "the retried request carries a fresh DPoP proof"),
                () -> assertTrue(decodePayload(retriedProof).contains("\"nonce\":\"" + nonce + "\""),
                        "the retried proof echoes the challenged DPoP-Nonce"));
    }

    @Test
    @DisplayName("Should refuse a wired refresh that replays a superseded token and revoke the family at the AS")
    void shouldRefuseRotatedTokenReuseOnWiredRefresh(URIBuilder uriBuilder) {
        ClientConfiguration config = config();
        ProviderMetadata metadata = metadataWithTokenEndpoint(uriBuilder);
        metadata.revocationEndpoint = uriBuilder.addPathSegment("revoke").buildAsString();
        RefreshFlow flow = refreshFlow(config);
        var revocationClient = new RecordingRevocationClient(config);
        var manager = new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
        String session = Generators.letterStrings(10, 20).next();
        String rt1 = Generators.letterStrings(20, 40).next();
        String rt2 = Generators.letterStrings(20, 40).next();

        manager.store(session, new StoredToken(Generators.letterStrings(20, 40).next(), rt1, null, null, null, null));
        getModuleDispatcher().success(accessHolder.getRawToken(), null, rt2, 300);
        manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth(config));

        // Replay the superseded token: roll the store back to rt1 while the family stays at rt2.
        manager.store(session, new StoredToken(Generators.letterStrings(20, 40).next(), rt1, null, null, null, null));
        getModuleDispatcher().success(accessHolder.getRawToken(), null, Generators.letterStrings(20, 40).next(), 300);
        var clientAuth = clientAuth(config);

        assertThrows(ClientProtocolException.class,
                () -> manager.refresh(session, metadata, flow, revocationClient, idBridge, clientAuth));

        assertAll("wired reuse refusal",
                () -> assertTrue(revocationClient.revoked(rt1),
                        "the wired refresh revokes the reused token at the AS (RFC 7009)"),
                () -> assertTrue(manager.get(session).isEmpty(),
                        "the wired refresh clears the store fail-closed on detected reuse"));
    }

    /**
     * Records the tokens passed to {@link RevocationClient#revoke} without issuing HTTP, so the wired
     * reuse case asserts the RFC 7009 revocation was driven without a second live endpoint.
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
    }

    /**
     * Assembles a DPoP-constrained refresh flow, exactly as the CDI producer does when the client is
     * configured for sender-constrained tokens.
     */
    private RefreshFlow dpopRefreshFlow(ClientConfiguration config) {
        SenderConstraint constraint = SenderConstraint.dpop(new DpopProofGenerator(rsaKeyPair(), "RS256"));
        return new RefreshFlow(config, new TokenEndpointClient(config), accessBridge, clientAuth(config), constraint);
    }

    private static KeyPair rsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } /*~~(TODO: Catch specific not Exception. Suppress: // cui-rewrite:disable InvalidExceptionUsageRecipe)~~>*/ catch (Exception e) {
            throw new IllegalStateException("RSA key pair generation failed", e);
        }
    }

    private static String decodePayload(String proof) {
        String[] segments = proof.split("\\.");
        return new String(Base64.getUrlDecoder().decode(segments[1]), StandardCharsets.UTF_8);
    }
}

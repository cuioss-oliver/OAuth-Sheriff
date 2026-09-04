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
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.dispatcher.TokenDispatcher;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Shared fixture for the <em>wired refresh</em> test tier: the assembled
 * {@link TokenLifecycleManager} / {@link RefreshFlow} pair driven end to end against a mock token
 * endpoint serving real, pipeline-validatable JWTs.
 * <p>
 * Extracted so the wired refresh contract can be pinned across several focused test classes without
 * either redeclaring the fixture or growing a single class past the module's 400-line budget. It
 * follows the {@code flow.WiredFlowTestSupport} precedent: a package-private abstract base carrying
 * the {@code @EnableMockWebServer} dispatcher accessor and the generated token holders, which a
 * subclass initializes from its own {@code @BeforeEach} via {@link #initRefreshFixture()}.
 *
 * @since 1.0
 */
abstract class RefreshTestSupport {

    @Getter
    private final TokenDispatcher moduleDispatcher = new TokenDispatcher();

    /** The generated access-token holder; its issuer config backs the validator. */
    protected TestTokenHolder accessHolder;

    /** The generated ID-token holder; validated against the same validator. */
    protected TestTokenHolder idHolder;

    /** The access-token validation bridge assembled over the shared validator. */
    protected TokenValidationBridge accessBridge;

    /** The ID-token validation bridge assembled over the same validator. */
    protected IdTokenValidationBridge idBridge;

    /**
     * Generates a fresh access/ID token pair, assembles both validation bridges over a validator
     * bound to the access token's issuer config, and resets the shared dispatcher. Subclasses call
     * this from their own {@code @BeforeEach}.
     */
    protected void initRefreshFixture() {
        accessHolder = TestTokenGenerators.accessTokens().next();
        idHolder = TestTokenGenerators.idTokens().next();
        TokenValidator validator = TokenValidator.builder().issuerConfig(accessHolder.getIssuerConfig()).build();
        accessBridge = new TokenValidationBridge(validator);
        idBridge = new IdTokenValidationBridge(validator);
        moduleDispatcher.reset();
    }

    /** A confidential client configuration bound to a generated issuer, permitting cleartext http. */
    protected static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer("https://" + Generators.letterStrings(3, 10).next() + ".example.com")
                .clientId(Generators.letterStrings(5, 12).next())
                .clientSecret(Generators.letterStrings(8, 20).next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .allowInsecureHttp(true)
                .build();
    }

    /** Provider metadata pointing the token and revocation endpoints at the mock server. */
    protected static ProviderMetadata metadata(URIBuilder uriBuilder) {
        var metadata = new ProviderMetadata();
        metadata.tokenEndpoint = uriBuilder.addPathSegments("oidc", "token").buildAsString();
        metadata.revocationEndpoint = uriBuilder.addPathSegment("revoke").buildAsString();
        return metadata;
    }

    /** The real refresh flow, assembled over the access-token bridge from {@link #initRefreshFixture()}. */
    protected RefreshFlow refreshFlow(ClientConfiguration config) {
        return new RefreshFlow(config, new TokenEndpointClient(config), accessBridge, clientAuth(config));
    }

    /** The shared-secret client authentication matching {@link #config()}. */
    protected static ClientSecretBasicAuth clientAuth(ClientConfiguration config) {
        return new ClientSecretBasicAuth(config.getClientId(), config.getClientSecret());
    }

    /** A lifecycle manager over an in-memory store and a real scheduler. */
    protected static TokenLifecycleManager manager() {
        return new TokenLifecycleManager(new InMemoryTokenStore(), new RefreshScheduler());
    }

    /** A plain bearer bundle carrying the supplied refresh and ID tokens and no binding or subject. */
    protected static StoredToken bearerBundle(String refreshToken, String idToken) {
        return new StoredToken(Generators.letterStrings(20, 40).next(), refreshToken, idToken, null, null, null);
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
     * best-effort {@code catch (TransportException)} in {@code revokeAndClearFailClosed} still fails
     * closed: the reuse signal propagates and the store is cleared even when the RFC 7009 revocation
     * fails.
     * <p>
     * The thrown type is {@link TransportException} because that is the only type
     * {@link RevocationClient#revoke} declares — a double that threw an undeclared type would be
     * asserting against a contract the production API does not offer.
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
            throw new TransportException("simulated AS revocation failure");
        }

        boolean attempted(String token) {
            return attemptedTokens.contains(token);
        }
    }
}

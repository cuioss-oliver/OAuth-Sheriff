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
package de.cuioss.sheriff.token.client.quarkus;

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth;
import de.cuioss.sheriff.token.client.auth.ClientSecretPostAuth;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.DiscoveryResolver;
import de.cuioss.sheriff.token.client.flow.AuthorizationCodeFlow;
import de.cuioss.sheriff.token.client.flow.IssValidator;
import de.cuioss.sheriff.token.client.flow.ParClient;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.flow.TokenEndpointClient;
import de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore;
import de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler;
import de.cuioss.sheriff.token.client.lifecycle.RevocationClient;
import de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager;
import de.cuioss.sheriff.token.client.lifecycle.TokenStore;
import de.cuioss.sheriff.token.client.quarkus.config.ClientConfigMapper;
import de.cuioss.sheriff.token.client.quarkus.config.ClientRuntimeConfig;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.client.token.UserInfoClient;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import org.eclipse.microprofile.config.Config;

/**
 * CDI producer that exposes the framework-agnostic {@code token-sheriff-client} engine to Quarkus
 * ({@code CLIENT-21}). The framework binding lives entirely here, outside the engine: the pure-Java
 * flow classes carry no CDI, MicroProfile, or JAX-RS coupling and are assembled from the resolved
 * {@link ClientConfiguration} by the {@code @Produces} methods below.
 * <p>
 * All produced beans are {@link ApplicationScoped} and resolved lazily. The core
 * {@link #clientConfiguration()} producer only demands the configuration when a consumer actually
 * injects an engine bean, so an application that has this extension on the classpath but does not use
 * the client never fails at startup — {@link ClientConfigMapper#isConfigured(Config)} guards the
 * required-property check.
 * <p>
 * The engine entry points that need only the configuration are produced directly
 * ({@link TokenEndpointClient}, {@link DiscoveryResolver}, {@link UserInfoClient},
 * {@link RevocationClient}). Server-side token lifecycle is wired with the default
 * {@link InMemoryTokenStore}; a relying party that needs a shared, persistent store replaces the
 * {@link TokenStore} bean with its own implementation.
 * <p>
 * The full guarded-exchange flow graph is also produced so an application can inject and drive the
 * engine end-to-end ({@code S0}): {@link AuthorizationCodeFlow} and {@link RefreshFlow} are assembled
 * from the {@link TokenValidationBridge} / {@link IdTokenValidationBridge} (backed by the
 * {@link TokenValidator} bean the {@code token-sheriff-validation-quarkus} extension produces), the
 * default {@link ClientAuthentication}, and the produced transport beans, and the flow defences
 * {@link IssValidator} and {@link ParClient} are produced alongside them.
 * <p>
 * Two collaborators are deliberately <em>not</em> produced as application-scoped beans, because their
 * lifecycle is per-request or per-token rather than application-wide:
 * <ul>
 *   <li>{@code SenderConstraint} is a per-request DPoP/mTLS binding built from a per-request proof;
 *       the flow constructs it when it decorates a token request.</li>
 *   <li>{@code RefreshTokenFamily} tracks a single refresh-token rotation chain and is seeded with a
 *       runtime-issued refresh token; a shared application-scoped instance would collapse every
 *       session's refresh chain into one family and is therefore never produced. The refresh path
 *       creates one family per token chain at runtime.</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@ApplicationScoped
public class TokenSheriffClientProducer {

    private static final CuiLogger LOGGER = new CuiLogger(TokenSheriffClientProducer.class);

    private final Config config;

    /**
     * @param config the MicroProfile config carrying the {@link ClientRuntimeConfig} properties; must
     *               not be {@code null}
     */
    public TokenSheriffClientProducer(Config config) {
        this.config = config;
    }

    /**
     * Produces the resolved, immutable client configuration from the {@link ClientRuntimeConfig}
     * properties.
     *
     * @return the resolved client configuration
     * @throws IllegalStateException when the extension is on the classpath but not configured
     */
    @Produces
    @ApplicationScoped
    public ClientConfiguration clientConfiguration() {
        if (!ClientConfigMapper.isConfigured(config)) {
            throw new IllegalStateException("The Token-Sheriff client extension is on the classpath but is not"
                    + " configured. Set '" + ClientRuntimeConfig.ISSUER + "' and '" + ClientRuntimeConfig.CLIENT_ID
                    + "' to enable it.");
        }
        ClientConfiguration clientConfiguration = ClientConfigMapper.map(config);
        LOGGER.debug("Produced ClientConfiguration for issuer '%s'", clientConfiguration.getIssuer());
        return clientConfiguration;
    }

    /**
     * @param clientConfiguration the resolved client configuration
     * @return the token-endpoint transport for the token / refresh / client-credentials exchanges
     */
    @Produces
    @ApplicationScoped
    public TokenEndpointClient tokenEndpointClient(ClientConfiguration clientConfiguration) {
        return new TokenEndpointClient(clientConfiguration);
    }

    /**
     * @param clientConfiguration the resolved client configuration
     * @return the discovery resolver for the issuer's {@code .well-known/openid-configuration}
     */
    @Produces
    @ApplicationScoped
    public DiscoveryResolver discoveryResolver(ClientConfiguration clientConfiguration) {
        return new DiscoveryResolver(clientConfiguration);
    }

    /**
     * @param clientConfiguration the resolved client configuration
     * @return the userinfo client for the OIDC userinfo endpoint
     */
    @Produces
    @ApplicationScoped
    public UserInfoClient userInfoClient(ClientConfiguration clientConfiguration) {
        return new UserInfoClient(clientConfiguration);
    }

    /**
     * @param clientConfiguration the resolved client configuration
     * @return the revocation client for the RFC 7009 revocation endpoint
     */
    @Produces
    @ApplicationScoped
    public RevocationClient revocationClient(ClientConfiguration clientConfiguration) {
        return new RevocationClient(clientConfiguration);
    }

    /**
     * @return the default in-memory server-side token store; replaceable by the relying party
     */
    @Produces
    @ApplicationScoped
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }

    /**
     * @return the proactive-refresh scheduler with its default refresh-lead window
     */
    @Produces
    @ApplicationScoped
    public RefreshScheduler refreshScheduler() {
        return new RefreshScheduler();
    }

    /**
     * @param tokenStore       the server-side token store
     * @param refreshScheduler the proactive-refresh policy
     * @return the token lifecycle manager orchestrating store / refresh / revoke-and-clear
     */
    @Produces
    @ApplicationScoped
    public TokenLifecycleManager tokenLifecycleManager(TokenStore tokenStore, RefreshScheduler refreshScheduler) {
        return new TokenLifecycleManager(tokenStore, refreshScheduler);
    }

    /**
     * Bridges retrieved access tokens into the {@code token-sheriff-validation} pipeline, reusing the
     * {@link TokenValidator} the {@code token-sheriff-validation-quarkus} extension produces.
     *
     * @param tokenValidator the configured multi-issuer validator
     * @return the access-token validation bridge ({@code CLIENT-15})
     */
    @Produces
    @ApplicationScoped
    public TokenValidationBridge tokenValidationBridge(TokenValidator tokenValidator) {
        return new TokenValidationBridge(tokenValidator);
    }

    /**
     * Bridges retrieved ID tokens into the validation pipeline and binds them to the flow
     * {@code nonce}, reusing the shared {@link TokenValidator}.
     *
     * @param tokenValidator the configured multi-issuer validator
     * @return the ID-token validation bridge ({@code CLIENT-2} / {@code CLIENT-15})
     */
    @Produces
    @ApplicationScoped
    public IdTokenValidationBridge idTokenValidationBridge(TokenValidator tokenValidator) {
        return new IdTokenValidationBridge(tokenValidator);
    }

    /**
     * Produces the default client authentication the back-channel flows present. The strategy is
     * derived from the configured {@link ClientAuthMethod}; the shared-secret methods
     * ({@code client_secret_basic} / {@code client_secret_post}) are supported here. Key-based client
     * authentication ({@code private_key_jwt} / {@code tls_client_auth}) is not yet plumbed into the
     * produced bean graph and fails closed rather than silently downgrading to a shared secret.
     *
     * @param clientConfiguration the resolved client configuration
     * @return the client authentication strategy to present on authenticated back-channel requests
     * @throws IllegalStateException if the configured method requires a secret that is absent, or is a
     *                               key-based method not yet plumbed into the produced graph
     */
    @Produces
    @ApplicationScoped
    public ClientAuthentication clientAuthentication(ClientConfiguration clientConfiguration) {
        ClientAuthMethod method = clientConfiguration.getAuthMethod();
        String clientId = clientConfiguration.getClientId();
        return switch (method) {
            case CLIENT_SECRET_BASIC ->
                new ClientSecretBasicAuth(clientId, requireSecret(clientConfiguration, method));
            case CLIENT_SECRET_POST ->
                new ClientSecretPostAuth(clientId, requireSecret(clientConfiguration, method));
            case PRIVATE_KEY_JWT, TLS_CLIENT_AUTH -> throw new IllegalStateException(
                    "client authentication method " + method + " is not yet plumbed into the produced"
                            + " client bean graph; configure a shared-secret method to inject the flow beans");
        };
    }

    /**
     * @return the RFC 9207 {@code iss} mix-up defence ({@code CLIENT-8})
     */
    @Produces
    @ApplicationScoped
    public IssValidator issValidator() {
        return new IssValidator();
    }

    /**
     * @param clientConfiguration the resolved client configuration carrying the TLS policy
     * @return the RFC 9126 pushed-authorization-request client ({@code CLIENT-10})
     */
    @Produces
    @ApplicationScoped
    public ParClient parClient(ClientConfiguration clientConfiguration) {
        return new ParClient(clientConfiguration);
    }

    /**
     * Produces the interactive {@code authorization_code} flow orchestrator, assembled so a guarded
     * exchange (validated access + nonce-bound ID token) can be driven end-to-end ({@code S0}).
     *
     * @param clientConfiguration   the resolved client configuration
     * @param tokenEndpointClient   the token-endpoint transport
     * @param tokenValidationBridge the access-token validation bridge
     * @param idTokenValidationBridge the ID-token validation bridge
     * @param issValidator          the container-managed RFC 9207 {@code iss} mix-up validator
     * @return the wired authorization-code flow
     */
    @Produces
    @ApplicationScoped
    public AuthorizationCodeFlow authorizationCodeFlow(ClientConfiguration clientConfiguration,
            TokenEndpointClient tokenEndpointClient, TokenValidationBridge tokenValidationBridge,
            IdTokenValidationBridge idTokenValidationBridge, IssValidator issValidator) {
        // SenderConstraint is a per-request DPoP/mTLS binding, deliberately NOT produced as an
        // @ApplicationScoped bean (see class Javadoc); the sibling refreshFlow() producer likewise
        // wires RefreshFlow's unconstrained overload. Pass null here to preserve the plain-bearer
        // CDI-wired behaviour — DPoP-bound authorization-code redemption remains available to callers
        // that construct AuthorizationCodeFlow directly with a constraint.
        return new AuthorizationCodeFlow(clientConfiguration, tokenEndpointClient, tokenValidationBridge,
                idTokenValidationBridge, issValidator, null);
    }

    /**
     * Produces the {@code refresh_token} flow orchestrator, assembled so a guarded refresh (validated
     * access token, rotation reported) can be driven end-to-end ({@code S0}).
     *
     * @param clientConfiguration   the resolved client configuration
     * @param tokenEndpointClient   the token-endpoint transport
     * @param tokenValidationBridge the access-token validation bridge
     * @param clientAuthentication  the client authentication strategy to present
     * @return the wired refresh flow
     */
    @Produces
    @ApplicationScoped
    public RefreshFlow refreshFlow(ClientConfiguration clientConfiguration,
            TokenEndpointClient tokenEndpointClient, TokenValidationBridge tokenValidationBridge,
            ClientAuthentication clientAuthentication) {
        return new RefreshFlow(clientConfiguration, tokenEndpointClient, tokenValidationBridge,
                clientAuthentication);
    }

    private static String requireSecret(ClientConfiguration clientConfiguration, ClientAuthMethod method) {
        String secret = clientConfiguration.getClientSecret();
        if (secret == null) {
            throw new IllegalStateException(
                    "client authentication method " + method + " requires a client secret");
        }
        return secret;
    }
}

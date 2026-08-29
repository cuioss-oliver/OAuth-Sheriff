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
import de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.dpop.DpopProofGenerator;
import de.cuioss.sheriff.token.client.dpop.SenderConstraint;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.flow.TokenEndpointClient;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import org.jspecify.annotations.Nullable;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;

/**
 * Assembles the <em>production</em> client engine against the running Keycloak container, so an
 * integration test can drive {@link RefreshFlow} and
 * {@link de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager} through exactly the wiring an
 * application performs — no hand-rolled {@code HttpRequest} to the token endpoint.
 *
 * <h2>The two-base reconciliation</h2>
 * The integration realm is imported with a fixed {@code frontendUrl}, so every token Keycloak signs
 * carries {@link KeycloakUrlSupport#INTERNAL_ISSUER} in its {@code iss} claim — an authority the test
 * JVM cannot reach. The endpoints, in contrast, must be addressed at
 * {@link KeycloakUrlSupport#EXTERNAL_BASE} through the host port mapping. The engine assembled here
 * therefore pins the <em>issuer identity</em> to the internal authority while pointing every
 * <em>endpoint</em> (token, revocation, JWKS) at the external base. Discovery is deliberately not
 * used: a discovery round trip would re-advertise the unreachable internal endpoints.
 *
 * <h2>TLS posture</h2>
 * The container serves a self-signed certificate. Rather than disabling server authentication with a
 * trust-all {@code TrustManager}, this support loads the generated
 * {@code localhost-truststore.p12} and performs full chain validation against it — the trust is
 * narrowed to the known test CA, not switched off.
 */
final class RefreshEngineSupport {

    /** Realm path shared by every endpoint this support addresses. */
    static final String REALM_PATH = "/realms/integration";

    /** Externally reachable token endpoint of the integration realm. */
    static final String TOKEN_ENDPOINT =
            KeycloakUrlSupport.EXTERNAL_BASE + REALM_PATH + "/protocol/openid-connect/token";

    /**
     * Token endpoint as the realm itself advertises it, on the Docker-internal authority.
     * <p>
     * This URL is never connected to from the test JVM — it is the {@code aud} a {@code private_key_jwt}
     * client assertion must carry. Keycloak matches the assertion audience against its own
     * issuer-derived endpoint URL, so an assertion audienced at {@link #TOKEN_ENDPOINT} (the loopback
     * base the request is actually sent to) is rejected with {@code invalid_client / Invalid token
     * audience}. The two-base reconciliation therefore reaches into the client assertion as well.
     */
    static final String INTERNAL_TOKEN_ENDPOINT =
            KeycloakUrlSupport.INTERNAL_BASE + REALM_PATH + "/protocol/openid-connect/token";

    /** Externally reachable RFC 7009 revocation endpoint of the integration realm. */
    static final String REVOCATION_ENDPOINT =
            KeycloakUrlSupport.EXTERNAL_BASE + REALM_PATH + "/protocol/openid-connect/revoke";

    /** Externally reachable JWKS endpoint of the integration realm. */
    static final String JWKS_URI =
            KeycloakUrlSupport.EXTERNAL_BASE + REALM_PATH + "/protocol/openid-connect/certs";

    /** DPoP proof signing algorithm the container advertises and the tests use. */
    static final String DPOP_SIGNING_ALGORITHM = "RS256";

    /** Package prefix identifying a frame inside the production client engine. */
    static final String PRODUCTION_PACKAGE = "de.cuioss.sheriff.token.client.";

    /**
     * Truststore generated by {@code src/main/docker/certificates/generate-truststore.sh}, holding the
     * container's self-signed {@code localhost} certificate. Resolved relative to the module directory,
     * which is the working directory of a Maven-launched test.
     */
    private static final Path TRUSTSTORE_PATH =
            Path.of("src", "main", "docker", "certificates", "localhost-truststore.p12");

    /** Truststore password, fixed by {@code generate-truststore.sh}. */
    private static final char[] TRUSTSTORE_PASSWORD = "localhost-trust".toCharArray();

    private RefreshEngineSupport() {
        // utility class
    }

    /**
     * Builds an {@link SSLContext} that performs full certificate-chain validation against the
     * generated test truststore.
     *
     * @return a chain-validating SSL context trusting only the container's test certificate
     * @throws IllegalStateException if the truststore is missing or cannot be read — the container
     *         fixtures were not generated, which is a setup failure, never a reason to fall back to
     *         an unvalidated context
     */
    static SSLContext chainValidatingSslContext() {
        if (!Files.isReadable(TRUSTSTORE_PATH)) {
            throw new IllegalStateException("Truststore not readable at " + TRUSTSTORE_PATH.toAbsolutePath()
                    + ". Run src/main/docker/certificates/generate-truststore.sh before the integration tests.");
        }
        try (InputStream truststore = Files.newInputStream(TRUSTSTORE_PATH)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(truststore, TRUSTSTORE_PASSWORD);
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            return sslContext;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Failed to build a chain-validating SSLContext from "
                    + TRUSTSTORE_PATH.toAbsolutePath(), e);
        }
    }

    /**
     * @param clientId     the realm client to authenticate as
     * @param clientSecret the client's shared secret
     * @return a {@code client_secret_basic} configuration bound to the realm's internal issuer identity
     *         and carrying the chain-validating trust material
     */
    static ClientConfiguration clientConfiguration(String clientId, String clientSecret) {
        return clientConfiguration(clientId, clientSecret, ClientAuthMethod.CLIENT_SECRET_BASIC);
    }

    /**
     * @param clientId     the realm client to authenticate as
     * @param clientSecret the client's shared secret, or {@code null} for the key-based methods
     *                     ({@code private_key_jwt} / {@code tls_client_auth}) where no shared secret
     *                     exists
     * @param authMethod   the client-authentication method the configuration declares
     * @return a configuration bound to the realm's internal issuer identity and carrying the
     *         chain-validating trust material
     */
    static ClientConfiguration clientConfiguration(String clientId, @Nullable String clientSecret,
            ClientAuthMethod authMethod) {
        return ClientConfiguration.builder()
                .issuer(KeycloakUrlSupport.INTERNAL_ISSUER)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authMethod(authMethod)
                .scope("openid")
                .scope("profile")
                .scope("email")
                .sslContext(chainValidatingSslContext())
                .build();
    }

    /**
     * Provider metadata assembled by hand rather than discovered: the realm advertises its
     * Docker-internal endpoints, which the test JVM cannot reach, so the endpoints are pinned to
     * {@link KeycloakUrlSupport#EXTERNAL_BASE} while the issuer identity stays internal.
     *
     * @return metadata carrying the externally reachable token and revocation endpoints
     */
    static ProviderMetadata providerMetadata() {
        var metadata = new ProviderMetadata();
        metadata.issuer = KeycloakUrlSupport.INTERNAL_ISSUER;
        metadata.tokenEndpoint = TOKEN_ENDPOINT;
        metadata.revocationEndpoint = REVOCATION_ENDPOINT;
        metadata.jwksUri = JWKS_URI;
        return metadata;
    }

    /**
     * Builds a real multi-issuer {@link TokenValidator} for the integration realm.
     * <p>
     * {@code audienceValidationDisabled(true)} because the realm's direct-access grant issues tokens
     * whose audience is the resource server, not the acquiring client; {@code claimSubOptional(false)}
     * keeps the RFC 7519 subject requirement in force, so the validated token is genuinely subject
     * bound. {@code allowLoopbackEgress(true)} is required because the JWKS endpoint is reached over
     * the host loopback port mapping, which the default egress policy rejects.
     *
     * @return a validator that fetches the realm's JWKS over the chain-validated loopback endpoint
     */
    static TokenValidator tokenValidator() {
        HttpJwksLoaderConfig jwksConfig = HttpJwksLoaderConfig.builder()
                .jwksUrl(JWKS_URI)
                .issuerIdentifier(KeycloakUrlSupport.INTERNAL_ISSUER)
                .sslContext(chainValidatingSslContext())
                .allowLoopbackEgress(true)
                .build();
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(KeycloakUrlSupport.INTERNAL_ISSUER)
                .audienceValidationDisabled(true)
                .claimSubOptional(false)
                .httpJwksLoaderConfig(jwksConfig)
                .build();
        return TokenValidator.builder().issuerConfig(issuerConfig).build();
    }

    /**
     * @param validator the shared validator
     * @return the access-token validation bridge the flows validate through
     */
    static TokenValidationBridge accessTokenBridge(TokenValidator validator) {
        return new TokenValidationBridge(validator);
    }

    /**
     * @param validator the shared validator
     * @return the ID-token validation bridge the lifecycle wiring validates refreshed ID tokens through
     */
    static IdTokenValidationBridge idTokenBridge(TokenValidator validator) {
        return new IdTokenValidationBridge(validator);
    }

    /**
     * Assembles an unconstrained refresh flow exactly as an application would.
     *
     * @param configuration the client configuration
     * @param accessBridge  the access-token validation bridge
     * @return the wired refresh flow
     */
    static RefreshFlow refreshFlow(ClientConfiguration configuration, TokenValidationBridge accessBridge) {
        return refreshFlow(configuration, accessBridge, clientAuthentication(configuration));
    }

    /**
     * Assembles an unconstrained refresh flow over a caller-chosen client-authentication strategy, so
     * the refresh leg can be driven through any of the engine's {@code ClientAuthentication}
     * implementations rather than only the shared-secret Basic form.
     *
     * @param configuration        the client configuration
     * @param accessBridge         the access-token validation bridge
     * @param clientAuthentication the strategy to present at the token endpoint
     * @return the wired refresh flow
     */
    static RefreshFlow refreshFlow(ClientConfiguration configuration, TokenValidationBridge accessBridge,
            ClientAuthentication clientAuthentication) {
        return new RefreshFlow(configuration, new TokenEndpointClient(configuration), accessBridge,
                clientAuthentication);
    }

    /**
     * Assembles a DPoP-constrained refresh flow over a caller-owned key pair, so the acquisition leg
     * and the refresh leg can present proofs from the <em>same</em> key and the sender-constraint
     * continuity is observable in the rotated token's {@code cnf.jkt}.
     *
     * @param configuration the client configuration
     * @param accessBridge  the access-token validation bridge
     * @param keyPair       the proof key shared with the acquisition leg
     * @return the wired, DPoP-constrained refresh flow
     */
    static RefreshFlow dpopRefreshFlow(ClientConfiguration configuration, TokenValidationBridge accessBridge,
            KeyPair keyPair) {
        SenderConstraint constraint = SenderConstraint.dpop(dpopProofGenerator(keyPair));
        return new RefreshFlow(configuration, new TokenEndpointClient(configuration), accessBridge,
                clientAuthentication(configuration), constraint);
    }

    /**
     * @param keyPair the proof key
     * @return the production DPoP proof generator over {@code keyPair}
     */
    static DpopProofGenerator dpopProofGenerator(KeyPair keyPair) {
        return new DpopProofGenerator(keyPair, DPOP_SIGNING_ALGORITHM);
    }

    /**
     * @param configuration the client configuration
     * @return the shared-secret client authentication for {@code configuration}
     */
    static ClientSecretBasicAuth clientAuthentication(ClientConfiguration configuration) {
        return new ClientSecretBasicAuth(configuration.getClientId(), configuration.getClientSecret());
    }

    /**
     * @param failure the captured engine failure
     * @return the first {@code de.cuioss.sheriff.token.client.*} frame on the failure's cause chain, or
     *         {@link Optional#empty()} when no production frame is present
     */
    static Optional<String> productionFrame(Throwable failure) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            for (StackTraceElement element : current.getStackTrace()) {
                if (element.getClassName().startsWith(PRODUCTION_PACKAGE)) {
                    return Optional.of(element.toString());
                }
            }
        }
        return Optional.empty();
    }

    /**
     * @return a freshly generated 2048-bit RSA key pair, for tests that own a proof or assertion
     *         signing key rather than sharing the container's realm-issued key material
     * @throws IllegalStateException if RSA is unavailable — never in practice, it is a mandatory JDK
     *         algorithm
     */
    static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA not available", e);
        }
    }
}

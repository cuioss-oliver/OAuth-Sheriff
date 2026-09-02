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
package de.cuioss.sheriff.token.client.internal;

import de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.AuthorizationCodeFlow;
import de.cuioss.sheriff.token.client.flow.CallbackParameters;
import de.cuioss.sheriff.token.client.flow.FlowContext;
import de.cuioss.sheriff.token.client.flow.TokenEndpointClient;
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.dispatcher.TokenDispatcher;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.TestProvidedCertificate;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Behavioural TLS coverage for the {@code verifyHostname} knob at the client back-channel seam.
 * <p>
 * Mirrors the validation-side control design: the mock authorization server serves a certificate whose
 * SAN is {@code not-the-server.example.com} while the server is actually reached over loopback, so the
 * certificate never matches the host contacted. The client trusts that exact certificate, isolating the
 * variable under test — <em>chain trust always succeeds, and only hostname matching is in question</em>.
 * <p>
 * Trust is injected through the JVM default trust-store system properties, following
 * {@code WiredFlowHttpsTest}, and explicitly <strong>not</strong> through
 * {@link ClientConfiguration#getSslContext()}: the knob-off half of every control pair would otherwise
 * be rejected by the configuration's mutual-exclusion guard before a socket is ever opened. The
 * properties are process-global, hence {@link Isolated} and the {@code @AfterEach} restore.
 * <p>
 * The unit-level counterpart — that the flag reaches the handler at all — lives in
 * {@code BackChannelHttpTlsTrustTest}, which needs no server fixture.
 *
 * @since 1.0
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer(useHttps = true)
@TestProvidedCertificate(providerClass = BackChannelHostnameVerificationTest.class, methodName = "serverCertificates")
@DisplayName("Back-channel hostname verification (TLS path)")
@Isolated
class BackChannelHostnameVerificationTest {

    private static final String ISSUER = "https://issuer.example.com";
    private static final String REDIRECT_URI = "https://rp.example.com/callback";
    private static final char[] TRUST_STORE_PASSWORD = "changeit".toCharArray();

    /**
     * The certificate the mock server serves. Its SAN is deliberately a name the server is NOT reached
     * by — the server binds to loopback — so hostname verification must fail while chain trust succeeds.
     */
    private static final HeldCertificate SAN_MISMATCHED_CERTIFICATE = new HeldCertificate.Builder()
            .commonName("not-the-server")
            .addSubjectAlternativeName("not-the-server.example.com")
            .build();

    /** An unrelated certificate, never served, used to model a genuinely untrusted issuer. */
    private static final HeldCertificate UNRELATED_CERTIFICATE = new HeldCertificate.Builder()
            .commonName("unrelated")
            .addSubjectAlternativeName("unrelated.example.com")
            .build();

    /**
     * Provider for {@link TestProvidedCertificate}.
     *
     * @return the server-side handshake certificates carrying {@link #SAN_MISMATCHED_CERTIFICATE}
     */
    static HandshakeCertificates serverCertificates() {
        return new HandshakeCertificates.Builder()
                .heldCertificate(SAN_MISMATCHED_CERTIFICATE)
                .build();
    }

    @Getter
    private final TokenDispatcher moduleDispatcher = new TokenDispatcher();

    private TestTokenHolder accessHolder;
    private TestTokenHolder idHolder;
    private TokenValidationBridge accessBridge;
    private IdTokenValidationBridge idBridge;
    private Map<String, String> savedTrustStoreProperties;

    @BeforeEach
    void setUp() {
        accessHolder = TestTokenGenerators.accessTokens().next();
        idHolder = TestTokenGenerators.idTokens().next();
        TokenValidator validator = TokenValidator.builder().issuerConfig(accessHolder.getIssuerConfig()).build();
        accessBridge = new TokenValidationBridge(validator);
        idBridge = new IdTokenValidationBridge(validator);
        moduleDispatcher.reset();
        savedTrustStoreProperties = null;
    }

    @AfterEach
    void restoreTrustStore() {
        if (savedTrustStoreProperties != null) {
            savedTrustStoreProperties.forEach((key, value) -> {
                if (value == null) {
                    System.clearProperty(key);
                } else {
                    System.setProperty(key, value);
                }
            });
        }
    }

    @Test
    @DisplayName("exchange() is refused against a SAN-mismatched authorization server under the default")
    void shouldRefuseSanMismatchByDefault(URIBuilder uriBuilder) throws Exception {
        // Arrange — trust the served certificate, so only hostname matching can fail
        installClientTrustStore(SAN_MISMATCHED_CERTIFICATE.certificate());
        var config = tlsConfig(true);
        var context = FlowContext.create(REDIRECT_URI);
        idHolder.withClaim("nonce", ClaimValue.forPlainString(context.nonce()));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), null,
                idHolder.getRawToken(), 300));
        var callback = new CallbackParameters(Generators.letterStrings(20, 40).next(),
                context.state(), null, null, null);
        var metadata = metadataWithTokenEndpoint(uriBuilder);
        var flow = flow(config);
        var clientAuth = auth(config);

        // Act & Assert
        assertThrows(TransportException.class,
                () -> flow.exchange(metadata, context, callback, clientAuth),
                "a SAN-mismatched certificate must fail the back-channel call while verification is enabled");
        moduleDispatcher.assertCallsAnswered(0);
    }

    @Test
    @DisplayName("exchange() completes against the same server when verifyHostname(false) is set")
    void shouldCompleteExchangeWhenVerificationDisabled(URIBuilder uriBuilder) throws Exception {
        // Arrange — identical server and trust material as the negative control above
        installClientTrustStore(SAN_MISMATCHED_CERTIFICATE.certificate());
        var config = tlsConfig(false);
        var context = FlowContext.create(REDIRECT_URI);
        idHolder.withClaim("nonce", ClaimValue.forPlainString(context.nonce()));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), null,
                idHolder.getRawToken(), 300));
        var callback = new CallbackParameters(Generators.letterStrings(20, 40).next(),
                context.state(), null, null, null);
        var metadata = metadataWithTokenEndpoint(uriBuilder);

        // Act
        AuthorizationCodeFlow.AuthenticationResult result =
                flow(config).exchange(metadata, context, callback, auth(config));

        // Assert
        assertAll("the exchange completes once hostname matching is relaxed",
                () -> assertTrue(metadata.tokenEndpoint.startsWith("https://"),
                        "the exchange must target the TLS token endpoint"),
                () -> assertNotNull(result.accessToken(), "a validated access token must be returned"),
                () -> assertNotNull(result.idToken(), "a validated ID token must be returned"),
                () -> moduleDispatcher.assertCallsAnswered(1));
    }

    @Test
    @DisplayName("exchange() is still refused with verifyHostname(false) when the issuer is untrusted")
    void shouldStillRefuseUntrustedIssuerWhenVerificationDisabled(URIBuilder uriBuilder) throws Exception {
        // Arrange — trust an unrelated certificate, so chain validation must fail on its own merits
        installClientTrustStore(UNRELATED_CERTIFICATE.certificate());
        var config = tlsConfig(false);
        var context = FlowContext.create(REDIRECT_URI);
        idHolder.withClaim("nonce", ClaimValue.forPlainString(context.nonce()));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), null,
                idHolder.getRawToken(), 300));
        var callback = new CallbackParameters(Generators.letterStrings(20, 40).next(),
                context.state(), null, null, null);
        var metadata = metadataWithTokenEndpoint(uriBuilder);
        var flow = flow(config);
        var clientAuth = auth(config);

        // Act & Assert — relaxing hostname matching must not relax chain validation
        assertThrows(TransportException.class,
                () -> flow.exchange(metadata, context, callback, clientAuth),
                "an untrusted issuer must still be refused when hostname verification is disabled");
        moduleDispatcher.assertCallsAnswered(0);
    }

    private static ClientConfiguration tlsConfig(boolean verifyHostname) {
        return ClientConfiguration.builder()
                .issuer(ISSUER)
                .clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                // Deliberately NOT allowInsecureHttp(true): this exercises the real TLS branch.
                // Trust arrives via the default trust store, never via sslContext(...), which the
                // configuration guard rejects in combination with verifyHostname(false).
                .verifyHostname(verifyHostname)
                .build();
    }

    private static ProviderMetadata metadataWithTokenEndpoint(URIBuilder uriBuilder) {
        var metadata = new ProviderMetadata();
        metadata.issuer = ISSUER;
        metadata.tokenEndpoint = uriBuilder.addPathSegments("oidc", "token").buildAsString();
        return metadata;
    }

    private AuthorizationCodeFlow flow(ClientConfiguration config) {
        return new AuthorizationCodeFlow(config, new TokenEndpointClient(config), accessBridge, idBridge);
    }

    private static ClientSecretBasicAuth auth(ClientConfiguration config) {
        return new ClientSecretBasicAuth(config.getClientId(), config.getClientSecret());
    }

    /**
     * Writes a PKCS12 trust store containing {@code trusted} and points the JVM trust-store system
     * properties at it, capturing the prior values for {@code @AfterEach} restoration.
     */
    private void installClientTrustStore(X509Certificate trusted) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, TRUST_STORE_PASSWORD);
        trustStore.setCertificateEntry("trusted", trusted);
        Path trustStoreFile = Files.createTempFile("back-channel-hostname-trust", ".p12");
        trustStoreFile.toFile().deleteOnExit();
        try (OutputStream out = Files.newOutputStream(trustStoreFile)) {
            trustStore.store(out, TRUST_STORE_PASSWORD);
        }

        savedTrustStoreProperties = new HashMap<>();
        captureAndSet("javax.net.ssl.trustStore", trustStoreFile.toString());
        captureAndSet("javax.net.ssl.trustStorePassword", new String(TRUST_STORE_PASSWORD));
        captureAndSet("javax.net.ssl.trustStoreType", "PKCS12");
    }

    private void captureAndSet(String key, String value) {
        savedTrustStoreProperties.put(key, System.getProperty(key));
        System.setProperty(key, value);
    }
}

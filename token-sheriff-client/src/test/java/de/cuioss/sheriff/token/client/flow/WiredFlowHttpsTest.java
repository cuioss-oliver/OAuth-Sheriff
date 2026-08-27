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

import de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
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
 * Unit-level HTTPS coverage for the back-channel token exchange (L1 / TEST-5).
 * <p>
 * Every other wired-flow test builds the client with {@code allowInsecureHttp(true)} and drives the
 * plaintext transport, so the TLS branch of {@link BackChannelHttp} — the {@code https://} handler
 * build plus the real JDK {@link javax.net.ssl.SSLContext} handshake — was never exercised. This class
 * drives the {@code authorization_code} exchange over a TLS-enabled {@link mockwebserver3.MockWebServer}
 * with a client that does <em>not</em> permit cleartext.
 * <p>
 * The client transport composes {@code cui-http}, which builds its own {@link javax.net.ssl.SSLContext}
 * from the JVM default trust store — there is no client-side {@code SSLContext} injection seam. To make
 * the loopback handshake real (rather than disabling verification), this class serves a self-signed
 * certificate it controls (via {@link TestProvidedCertificate}) and, for the positive case, installs a
 * matching client trust store through the {@code javax.net.ssl.trustStore} system properties the
 * {@code cui-http} handler honors. The negative case installs a trust store that trusts an
 * <em>unrelated</em> certificate, so the TLS material is mismatched and the handshake is refused.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer(useHttps = true)
@TestProvidedCertificate(providerClass = WiredFlowHttpsTest.class, methodName = "serverCertificates")
@DisplayName("Wired back-channel exchange over HTTPS (TLS path)")
@Isolated
class WiredFlowHttpsTest {

    private static final String ISSUER = "https://issuer.example.com";
    private static final String REDIRECT_URI = "https://rp.example.com/callback";
    private static final char[] TRUST_STORE_PASSWORD = "changeit".toCharArray();

    /**
     * The self-signed certificate the mock server serves. Valid for the loopback host names the mock
     * server binds to, so JDK hostname verification passes once the client trusts it.
     */
    private static final HeldCertificate SERVER_CERTIFICATE = new HeldCertificate.Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .addSubjectAlternativeName("127.0.0.1")
            .build();

    /** An unrelated self-signed certificate used to model mismatched client TLS trust material. */
    private static final HeldCertificate UNRELATED_CERTIFICATE = new HeldCertificate.Builder()
            .commonName("not-the-server")
            .addSubjectAlternativeName("not-the-server.example.com")
            .build();

    /**
     * Provider for {@link TestProvidedCertificate}: the mock server serves the certificate this test
     * also builds its client trust store from, so both ends share the key material under test.
     *
     * @return the server-side handshake certificates carrying {@link #SERVER_CERTIFICATE}
     */
    static HandshakeCertificates serverCertificates() {
        return new HandshakeCertificates.Builder()
                .heldCertificate(SERVER_CERTIFICATE)
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
    @DisplayName("exchange() completes over HTTPS when the client trusts the server certificate")
    void shouldCompleteExchangeOverHttps(URIBuilder uriBuilder) throws Exception {
        installClientTrustStore(SERVER_CERTIFICATE.certificate());
        var config = tlsConfig();
        var context = FlowContext.create(REDIRECT_URI);
        idHolder.withClaim("nonce", ClaimValue.forPlainString(context.nonce()));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), null,
                idHolder.getRawToken(), 300));
        String code = Generators.letterStrings(20, 40).next();
        var callback = new CallbackParameters(code, context.state(), null, null, null);
        var metadata = metadataWithTokenEndpoint(uriBuilder);

        AuthorizationCodeFlow.AuthenticationResult result =
                flow(config).exchange(metadata, context, callback, auth(config));

        assertAll("validated HTTPS exchange",
                () -> assertTrue(metadata.tokenEndpoint.startsWith("https://"),
                        "the exchange must target the TLS token endpoint"),
                () -> assertNotNull(result.accessToken(), "a validated access token must be returned over TLS"),
                () -> assertNotNull(result.idToken(), "a validated ID token must be returned over TLS"),
                () -> moduleDispatcher.assertCallsAnswered(1));
    }

    @Test
    @DisplayName("exchange() is refused over HTTPS when the client TLS trust material is mismatched")
    void shouldRefuseExchangeWhenTlsMaterialMismatched(URIBuilder uriBuilder) throws Exception {
        installClientTrustStore(UNRELATED_CERTIFICATE.certificate());
        var config = tlsConfig();
        var context = FlowContext.create(REDIRECT_URI);
        idHolder.withClaim("nonce", ClaimValue.forPlainString(context.nonce()));
        moduleDispatcher.respondWith(TokenDispatcher.tokenResponse(accessHolder.getRawToken(), null,
                idHolder.getRawToken(), 300));
        var callback = new CallbackParameters(Generators.letterStrings(20, 40).next(),
                context.state(), null, null, null);
        var metadata = metadataWithTokenEndpoint(uriBuilder);
        var flow = flow(config);
        var clientAuth = auth(config);

        assertThrows(TransportException.class,
                () -> flow.exchange(metadata, context, callback, clientAuth),
                "a TLS handshake against an untrusted server certificate must fail the back-channel call");
        moduleDispatcher.assertCallsAnswered(0);
    }

    private static ClientConfiguration tlsConfig() {
        return ClientConfiguration.builder()
                .issuer(ISSUER)
                .clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                // Deliberately NOT allowInsecureHttp(true): this exercises the real TLS branch.
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
     * properties at it, so the {@code cui-http} handler's default-trust {@link javax.net.ssl.SSLContext}
     * trusts exactly that certificate. The prior property values are captured for {@code @AfterEach}
     * restoration.
     */
    private void installClientTrustStore(X509Certificate trusted) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, TRUST_STORE_PASSWORD);
        trustStore.setCertificateEntry("trusted", trusted);
        Path trustStoreFile = Files.createTempFile("wired-flow-https-trust", ".p12");
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

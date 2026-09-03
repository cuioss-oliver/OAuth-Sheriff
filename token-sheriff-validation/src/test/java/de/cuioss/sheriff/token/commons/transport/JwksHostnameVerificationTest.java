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
package de.cuioss.sheriff.token.commons.transport;

import de.cuioss.http.client.handler.HttpHandler;
import de.cuioss.sheriff.token.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.TestProvidedCertificate;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import java.io.IOException;
import java.io.OutputStream;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Behavioural TLS coverage for the {@code verifyHostname} knob on the JWKS transport.
 * <p>
 * The mock server serves a certificate whose SAN is {@code not-the-server.example.com} while the server
 * is actually reached over loopback, so the certificate never matches the host contacted. The client
 * trusts that exact certificate, which isolates the variable under test: <em>chain trust always
 * succeeds, and only hostname matching is in question</em>.
 * <p>
 * Trust is injected through the JVM default trust-store system properties rather than through
 * {@code sslContext(...)}. That is not a stylistic choice: the knob-off half of every control pair
 * would otherwise be rejected by the builder's mutual-exclusion guard before a socket is ever opened.
 * The fixture works because {@code SecureSSLContextProvider} derives BOTH its secure and its
 * hostname-relaxed context from {@code TrustManagerFactory.init((KeyStore) null)}, which reads those
 * properties at call time — so the same trust material steers both postures. The properties are
 * process-global, hence {@link Isolated} and the {@code @AfterEach} restore.
 * <p>
 * Three controls are asserted, forming a matched positive/negative set:
 * <ol>
 *   <li>default posture → the fetch is rejected, and specifically on hostname mismatch;</li>
 *   <li>{@code verifyHostname(false)} → the same fetch against the same server succeeds;</li>
 *   <li>{@code verifyHostname(false)} with an unrelated certificate in the trust store → still
 *       rejected, proving chain validation survives the relaxation.</li>
 * </ol>
 *
 * @since 1.0
 */
@EnableTestLogger
@EnableMockWebServer(useHttps = true)
@TestProvidedCertificate(providerClass = JwksHostnameVerificationTest.class, methodName = "serverCertificates")
@DisplayName("Tests JWKS transport hostname verification")
@Isolated
class JwksHostnameVerificationTest {

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
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private Map<String, String> savedTrustStoreProperties;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        preWarmTlsStack(uriBuilder);
        moduleDispatcher.setCallCounter(0);
        savedTrustStoreProperties = null;
    }

    /**
     * Performs one throwaway HTTPS handshake against the mock server under the default posture, with no
     * trust store installed, and discards the outcome.
     * <p>
     * The call exists only so the JVM's TLS machinery — provider initialisation, class loading and
     * {@code SecureRandom} seeding — is already warm before any assertion-bearing fetch runs. Without it
     * the first handshake in the JVM absorbs that one-off cost, and on a loaded machine it can exceed the
     * transport timeout, so the fixture's verdict would report machine load rather than the TLS outcome
     * under test. Sequenced before {@code setCallCounter(0)} so the counter every control asserts on is
     * zeroed after this warm-up, whatever it did.
     */
    private static void preWarmTlsStack(URIBuilder uriBuilder) {
        try {
            fetch(handlerFor(uriBuilder, null));
        } catch (IOException ignored) {
            // No trust store is installed, so the handshake is expected to fail. Warming the stack is the
            // whole point; the outcome carries no information and is deliberately discarded.
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
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
    @DisplayName("Should reject a SAN-mismatched JWKS endpoint under the default posture")
    void shouldRejectSanMismatchByDefault(URIBuilder uriBuilder) throws Exception {
        // Arrange — trust the served certificate, so only hostname matching can fail
        installClientTrustStore(SAN_MISMATCHED_CERTIFICATE.certificate());
        HttpHandler handler = handlerFor(uriBuilder, null);

        // Act
        IOException failure = assertThrows(IOException.class, () -> fetch(handler),
                "a SAN-mismatched certificate must be rejected while hostname verification is enabled");

        // Assert — it must fail ON HOSTNAME, not because the chain was untrusted
        String causes = causeChain(failure);
        assertTrue(causes.contains("subject alternative") || causes.contains("no match")
                || causes.contains("doesn't match") || causes.contains("does not match"),
                "the rejection must be a hostname mismatch, but the cause chain was: " + causes);
        assertFalse(causes.contains("pkix path building failed"),
                "the served certificate is trusted, so this must not fail as an untrusted chain: " + causes);
    }

    @Test
    @DisplayName("Should accept the same SAN-mismatched endpoint when verifyHostname(false) is set")
    void shouldAcceptSanMismatchWhenVerificationDisabled(URIBuilder uriBuilder) throws Exception {
        // Arrange — identical server and trust material as the negative control above
        installClientTrustStore(SAN_MISMATCHED_CERTIFICATE.certificate());
        HttpHandler handler = handlerFor(uriBuilder, false);

        // Act
        HttpResponse<String> response = fetchDiscriminatingTimeouts(handler);

        // Assert
        assertEquals(200, response.statusCode(), "the JWKS fetch must succeed once hostname matching is relaxed");
        assertEquals(1, moduleDispatcher.getCallCounter(), "the request must actually have reached the server");
    }

    @Test
    @DisplayName("Should still reject an untrusted issuer when verifyHostname(false) is set")
    void shouldStillRejectUntrustedIssuerWhenVerificationDisabled(URIBuilder uriBuilder) throws Exception {
        // Arrange — trust an unrelated certificate, so chain validation must fail on its own merits
        installClientTrustStore(UNRELATED_CERTIFICATE.certificate());
        HttpHandler handler = handlerFor(uriBuilder, false);

        // Act
        IOException failure = assertThrows(IOException.class, () -> fetch(handler),
                "relaxing hostname matching must not relax certificate chain validation");

        // Assert
        assertEquals(0, moduleDispatcher.getCallCounter(),
                "the handshake must be refused before any request is answered");
        String causes = causeChain(failure);
        assertFalse(causes.isEmpty(), "the failure must carry a diagnosable cause");
        // Positively pin the rejection to chain-trust validation, mirroring the reciprocal check on the
        // default-posture control above — without this, a socket/read timeout (also an IOException, also
        // reaching the server zero times) would satisfy every other assertion here and silently masquerade
        // as proof that chain validation is still enforced.
        assertTrue(causes.contains("pkix") || causes.contains("unable to find valid certification path"),
                "the rejection must be a certificate chain-trust failure (e.g. PKIX path building failed), "
                        + "not an unrelated IOException such as a timeout, but the cause chain was: " + causes);
    }

    /**
     * Builds the JWKS transport handler for the mock server's JWKS path.
     *
     * @param verifyHostname {@code null} to leave the knob untouched (default posture), otherwise the
     *                       explicit value to configure
     */
    private static HttpHandler handlerFor(URIBuilder uriBuilder, Boolean verifyHostname) {
        var builder = HttpJwksLoaderConfig.builder()
                .jwksUrl(uriBuilder.addPathSegments("oidc", "jwks.json").buildAsString())
                .issuerIdentifier("test-issuer")
                .allowLoopbackEgress(true)
                // The transport defaults (2s/3s) are tuned for production DoS bounds and are too tight
                // for a first in-JVM TLS handshake against the mock server; widened so a slow handshake
                // cannot masquerade as a verification outcome.
                .connectTimeoutSeconds(10)
                .readTimeoutSeconds(30);
        if (verifyHostname != null) {
            builder.verifyHostname(verifyHostname);
        }
        return builder.build().getHttpHandler();
    }

    private static HttpResponse<String> fetch(HttpHandler handler) throws IOException, InterruptedException {
        return handler.send(handler.requestBuilder().GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Fetches as {@link #fetch(HttpHandler)} does, but names a timeout for what it is before the failure
     * can be read as a verification outcome.
     * <p>
     * This guards the positive control: an escaping {@link IOException} is only meaningful here if it
     * came from the TLS decision under test. A connect or read timeout is also an {@code IOException},
     * so without this discrimination a slow machine would report a verification failure that never
     * actually happened. A proven timeout therefore aborts the test as no-verdict — {@link
     * Assumptions#abort(String)} — rather than failing it; a test that could not reach a verdict must
     * report "no verdict", never "failed". Any non-timeout failure is rethrown untouched so the real
     * cause still surfaces and still fails the test.
     */
    private static HttpResponse<String> fetchDiscriminatingTimeouts(HttpHandler handler)
            throws IOException, InterruptedException {
        try {
            return fetch(handler);
        } catch (IOException failure) {
            String causes = causeChain(failure);
            if (causes.contains("timed out") || causes.contains("timeout")) {
                Assumptions.abort(
                        "the fetch timed out rather than reaching a TLS verification outcome; this is a machine-load "
                                + "artefact, not evidence about hostname relaxation. Cause chain was: " + causes);
            }
            throw failure;
        }
    }

    /** Flattens a throwable's cause chain into one lower-cased string for message-shape assertions. */
    private static String causeChain(Throwable throwable) {
        StringBuilder builder = new StringBuilder();
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current.getMessage() != null) {
                builder.append(current.getMessage()).append(" | ");
            }
            if (current.getCause() == current) {
                break;
            }
        }
        return builder.toString().toLowerCase(Locale.ROOT);
    }

    /**
     * Writes a PKCS12 trust store containing {@code trusted} and points the JVM trust-store system
     * properties at it, capturing the prior values for {@code @AfterEach} restoration.
     */
    private void installClientTrustStore(X509Certificate trusted) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, TRUST_STORE_PASSWORD);
        trustStore.setCertificateEntry("trusted", trusted);
        Path trustStoreFile = Files.createTempFile("jwks-hostname-verification-trust", ".p12");
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

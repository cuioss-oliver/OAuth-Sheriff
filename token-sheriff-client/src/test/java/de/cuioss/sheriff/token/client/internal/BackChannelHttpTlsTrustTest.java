/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.commons.error.TransportException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies that the per-client TLS trust configured on {@link ClientConfiguration} reaches the
 * outbound transport at the {@link BackChannelHttp#validatedHandler(String, String)} seam, and that
 * adding the trust hand-off did not regress the consistent-transport-typing guarantee (M9).
 */
@DisplayName("BackChannelHttp per-client TLS trust")
class BackChannelHttpTlsTrustTest {

    private static final int MAX_CONTENT_SIZE = 8192;
    private static final String ISSUER = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = ISSUER + "/token";
    private static final String USERINFO_ENDPOINT = ISSUER + "/userinfo";
    private static final String FAILURE_CONTEXT = "token endpoint request failed";

    @Test
    @DisplayName("Should forward the configured SSL context to the handler it builds")
    void shouldForwardConfiguredSslContextToHandler() {
        var configured = freshSslContext();
        var backChannel = backChannelWith(configured);

        var handler = backChannel.validatedHandler(TOKEN_ENDPOINT, FAILURE_CONTEXT);

        assertSame(configured, handler.getSslContext(),
                "the caller's trust material must be handed to the handler unchanged");
    }

    @Test
    @DisplayName("Should apply the same SSL context to every endpoint handler the helper produces")
    void shouldApplySameSslContextToEveryEndpointHandler() {
        var configured = freshSslContext();
        var backChannel = backChannelWith(configured);

        var tokenHandler = backChannel.validatedHandler(TOKEN_ENDPOINT, FAILURE_CONTEXT);
        var userinfoHandler = backChannel.validatedHandler(USERINFO_ENDPOINT, FAILURE_CONTEXT);

        assertAll("all endpoints of one authorization server share the same trust",
                () -> assertSame(configured, tokenHandler.getSslContext()),
                () -> assertSame(configured, userinfoHandler.getSslContext()));
    }

    @Test
    @DisplayName("Should fall back to the cui-http default trust when no SSL context is configured")
    void shouldFallBackToDefaultTrustWhenUnconfigured() {
        var unrelated = freshSslContext();
        var backChannel = backChannelWithoutTrust();

        var handler = backChannel.validatedHandler(TOKEN_ENDPOINT, FAILURE_CONTEXT);

        assertAll("an unconfigured client still gets a working, secure handler",
                () -> assertNotNull(handler.getSslContext(),
                        "cui-http creates a secure context when the client configures none"),
                () -> assertNotSame(unrelated, handler.getSslContext()),
                () -> assertNotNull(backChannel.sharedClient(handler),
                        "the handler must still yield a usable shared HttpClient"));
    }

    @Test
    @DisplayName("Should still surface a non-TLS endpoint as TransportException with an SSL context configured (M9)")
    void shouldKeepTransportTypingForNonTlsEndpoint() {
        var backChannel = backChannelWith(freshSslContext());

        assertThrows(TransportException.class,
                () -> backChannel.validatedHandler("http://as.example.com/token", FAILURE_CONTEXT),
                "cleartext must be refused as the declared transport failure, not a raw IllegalArgumentException");
    }

    @Test
    @DisplayName("Should still surface an unsupported scheme as TransportException with an SSL context configured (M9)")
    void shouldKeepTransportTypingForUnsupportedScheme() {
        var backChannel = backChannelWith(freshSslContext());

        assertThrows(TransportException.class,
                () -> backChannel.validatedHandler("ftp://as.example.com/token", FAILURE_CONTEXT),
                "a non-HTTP scheme must be refused as the declared transport failure");
    }

    private static BackChannelHttp backChannelWith(SSLContext sslContext) {
        return new BackChannelHttp(configurationBuilder().sslContext(sslContext).build(), MAX_CONTENT_SIZE);
    }

    private static BackChannelHttp backChannelWithoutTrust() {
        return new BackChannelHttp(configurationBuilder().build(), MAX_CONTENT_SIZE);
    }

    private static ClientConfiguration.ClientConfigurationBuilder configurationBuilder() {
        return ClientConfiguration.builder()
                .issuer(ISSUER)
                .clientId("test-client")
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC);
    }

    private static SSLContext freshSslContext() {
        return assertDoesNotThrow(() -> {
            var context = SSLContext.getInstance("TLSv1.3");
            context.init(null, null, null);
            return context;
        });
    }
}

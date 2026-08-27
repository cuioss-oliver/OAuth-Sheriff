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
package de.cuioss.sheriff.token.client.auth;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link MtlsClientAuth} ({@code tls_client_auth}, RFC 8705) — H4.
 * <p>
 * Mutual-TLS authenticates the client at the transport layer via a client certificate carried by an
 * {@code SSLContext} on the {@code HttpHandler}. No code path plumbs such an {@code SSLContext} into
 * the transport, so a {@code tls_client_auth} request would leave the client without a bound
 * certificate — an unauthenticated request. The strategy therefore fails fast at construction rather
 * than producing that request; these tests confirm the fail-fast contract.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Mutual-TLS (tls_client_auth) client authentication")
class MtlsClientAuthTest {

    @Test
    @DisplayName("Should fail fast at construction because the transport cannot honor mutual-TLS")
    void shouldFailFastAtConstruction() {
        String clientId = Generators.letterStrings(5, 12).next();

        var exception = assertThrows(UnsupportedOperationException.class,
                () -> new MtlsClientAuth(clientId),
                "constructing tls_client_auth must fail fast until the transport can honor mTLS");

        assertTrue(exception.getMessage().contains("tls_client_auth"),
                "the failure must name the unsupported method");
    }

    @Test
    @DisplayName("Should fail fast for a null client id — no unauthenticated strategy is constructible")
    void shouldFailFastForNullClientId() {
        assertThrows(UnsupportedOperationException.class, () -> new MtlsClientAuth(null),
                "no tls_client_auth strategy is constructible regardless of the client id");
    }
}

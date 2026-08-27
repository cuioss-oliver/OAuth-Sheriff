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

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Fail-closed / no-silent-downgrade adversarial cases for {@link ClientAuthenticationSelector}
 * ({@code CLIENT-4}) — deliverable 3.
 * <p>
 * The security invariant under test: the selector must never downgrade to a shared secret when a
 * stronger method ({@code private_key_jwt}) is <em>both</em> configured and advertised, and must
 * fail closed rather than fall back to a configured secret the AS does not advertise. Mutual-TLS
 * ({@code tls_client_auth}) is a separate case: the transport cannot honor it, so a working shared
 * secret is preferred over it rather than treated as a downgrade (H4).
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("ClientAuthenticationSelector no-silent-downgrade invariant")
class WeakAuthRefusedTest {

    private final ClientAuthenticationSelector selector = new ClientAuthenticationSelector();

    private static ClientAuthentication auth(ClientAuthMethod method) {
        return new ClientAuthentication() {
            @Override
            public ClientAuthMethod method() {
                return method;
            }

            @Override
            public void decorate(Map<String, String> formParameters, Map<String, String> requestHeaders) {
                // selection-only test double
            }
        };
    }

    private static ProviderMetadata advertising(List<String> methods) {
        var metadata = new ProviderMetadata();
        metadata.tokenEndpointAuthMethodsSupported = methods;
        return metadata;
    }

    static Stream<Arguments> strongOverWeakCombinations() {
        return Stream.of(
                Arguments.of(ClientAuthMethod.PRIVATE_KEY_JWT, ClientAuthMethod.CLIENT_SECRET_BASIC),
                Arguments.of(ClientAuthMethod.PRIVATE_KEY_JWT, ClientAuthMethod.CLIENT_SECRET_POST));
    }

    @ParameterizedTest
    @MethodSource("strongOverWeakCombinations")
    @DisplayName("Should never downgrade to a shared secret when a stronger method is configured and advertised")
    void shouldNeverDowngradeWhenStrongIsAdvertised(ClientAuthMethod strong, ClientAuthMethod weak) {
        var metadata = advertising(List.of(strong.getMetadataValue(), weak.getMetadataValue()));

        ClientAuthentication selected = selector.select(List.of(auth(weak), auth(strong)), metadata);

        assertEquals(strong, selected.method(),
                "the selector must pick the stronger advertised method, never the shared secret");
    }

    @Test
    @DisplayName("Should prefer a working client_secret_basic over a non-functional tls_client_auth (H4)")
    void shouldPreferWorkingSecretOverNonFunctionalMtls() {
        var metadata = advertising(List.of("client_secret_basic", "tls_client_auth"));

        ClientAuthentication selected = selector.select(
                List.of(auth(ClientAuthMethod.CLIENT_SECRET_BASIC), auth(ClientAuthMethod.TLS_CLIENT_AUTH)),
                metadata);

        assertEquals(ClientAuthMethod.CLIENT_SECRET_BASIC, selected.method(),
                "tls_client_auth cannot be honored by the transport, so the working shared secret is used "
                        + "rather than producing an unauthenticated request");
    }

    @Test
    @DisplayName("Should fail closed rather than fall back to a configured secret the AS does not advertise")
    void shouldFailClosedRatherThanUseUnadvertisedSecret() {
        ClientAuthentication basic = auth(ClientAuthMethod.CLIENT_SECRET_BASIC);
        var metadata = advertising(List.of("tls_client_auth"));
        var configured = List.of(basic);

        assertThrows(ClientProtocolException.class, () -> selector.select(configured, metadata),
                "a configured secret that the AS does not advertise must not be silently used");
    }

    @Test
    @DisplayName("Should select the strongest method even when the weaker one appears first in the configured list")
    void shouldSelectStrongestRegardlessOfConfigurationOrder() {
        var metadata = advertising(List.of("client_secret_basic", "private_key_jwt"));

        ClientAuthentication selected = selector.select(
                List.of(auth(ClientAuthMethod.CLIENT_SECRET_BASIC), auth(ClientAuthMethod.PRIVATE_KEY_JWT)),
                metadata);

        assertEquals(ClientAuthMethod.PRIVATE_KEY_JWT, selected.method(),
                "selection strength must not depend on the configuration order");
    }
}

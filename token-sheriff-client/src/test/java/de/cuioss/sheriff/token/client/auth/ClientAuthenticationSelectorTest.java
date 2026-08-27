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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link ClientAuthenticationSelector} — deliverable 3 (CLIENT-4).
 * <p>
 * The selector picks the strongest client-authentication strategy the authorization server
 * advertises, applies the RFC 8414 {@code client_secret_basic} default when the metadata omits the
 * advertised methods, and fails closed when the AS advertises none of the configured methods.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("ClientAuthenticationSelector strongest-mutually-supported selection")
class ClientAuthenticationSelectorTest {

    private final ClientAuthenticationSelector selector = new ClientAuthenticationSelector();

    private static ClientAuthentication auth(ClientAuthMethod method) {
        return new ClientAuthentication() {
            @Override
            public ClientAuthMethod method() {
                return method;
            }

            @Override
            public void decorate(Map<String, String> formParameters, Map<String, String> requestHeaders) {
                // selection-only test double; the selector never invokes decorate
            }
        };
    }

    private static ProviderMetadata metadataAdvertising(List<String> methods) {
        var metadata = new ProviderMetadata();
        metadata.tokenEndpointAuthMethodsSupported = methods;
        return metadata;
    }

    @Test
    @DisplayName("Should select the single method the AS advertises")
    void shouldSelectTheOnlyAdvertisedMethod() {
        ClientAuthentication basic = auth(ClientAuthMethod.CLIENT_SECRET_BASIC);
        var metadata = metadataAdvertising(List.of("client_secret_basic"));

        ClientAuthentication selected = selector.select(List.of(basic), metadata);

        assertSame(basic, selected, "the only advertised strategy must be selected");
    }

    @Test
    @DisplayName("Should prefer the strongest advertised method over a shared secret")
    void shouldPreferStrongestAdvertisedMethod() {
        ClientAuthentication basic = auth(ClientAuthMethod.CLIENT_SECRET_BASIC);
        ClientAuthentication privateKeyJwt = auth(ClientAuthMethod.PRIVATE_KEY_JWT);
        var metadata = metadataAdvertising(List.of("client_secret_basic", "private_key_jwt"));

        ClientAuthentication selected = selector.select(List.of(basic, privateKeyJwt), metadata);

        assertSame(privateKeyJwt, selected, "private_key_jwt outranks the shared secret when both are advertised");
    }

    @Test
    @DisplayName("Should never select tls_client_auth over a working client_secret_basic (H4)")
    void shouldNeverSelectTlsClientAuthOverWorkingSecret() {
        ClientAuthentication basic = auth(ClientAuthMethod.CLIENT_SECRET_BASIC);
        ClientAuthentication mtls = auth(ClientAuthMethod.TLS_CLIENT_AUTH);
        var metadata = metadataAdvertising(List.of("client_secret_basic", "tls_client_auth"));

        ClientAuthentication selected = selector.select(List.of(basic, mtls), metadata);

        assertSame(basic, selected,
                "tls_client_auth cannot be honored by the transport, so it must not be selected over "
                        + "a working client_secret_basic");
    }

    @Test
    @DisplayName("Should fail closed when the AS advertises only tls_client_auth — never a non-functional method")
    void shouldFailClosedWhenOnlyTlsClientAuthAdvertised() {
        ClientAuthentication mtls = auth(ClientAuthMethod.TLS_CLIENT_AUTH);
        var metadata = metadataAdvertising(List.of("tls_client_auth"));
        var configured = List.of(mtls);

        assertThrows(ClientProtocolException.class, () -> selector.select(configured, metadata),
                "selection must fail closed rather than pick the transport-unsupported tls_client_auth");
    }

    @Test
    @DisplayName("Should apply the RFC 8414 client_secret_basic default when the AS omits the advertised methods")
    void shouldApplyClientSecretBasicDefault() {
        ClientAuthentication basic = auth(ClientAuthMethod.CLIENT_SECRET_BASIC);
        ClientAuthentication post = auth(ClientAuthMethod.CLIENT_SECRET_POST);
        var metadata = metadataAdvertising(null);

        ClientAuthentication selected = selector.select(List.of(basic, post), metadata);

        assertEquals(ClientAuthMethod.CLIENT_SECRET_BASIC, selected.method(),
                "client_secret_basic is the RFC 8414 default when metadata is absent");
    }

    @Test
    @DisplayName("Should fail closed when the AS advertises none of the configured methods")
    void shouldFailClosedWhenNoConfiguredMethodAdvertised() {
        ClientAuthentication privateKeyJwt = auth(ClientAuthMethod.PRIVATE_KEY_JWT);
        var metadata = metadataAdvertising(List.of("client_secret_post"));
        var configured = List.of(privateKeyJwt);

        assertThrows(ClientProtocolException.class, () -> selector.select(configured, metadata),
                "selection must fail closed rather than pick an unadvertised method");
    }

    @Test
    @DisplayName("Should reject an empty set of configured strategies")
    void shouldRejectEmptyAvailable() {
        var metadata = metadataAdvertising(List.of("client_secret_basic"));

        assertThrows(IllegalArgumentException.class, () -> selector.select(List.of(), metadata),
                "at least one configured strategy is required");
    }

    @Test
    @DisplayName("Should reject null arguments")
    void shouldRejectNullArguments() {
        ClientAuthentication basic = auth(ClientAuthMethod.CLIENT_SECRET_BASIC);
        var metadata = metadataAdvertising(List.of("client_secret_basic"));
        var configured = List.of(basic);
        assertThrows(NullPointerException.class, () -> selector.select(null, metadata));
        assertThrows(NullPointerException.class, () -> selector.select(configured, null));
    }
}

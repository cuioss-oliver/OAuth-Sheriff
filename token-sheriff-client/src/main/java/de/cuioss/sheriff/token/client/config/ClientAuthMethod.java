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
package de.cuioss.sheriff.token.client.config;

import lombok.Getter;

import java.util.Optional;

/**
 * The client-authentication methods this confidential client can present to an OAuth 2.0
 * authorization server's token endpoint (and the other authenticated back-channel endpoints:
 * revocation, introspection, PAR).
 * <p>
 * Each constant carries two pieces of metadata:
 * <ul>
 *   <li>its {@link #metadataValue metadata value} — the exact string the AS advertises in
 *       {@code token_endpoint_auth_methods_supported} (RFC 8414);</li>
 *   <li>its {@link #strength strength} — a relative ordering used by the
 *       {@code ClientAuthenticationSelector} to prefer the strongest method the AS supports.
 *       Key-based methods ({@code private_key_jwt}, {@code tls_client_auth}) rank above the
 *       shared-secret methods, so the selector never downgrades to a shared secret where a
 *       stronger method is available.</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8414">RFC 8414 - OAuth 2.0 Authorization Server Metadata</a>
 */
@Getter
public enum ClientAuthMethod {

    /**
     * HTTP Basic authentication carrying {@code client_id} / {@code client_secret} (RFC 6749
     * §2.3.1). Shared secret over TLS only.
     */
    CLIENT_SECRET_BASIC("client_secret_basic", 1),

    /**
     * {@code client_id} / {@code client_secret} sent in the form-encoded request body (RFC 6749
     * §2.3.1). Shared secret over TLS only.
     */
    CLIENT_SECRET_POST("client_secret_post", 1),

    /**
     * A signed JWT client assertion (RFC 7523 / RFC 7521). No shared secret leaves the client.
     */
    PRIVATE_KEY_JWT("private_key_jwt", 3),

    /**
     * Mutual-TLS certificate-bound client authentication (RFC 8705). The client is authenticated
     * by its TLS client certificate.
     */
    TLS_CLIENT_AUTH("tls_client_auth", 3);

    /**
     * The exact string the authorization server advertises for this method in
     * {@code token_endpoint_auth_methods_supported}.
     */
    private final String metadataValue;

    /**
     * The relative strength of this method. A higher value is stronger; key-based methods
     * outrank shared-secret methods.
     */
    private final int strength;

    ClientAuthMethod(String metadataValue, int strength) {
        this.metadataValue = metadataValue;
        this.strength = strength;
    }

    /**
     * Resolves the method whose {@link #metadataValue metadata value} equals the supplied
     * advertised string.
     *
     * @param metadataValue the {@code token_endpoint_auth_methods_supported} entry to resolve;
     *                      may be {@code null}
     * @return the matching method, or {@link Optional#empty()} when the string is {@code null} or
     *         not recognised
     */
    public static Optional<ClientAuthMethod> fromMetadataValue(String metadataValue) {
        if (metadataValue == null) {
            return Optional.empty();
        }
        for (ClientAuthMethod method : values()) {
            if (method.metadataValue.equals(metadataValue)) {
                return Optional.of(method);
            }
        }
        return Optional.empty();
    }
}

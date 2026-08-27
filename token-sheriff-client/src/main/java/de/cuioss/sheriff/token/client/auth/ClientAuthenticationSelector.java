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
import de.cuioss.sheriff.token.client.internal.LogSanitizer;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Selects the strongest client-authentication method the authorization server advertises.
 * <p>
 * Given the client's configured authentication strategies and the AS
 * {@code token_endpoint_auth_methods_supported} metadata (RFC 8414), the selector picks the strategy
 * with the highest {@link de.cuioss.sheriff.token.client.config.ClientAuthMethod#strength
 * strength} that the AS supports — preferring {@code private_key_jwt} over a shared secret, and
 * never silently downgrading to a shared secret where a stronger method is both configured and
 * advertised. When the AS advertises no configured method, selection fails closed.
 * <p>
 * {@code tls_client_auth} is <strong>never selected</strong>: mutual-TLS is a transport-layer
 * binding that the current transport cannot honor (no {@code SSLContext} client key material is
 * plumbed), so selecting it would produce an unauthenticated request. The selector skips it even
 * when the AS advertises it, so a working {@code client_secret_basic} is preferred rather than
 * silently downgraded to a non-functional mTLS method (H4).
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class ClientAuthenticationSelector {

    private static final String DEFAULT_ADVERTISED_METHOD = "client_secret_basic";

    /**
     * Selects the strongest mutually-supported client authentication strategy.
     *
     * @param available the client's configured authentication strategies; must not be {@code null}
     *                  or empty
     * @param metadata  the resolved provider metadata; must not be {@code null}
     * @return the strongest strategy the AS advertises
     * @throws IllegalArgumentException if {@code available} is empty
     * @throws ClientProtocolException  if the AS advertises none of the configured methods
     */
    public ClientAuthentication select(Collection<ClientAuthentication> available, ProviderMetadata metadata) {
        Objects.requireNonNull(available, "available must not be null");
        Objects.requireNonNull(metadata, "metadata must not be null");
        if (available.isEmpty()) {
            throw new IllegalArgumentException("at least one client authentication strategy must be configured");
        }

        Set<String> advertised = advertisedMethods(metadata);

        ClientAuthentication strongest = null;
        for (ClientAuthentication candidate : available) {
            if (candidate.method() == ClientAuthMethod.TLS_CLIENT_AUTH) {
                // Transport cannot honor mutual-TLS (no SSLContext client key material is plumbed),
                // so selecting tls_client_auth would produce an unauthenticated request. Skip it even
                // when advertised, preferring a working method rather than downgrading silently (H4).
                continue;
            }
            if (advertised.contains(candidate.method().getMetadataValue())
                    && (strongest == null
                    || candidate.method().getStrength() > strongest.method().getStrength())) {
                strongest = candidate;
            }
        }

        if (strongest == null) {
            throw new ClientProtocolException(
                    "no configured client authentication method is advertised by the authorization server; advertised="
                            + LogSanitizer.sanitize(String.valueOf(advertised)));
        }
        return strongest;
    }

    private static Set<String> advertisedMethods(ProviderMetadata metadata) {
        // getTokenEndpointAuthMethods() returns a null-element-free list, so Set.copyOf cannot NPE on
        // a JSON null array element in token_endpoint_auth_methods_supported (L6).
        List<String> advertised = metadata.getTokenEndpointAuthMethods();
        if (advertised.isEmpty()) {
            // RFC 8414: client_secret_basic is the default when the AS omits the metadata.
            return Set.of(DEFAULT_ADVERTISED_METHOD);
        }
        return Set.copyOf(advertised);
    }
}

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

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.dpop.SenderConstraint;
import de.cuioss.sheriff.token.client.token.TokenResponse;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Drives the OAuth 2.0 {@code client_credentials} grant (RFC 6749 §4.4).
 * <p>
 * The flow builds the {@code grant_type=client_credentials} request, applies the configured
 * {@link ClientAuthentication} strategy, exchanges it at the token endpoint through
 * {@link TokenEndpointClient}, and validates the returned access token through the
 * {@link TokenValidationBridge} ({@code CLIENT-15}). It returns only a validated token — a
 * successful HTTP exchange alone is never trusted.
 * <p>
 * The strategy is resolved by the caller through
 * {@link de.cuioss.sheriff.token.client.auth.ClientAuthenticationSelector}, so the flow honors the
 * strongest client-authentication method the authorization server advertises — including the
 * key-based methods ({@code private_key_jwt}) — rather than capping at a shared secret. The
 * shared-secret {@code Authorization} encoding is delegated to
 * {@link de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth} and never duplicated here.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4">RFC 6749 §4.4 - Client Credentials Grant</a>
 */
public class ClientCredentialsFlow {

    private static final CuiLogger LOGGER = new CuiLogger(ClientCredentialsFlow.class);

    private static final String PARAM_GRANT_TYPE = "grant_type";
    private static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
    private static final String PARAM_SCOPE = "scope";

    private final ClientConfiguration configuration;
    private final TokenEndpointClient tokenEndpointClient;
    private final TokenValidationBridge validationBridge;
    private final ClientAuthentication clientAuthentication;
    @Nullable
    private final SenderConstraint senderConstraint;

    /**
     * Creates an unconstrained client-credentials flow (plain bearer token, no DPoP/mTLS).
     *
     * @param configuration        the client configuration; must not be {@code null}
     * @param tokenEndpointClient  the token-endpoint transport; must not be {@code null}
     * @param validationBridge     the validation bridge; must not be {@code null}
     * @param clientAuthentication the client authentication strategy to present; must not be
     *                             {@code null}
     */
    public ClientCredentialsFlow(ClientConfiguration configuration,
            TokenEndpointClient tokenEndpointClient,
            TokenValidationBridge validationBridge,
            ClientAuthentication clientAuthentication) {
        this(configuration, tokenEndpointClient, validationBridge, clientAuthentication, null);
    }

    /**
     * Creates a client-credentials flow that, when a sender-constraint is supplied, attaches a DPoP
     * proof to the token request so the issued access token is bound to the proof key
     * ({@code CLIENT-11}).
     *
     * @param configuration        the client configuration; must not be {@code null}
     * @param tokenEndpointClient  the token-endpoint transport; must not be {@code null}
     * @param validationBridge     the validation bridge; must not be {@code null}
     * @param clientAuthentication the client authentication strategy to present; must not be
     *                             {@code null}
     * @param senderConstraint     the DPoP/mTLS sender-constraint to attach, or {@code null} for a
     *                             plain bearer request
     */
    public ClientCredentialsFlow(ClientConfiguration configuration,
            TokenEndpointClient tokenEndpointClient,
            TokenValidationBridge validationBridge,
            ClientAuthentication clientAuthentication,
            @Nullable SenderConstraint senderConstraint) {
        this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
        this.tokenEndpointClient = Objects.requireNonNull(tokenEndpointClient, "tokenEndpointClient must not be null");
        this.validationBridge = Objects.requireNonNull(validationBridge, "validationBridge must not be null");
        this.clientAuthentication = Objects.requireNonNull(clientAuthentication,
                "clientAuthentication must not be null");
        this.senderConstraint = senderConstraint;
    }

    /**
     * Obtains and validates an access token via the {@code client_credentials} grant.
     *
     * @param metadata the resolved provider metadata carrying the token endpoint; must not be
     *                 {@code null}
     * @return the validated access token content
     * @throws de.cuioss.sheriff.token.commons.error.TransportException if the token request fails
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if the returned
     *         token fails validation
     */
    public AccessTokenContent obtainToken(ProviderMetadata metadata) {
        Objects.requireNonNull(metadata, "metadata must not be null");
        String tokenEndpoint = metadata.getTokenEndpoint()
                .orElseThrow(() -> new IllegalStateException("provider metadata is missing the token endpoint"));

        Map<String, String> form = new LinkedHashMap<>();
        form.put(PARAM_GRANT_TYPE, GRANT_CLIENT_CREDENTIALS);
        if (!configuration.getScopes().isEmpty()) {
            form.put(PARAM_SCOPE, String.join(" ", configuration.getScopes()));
        }

        Map<String, String> headers = new HashMap<>();
        clientAuthentication.decorate(form, headers);

        TokenResponse tokenResponse = tokenEndpointClient.requestToken(tokenEndpoint, form, headers,
                senderConstraint);
        LOGGER.debug("Obtained client_credentials token for client '%s'", configuration.getClientId());

        return validationBridge.validateAccessToken(tokenResponse.accessToken);
    }
}

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
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenResponse;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Drives the OAuth 2.0 {@code refresh_token} grant (RFC 6749 §6) with refresh-token rotation.
 * <p>
 * The flow builds the {@code grant_type=refresh_token} request, applies the configured
 * {@link ClientAuthentication} strategy (deliverable 3), exchanges it at the token endpoint through
 * {@link TokenEndpointClient}, and validates the returned access token through the
 * {@link TokenValidationBridge} ({@code CLIENT-15}). It returns only a validated token — a
 * successful HTTP exchange alone is never trusted.
 * <p>
 * When the authorization server issues a new refresh token (rotation, per the OAuth 2.0 Security
 * BCP), the {@link RotationResult} reports the rotated token and flags the rotation; the caller
 * feeds that transition into its {@link de.cuioss.sheriff.token.client.token.RefreshTokenFamily} so
 * a later replay of a superseded token is detected and the family revoked ({@code CLIENT-17}).
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6 - Refreshing an Access Token</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics">OAuth 2.0 Security BCP</a>
 */
public class RefreshFlow {

    private static final CuiLogger LOGGER = new CuiLogger(RefreshFlow.class);

    private static final String PARAM_GRANT_TYPE = "grant_type";
    private static final String GRANT_REFRESH_TOKEN = "refresh_token";
    private static final String PARAM_REFRESH_TOKEN = "refresh_token";
    private static final String PARAM_SCOPE = "scope";

    private final ClientConfiguration configuration;
    private final TokenEndpointClient tokenEndpointClient;
    private final TokenValidationBridge validationBridge;
    private final ClientAuthentication clientAuthentication;
    @Nullable
    private final SenderConstraint senderConstraint;

    /**
     * Creates an unconstrained refresh flow (plain bearer token, no DPoP/mTLS).
     *
     * @param configuration        the client configuration; must not be {@code null}
     * @param tokenEndpointClient  the token-endpoint transport; must not be {@code null}
     * @param validationBridge     the validation bridge; must not be {@code null}
     * @param clientAuthentication the client authentication strategy to present; must not be
     *                             {@code null}
     */
    public RefreshFlow(ClientConfiguration configuration,
            TokenEndpointClient tokenEndpointClient,
            TokenValidationBridge validationBridge,
            ClientAuthentication clientAuthentication) {
        this(configuration, tokenEndpointClient, validationBridge, clientAuthentication, null);
    }

    /**
     * Creates a refresh flow that, when a sender-constraint is supplied, attaches a DPoP proof to the
     * refresh request so the rotated access token is issued bound to the proof key ({@code CLIENT-11}).
     *
     * @param configuration        the client configuration; must not be {@code null}
     * @param tokenEndpointClient  the token-endpoint transport; must not be {@code null}
     * @param validationBridge     the validation bridge; must not be {@code null}
     * @param clientAuthentication the client authentication strategy to present; must not be
     *                             {@code null}
     * @param senderConstraint     the DPoP/mTLS sender-constraint to attach, or {@code null} for a
     *                             plain bearer refresh
     */
    public RefreshFlow(ClientConfiguration configuration,
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
     * Exchanges a refresh token for a freshly validated access token, reporting any rotation.
     *
     * @param metadata     the resolved provider metadata carrying the token endpoint; must not be
     *                     {@code null}
     * @param refreshToken the refresh token to redeem; must not be {@code null} or blank
     * @return the rotation result carrying the validated access token, the refresh token to use
     *         next, and the raw refreshed ID token (when the AS issued one) for the lifecycle
     *         consistency check (OIDC Core §12.2)
     * @throws de.cuioss.sheriff.token.commons.error.TransportException if the token request fails
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if the returned
     *         token fails validation
     */
    public RotationResult refresh(ProviderMetadata metadata, String refreshToken) {
        Objects.requireNonNull(metadata, "metadata must not be null");
        Objects.requireNonNull(refreshToken, "refreshToken must not be null");
        if (refreshToken.isBlank()) {
            throw new IllegalArgumentException("refreshToken must not be blank");
        }
        String tokenEndpoint = metadata.getTokenEndpoint()
                .orElseThrow(() -> new IllegalStateException("provider metadata is missing the token endpoint"));

        Map<String, String> form = new HashMap<>(Map.of(
                PARAM_GRANT_TYPE, GRANT_REFRESH_TOKEN,
                PARAM_REFRESH_TOKEN, refreshToken));
        if (!configuration.getScopes().isEmpty()) {
            form.put(PARAM_SCOPE, String.join(" ", configuration.getScopes()));
        }

        Map<String, String> headers = new HashMap<>();
        clientAuthentication.decorate(form, headers);

        TokenResponse tokenResponse = tokenEndpointClient.requestToken(tokenEndpoint, form, headers,
                senderConstraint);
        AccessTokenContent accessToken = validationBridge.validateAccessToken(tokenResponse.accessToken);

        String rotatedRefreshToken = resolveRefreshToken(refreshToken, tokenResponse.refreshToken);
        boolean rotated = !rotatedRefreshToken.equals(refreshToken);
        LOGGER.debug("Refreshed access token for client '%s' (rotated=%s)", configuration.getClientId(), rotated);

        return new RotationResult(accessToken, rotatedRefreshToken, tokenResponse.idToken,
                tokenResponse.expiresIn, rotated);
    }

    /**
     * Resolves the refresh token to use for the next refresh: the rotated token the AS returned, or
     * the presented token when the AS chose not to rotate (RFC 6749 §6 permits omitting it).
     */
    private static String resolveRefreshToken(String presented, String issued) {
        if (issued != null && !issued.isBlank()) {
            return issued;
        }
        return presented;
    }
}

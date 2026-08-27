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

import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.internal.ClientLogMessages;
import de.cuioss.sheriff.token.client.internal.FormEncoder;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.tools.logging.CuiLogger;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Builds the front-channel {@code authorization_code} request URL (RFC 6749 §4.1.1) with PKCE
 * {@code S256} (RFC 7636) and optional RFC 9470 step-up parameters.
 * <p>
 * The URL always carries {@code response_type=code}, the {@code client_id}, the exact
 * {@code redirect_uri}, the requested {@code scope}, the anti-CSRF {@code state}, the {@code nonce},
 * and the PKCE {@code code_challenge} / {@code code_challenge_method=S256}. It also always requests
 * {@code response_mode=form_post} (OAuth 2.0 Form Post Response Mode) so the authorization response —
 * {@code code}, {@code state}, and the RFC 9207 {@code iss} — is delivered in the body of a POST to
 * the redirect URI rather than as query parameters on a redirect URL, where it would leak into
 * browser history, server logs, and the {@code Referer} header ({@code CLIENT-1} / {@code CLIENT-14},
 * {@code T-URL-LEAK}). When the flow context requests {@code acr_values} and/or a {@code max_age}
 * freshness constraint (RFC 9470 step-up), they are appended. The builder fails closed when the
 * authorization server does not advertise PKCE {@code S256}, so a downgrade to a non-PKCE (or
 * {@code plain}) request can never be issued ({@code CLIENT-2}).
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1 - Authorization Request</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9470">RFC 9470 - OAuth 2.0 Step Up Authentication Challenge</a>
 */
public class AuthorizationRequestBuilder {

    private static final CuiLogger LOGGER = new CuiLogger(AuthorizationRequestBuilder.class);

    private static final String PARAM_RESPONSE_TYPE = "response_type";
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String PARAM_CLIENT_ID = "client_id";
    private static final String PARAM_REDIRECT_URI = "redirect_uri";
    private static final String PARAM_SCOPE = "scope";
    private static final String PARAM_STATE = "state";
    private static final String PARAM_NONCE = "nonce";
    private static final String PARAM_CODE_CHALLENGE = "code_challenge";
    private static final String PARAM_CODE_CHALLENGE_METHOD = "code_challenge_method";
    private static final String PARAM_ACR_VALUES = "acr_values";
    private static final String PARAM_MAX_AGE = "max_age";
    private static final String PARAM_RESPONSE_MODE = "response_mode";
    private static final String RESPONSE_MODE_FORM_POST = "form_post";
    private static final String SCHEME_HTTPS = "https";
    private static final String SCHEME_HTTP = "http";

    /**
     * Builds the authorization request URL for the given flow context.
     *
     * @param configuration the client configuration; must not be {@code null}
     * @param metadata      the resolved provider metadata carrying the authorization endpoint; must
     *                      not be {@code null}
     * @param context       the flow context carrying {@code state}, {@code nonce}, PKCE, and the
     *                      redirect URI; must not be {@code null}
     * @return the fully-formed authorization request URL
     * @throws ClientProtocolException if the AS advertises no authorization endpoint or does not
     *                               advertise PKCE {@code S256}
     */
    public String build(ClientConfiguration configuration, ProviderMetadata metadata, FlowContext context) {
        Objects.requireNonNull(configuration, "configuration must not be null");
        Objects.requireNonNull(metadata, "metadata must not be null");
        Objects.requireNonNull(context, "context must not be null");

        String authorizationEndpoint = metadata.getAuthorizationEndpoint()
                .orElseThrow(() -> new ClientProtocolException(
                        "provider metadata is missing the authorization endpoint"));
        enforceEndpointScheme(authorizationEndpoint, configuration);
        if (!metadata.supportsS256()) {
            LOGGER.warn(ClientLogMessages.WARN.S256_NOT_ADVERTISED, metadata.getIssuer().orElse(authorizationEndpoint));
            throw new ClientProtocolException(
                    "authorization server does not advertise PKCE 'S256'; refusing to start the authorization_code"
                            + " flow");
        }

        Map<String, String> params = new HashMap<>(Map.of(
                PARAM_RESPONSE_TYPE, RESPONSE_TYPE_CODE,
                PARAM_CLIENT_ID, configuration.getClientId(),
                PARAM_REDIRECT_URI, context.redirectUri()));
        if (!configuration.getScopes().isEmpty()) {
            params.put(PARAM_SCOPE, String.join(" ", configuration.getScopes()));
        }
        params.put(PARAM_STATE, context.state());
        params.put(PARAM_NONCE, context.nonce());
        params.put(PARAM_CODE_CHALLENGE, context.pkceChallenge().codeChallenge());
        params.put(PARAM_CODE_CHALLENGE_METHOD, context.pkceChallenge().method());
        params.put(PARAM_RESPONSE_MODE, RESPONSE_MODE_FORM_POST);
        context.acrValues().ifPresent(acr -> params.put(PARAM_ACR_VALUES, acr));
        context.maxAge().ifPresent(maxAge -> params.put(PARAM_MAX_AGE, Integer.toString(maxAge)));

        return authorizationEndpoint + (authorizationEndpoint.indexOf('?') < 0 ? '?' : '&') + FormEncoder.encode(params);
    }

    /**
     * Refuses a non-TLS authorization endpoint (L5). The authorization request URL is the front-channel
     * redirect the user agent follows, so a cleartext {@code http://} endpoint would expose the
     * {@code state}/{@code nonce}/PKCE parameters — and the resulting authorization code — to a network
     * observer. A non-TLS endpoint is rejected unless {@link ClientConfiguration#allowInsecureHttp}
     * is set for a local test setup, mirroring the discovery/back-channel TLS policy.
     */
    private static void enforceEndpointScheme(String authorizationEndpoint, ClientConfiguration configuration) {
        String scheme;
        try {
            scheme = URI.create(authorizationEndpoint).getScheme();
        } catch (IllegalArgumentException e) {
            throw new ClientProtocolException(
                    "authorization endpoint is not a valid URL: " + authorizationEndpoint, e);
        }
        if (SCHEME_HTTPS.equalsIgnoreCase(scheme)) {
            return;
        }
        // Only literal cleartext http is tolerated, and only when explicitly allowed for a local test
        // setup. Any other scheme (ftp/file/javascript/…) and an absent/blank scheme are rejected, so a
        // non-http(s) authorization endpoint can never be issued.
        if (configuration.isAllowInsecureHttp() && SCHEME_HTTP.equalsIgnoreCase(scheme)) {
            return;
        }
        throw new ClientProtocolException(
                "authorization endpoint is not a TLS (https) URL; refusing to start the authorization_code"
                        + " flow over an insecure channel");
    }
}

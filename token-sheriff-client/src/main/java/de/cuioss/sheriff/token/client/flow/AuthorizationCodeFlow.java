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
import de.cuioss.sheriff.token.client.token.IdTokenValidationBridge;
import de.cuioss.sheriff.token.client.token.TokenResponse;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Drives the interactive OpenID Connect {@code authorization_code} flow with PKCE {@code S256}
 * (RFC 6749 §4.1 / RFC 7636 / OIDC Core).
 * <p>
 * The flow has two halves bridged by the relying party's session:
 * <ol>
 *   <li>{@link #authorize(ProviderMetadata)} mints a {@link FlowContext} (fresh {@code state},
 *       {@code nonce}, PKCE) and returns the authorization URL to redirect the user to;</li>
 *   <li>{@link #exchange(ProviderMetadata, FlowContext, CallbackParameters, ClientAuthentication)}
 *       validates the callback, redeems the code at the token endpoint with the PKCE verifier and
 *       client authentication, and validates the returned access token and ID token (binding the ID
 *       token's {@code nonce} to the flow and, per OIDC Core §3.1.3.6, its {@code at_hash} to the
 *       returned access token).</li>
 * </ol>
 * Only validated tokens are returned — a successful HTTP exchange alone is never trusted
 * ({@code CLIENT-15}).
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1">RFC 6749 §4.1 - Authorization Code Grant</a>
 */
public class AuthorizationCodeFlow {

    private static final CuiLogger LOGGER = new CuiLogger(AuthorizationCodeFlow.class);

    private static final String PARAM_GRANT_TYPE = "grant_type";
    private static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
    private static final String PARAM_CODE = "code";
    private static final String PARAM_REDIRECT_URI = "redirect_uri";
    private static final String PARAM_CODE_VERIFIER = "code_verifier";

    private final ClientConfiguration configuration;
    private final TokenEndpointClient tokenEndpointClient;
    private final TokenValidationBridge accessTokenBridge;
    private final IdTokenValidationBridge idTokenBridge;
    private final IssValidator issValidator;
    private final AuthorizationRequestBuilder authorizationRequestBuilder;
    private final CallbackHandler callbackHandler;
    @Nullable
    private final SenderConstraint senderConstraint;

    /**
     * Creates a flow with a default {@link IssValidator}, {@link AuthorizationRequestBuilder}, and
     * {@link CallbackHandler}.
     *
     * @param configuration       the client configuration; must not be {@code null}
     * @param tokenEndpointClient the token-endpoint transport; must not be {@code null}
     * @param accessTokenBridge   the access-token validation bridge; must not be {@code null}
     * @param idTokenBridge       the ID-token validation bridge; must not be {@code null}
     */
    public AuthorizationCodeFlow(ClientConfiguration configuration, TokenEndpointClient tokenEndpointClient,
            TokenValidationBridge accessTokenBridge, IdTokenValidationBridge idTokenBridge) {
        this(configuration, tokenEndpointClient, accessTokenBridge, idTokenBridge, new IssValidator(),
                new AuthorizationRequestBuilder(), new CallbackHandler(), null);
    }

    /**
     * Creates a flow with an explicit {@link IssValidator} and default {@link AuthorizationRequestBuilder}
     * / {@link CallbackHandler}.
     * <p>
     * When {@code senderConstraint} is supplied, the initial code redemption is DPoP/mTLS-bound so the
     * issued access token is confirmed to the proof key ({@code CLIENT-11}); {@code null} preserves the
     * plain-bearer redemption.
     *
     * @param configuration       the client configuration; must not be {@code null}
     * @param tokenEndpointClient the token-endpoint transport; must not be {@code null}
     * @param accessTokenBridge   the access-token validation bridge; must not be {@code null}
     * @param idTokenBridge       the ID-token validation bridge; must not be {@code null}
     * @param issValidator        the RFC 9207 issuer mix-up validator; must not be {@code null}
     * @param senderConstraint    the DPoP/mTLS sender-constraint to attach to the code exchange, or
     *                            {@code null} for a plain bearer redemption
     */
    public AuthorizationCodeFlow(ClientConfiguration configuration, TokenEndpointClient tokenEndpointClient,
            TokenValidationBridge accessTokenBridge, IdTokenValidationBridge idTokenBridge,
            IssValidator issValidator, @Nullable SenderConstraint senderConstraint) {
        this(configuration, tokenEndpointClient, accessTokenBridge, idTokenBridge, issValidator,
                new AuthorizationRequestBuilder(), new CallbackHandler(), senderConstraint);
    }

    /**
     * Creates a flow with explicit collaborators.
     *
     * @param configuration               the client configuration; must not be {@code null}
     * @param tokenEndpointClient         the token-endpoint transport; must not be {@code null}
     * @param accessTokenBridge           the access-token validation bridge; must not be {@code null}
     * @param idTokenBridge               the ID-token validation bridge; must not be {@code null}
     * @param issValidator                the RFC 9207 issuer mix-up validator; must not be {@code null}
     * @param authorizationRequestBuilder the authorization-request builder; must not be {@code null}
     * @param callbackHandler             the callback handler; must not be {@code null}
     * @param senderConstraint            the DPoP/mTLS sender-constraint to attach to the code exchange,
     *                                    or {@code null} for a plain bearer redemption
     */
    // S107 (too many parameters) is unavoidable here: this is the explicit-collaborators constructor
    // that exposes every dependency for DI/testing; the two shorter overloads above delegate to it.
    // Collapsing the parameters into a parameter object would obscure, not reduce, the collaborators.
    @SuppressWarnings("java:S107")
    public AuthorizationCodeFlow(ClientConfiguration configuration, TokenEndpointClient tokenEndpointClient,
            TokenValidationBridge accessTokenBridge, IdTokenValidationBridge idTokenBridge,
            IssValidator issValidator, AuthorizationRequestBuilder authorizationRequestBuilder,
            CallbackHandler callbackHandler, @Nullable SenderConstraint senderConstraint) {
        this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
        this.tokenEndpointClient = Objects.requireNonNull(tokenEndpointClient, "tokenEndpointClient must not be null");
        this.accessTokenBridge = Objects.requireNonNull(accessTokenBridge, "accessTokenBridge must not be null");
        this.idTokenBridge = Objects.requireNonNull(idTokenBridge, "idTokenBridge must not be null");
        this.issValidator = Objects.requireNonNull(issValidator, "issValidator must not be null");
        this.authorizationRequestBuilder = Objects.requireNonNull(authorizationRequestBuilder,
                "authorizationRequestBuilder must not be null");
        this.callbackHandler = Objects.requireNonNull(callbackHandler, "callbackHandler must not be null");
        this.senderConstraint = senderConstraint;
    }

    /**
     * Starts the flow: mints a flow context and builds the authorization URL to redirect to.
     *
     * @param metadata the resolved provider metadata; must not be {@code null}
     * @return the authorization redirect (URL + flow context to persist)
     * @throws IllegalArgumentException if the client declares no redirect URI
     * @throws IllegalStateException    if the AS advertises no authorization endpoint or no PKCE
     *                                  {@code S256}
     */
    public AuthorizationRedirect authorize(ProviderMetadata metadata) {
        Objects.requireNonNull(metadata, "metadata must not be null");
        String redirectUri = configuration.getRedirectUri();
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IllegalArgumentException("client declares no redirect URI");
        }
        FlowContext context = FlowContext.create(redirectUri);
        String url = authorizationRequestBuilder.build(configuration, metadata, context);
        return new AuthorizationRedirect(url, context);
    }

    /**
     * Completes the flow: validates the callback, redeems the code, and validates the tokens.
     *
     * @param metadata             the resolved provider metadata carrying the token endpoint; must
     *                             not be {@code null}
     * @param context              the flow context that started this flow; must not be {@code null}
     * @param callback             the parsed callback parameters; must not be {@code null}
     * @param clientAuthentication the client authentication strategy to present; must not be
     *                             {@code null}
     * @return the validated access token and ID token
     * @throws de.cuioss.sheriff.token.commons.error.TransportException if the token request fails
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if a token fails
     *         validation
     * @throws IllegalStateException if the callback is invalid or no ID token is returned
     */
    public AuthenticationResult exchange(ProviderMetadata metadata, FlowContext context,
            CallbackParameters callback, ClientAuthentication clientAuthentication) {
        Objects.requireNonNull(metadata, "metadata must not be null");
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(callback, "callback must not be null");
        Objects.requireNonNull(clientAuthentication, "clientAuthentication must not be null");

        String code = callbackHandler.handle(context, callback);

        // RFC 9207 mix-up defence (CLIENT-8): after the state check and BEFORE redeeming the code,
        // reject the callback when the returned 'iss' does not match the issuer this flow was started
        // with. When the AS advertises authorization_response_iss_parameter_supported, an absent 'iss'
        // is itself a mix-up signal, so the issuer is required — closing the omit-iss bypass.
        boolean requireIssuer = metadata.supportsAuthorizationResponseIssParameter();
        issValidator.validate(configuration.getIssuer(), callback, requireIssuer);

        String tokenEndpoint = metadata.getTokenEndpoint()
                .orElseThrow(() -> new IllegalStateException("provider metadata is missing the token endpoint"));

        Map<String, String> form = new HashMap<>(Map.of(
                PARAM_GRANT_TYPE, GRANT_AUTHORIZATION_CODE,
                PARAM_CODE, code,
                PARAM_REDIRECT_URI, context.redirectUri(),
                PARAM_CODE_VERIFIER, context.pkceChallenge().codeVerifier()));

        Map<String, String> headers = new HashMap<>();
        clientAuthentication.decorate(form, headers);

        // Route through the constraint-bearing overload so a DPoP/mTLS-requiring AS can bind the
        // initial code redemption; a null senderConstraint preserves the plain-bearer exchange.
        // The one-shot use_dpop_nonce retry the 4-arg overload implements applies only when a DPoP
        // senderConstraint is supplied — it never fires for the null-senderConstraint plain-bearer path.
        TokenResponse tokenResponse = tokenEndpointClient.requestToken(tokenEndpoint, form, headers,
                senderConstraint);
        AccessTokenContent accessToken = accessTokenBridge.validateAccessToken(tokenResponse.accessToken);

        if (tokenResponse.idToken == null || tokenResponse.idToken.isBlank()) {
            throw new IllegalStateException("authorization_code response is missing the ID token");
        }
        // Bind the ID token to the access token issued in the same response via 'at_hash' (OIDC Core
        // §3.1.3.6, M4): both tokens were requested and validated together here, so this is the call
        // site where the at_hash check the validation bridge exposes must actually be exercised;
        // the two-arg overload (nonce only) would silently skip it.
        IdTokenContent idToken = idTokenBridge.validateIdToken(tokenResponse.idToken, context.nonce(),
                tokenResponse.accessToken);
        LOGGER.debug("Completed authorization_code exchange for client '%s'", configuration.getClientId());

        return new AuthenticationResult(accessToken, idToken);
    }

    /**
     * The authorization redirect produced by {@link #authorize(ProviderMetadata)}.
     *
     * @param authorizationUrl the authorization request URL to redirect the user to
     * @param context          the flow context to persist until the callback returns
     */
    public record AuthorizationRedirect(String authorizationUrl, FlowContext context) {

        /**
         * @param authorizationUrl the authorization request URL; must not be {@code null}
         * @param context          the flow context; must not be {@code null}
         */
        public AuthorizationRedirect {
            Objects.requireNonNull(authorizationUrl, "authorizationUrl must not be null");
            Objects.requireNonNull(context, "context must not be null");
        }
    }

    /**
     * The validated tokens produced by a successful {@code authorization_code} exchange.
     *
     * @param accessToken the validated access token content
     * @param idToken     the validated, nonce-bound ID token content
     */
    public record AuthenticationResult(AccessTokenContent accessToken, IdTokenContent idToken) {

        /**
         * @param accessToken the validated access token content; must not be {@code null}
         * @param idToken     the validated ID token content; must not be {@code null}
         */
        public AuthenticationResult {
            Objects.requireNonNull(accessToken, "accessToken must not be null");
            Objects.requireNonNull(idToken, "idToken must not be null");
        }
    }
}

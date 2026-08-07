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
package de.cuioss.sheriff.token.client.token;

import com.dslplatform.json.DslJson;
import de.cuioss.http.client.handler.HttpHandler;
import de.cuioss.http.client.handler.HttpStatusFamily;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.dpop.SenderConstraint;
import de.cuioss.sheriff.token.client.internal.BackChannelHttp;
import de.cuioss.sheriff.token.client.internal.LogSanitizer;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Fetches the OpenID Connect userinfo document over the authenticated back channel and normalizes it
 * ({@code CLIENT-16}).
 * <p>
 * The client presents the validated access token as an RFC 6750 {@code Bearer} credential to the
 * userinfo endpoint over TLS and normalizes the JSON response into a {@link UserInfoResponse}. The
 * response is transport-authenticated only; its identity is never trusted until
 * {@link SubBindingValidator} binds the {@code sub} back to the validated ID token. The transport
 * reuses the commons-blessed cui-http {@link HttpHandler}; it adds no transport hardening of its own.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC Core §5.3</a>
 */
public class UserInfoClient {

    private static final CuiLogger LOGGER = new CuiLogger(UserInfoClient.class);

    private static final String AUTHORIZATION = "Authorization";
    private static final String ACCEPT = "Accept";
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String APPLICATION_JSON = "application/json";
    private static final String APPLICATION_JWT = "application/jwt";
    private static final String ACCEPT_JSON_OR_JWT = APPLICATION_JSON + ", " + APPLICATION_JWT;
    private static final String HTTP_GET = "GET";
    private static final String BEARER_SCHEME = "Bearer";
    private static final String FAILURE_CONTEXT = "userinfo request failed";

    /**
     * Validation seam for a signed userinfo response (OIDC Core §5.3.2,
     * {@code userinfo_signed_response_alg}, M3). The relying party supplies the implementation that
     * runs the signed JWT through the existing token-validation pipeline (signature via JWKS,
     * {@code iss}, {@code aud}) and returns the normalized claims. Keeping it a seam lets the transport
     * support the signed path without coupling to the validation module or changing the wiring of
     * callers that only ever see plain JSON userinfo.
     */
    @FunctionalInterface
    public interface SignedUserInfoValidator {

        /**
         * @param signedJwt the raw signed userinfo JWT (the response body); never {@code null} or blank
         * @return the validated, normalized userinfo claims
         */
        UserInfoResponse validate(String signedJwt);
    }

    private final DslJson<Object> dslJson;
    private final int maxContentSize;
    private final BackChannelHttp backChannel;

    /**
     * @param configuration the client configuration carrying the TLS policy; must not be {@code null}
     */
    public UserInfoClient(ClientConfiguration configuration) {
        Objects.requireNonNull(configuration, "configuration must not be null");
        ParserConfig parserConfig = ParserConfig.builder().build();
        this.dslJson = parserConfig.getDslJson();
        this.maxContentSize = parserConfig.getMaxPayloadSize();
        this.backChannel = new BackChannelHttp(configuration, maxContentSize,
                BackChannelHttp.FIXED_PARSER_CONFIG_ORIGIN);
    }

    /**
     * Fetches the userinfo document, presenting the access token as a plain RFC 6750 {@code Bearer}
     * credential.
     *
     * @param userInfoEndpoint the absolute userinfo endpoint URL (from discovery); must be TLS unless
     *                         {@link ClientConfiguration#allowInsecureHttp} is set
     * @param accessToken      the validated access token to present as a Bearer credential; must not
     *                         be {@code null}
     * @return the normalized userinfo response
     * @throws TransportException if the request fails, the response is not successful, the body cannot
     *         be parsed, or the response omits the {@code sub}
     */
    public UserInfoResponse fetchUserInfo(String userInfoEndpoint, String accessToken) {
        return fetchUserInfo(userInfoEndpoint, accessToken, null);
    }

    /**
     * Fetches the userinfo document, presenting the access token under the scheme its sender-constraint
     * requires.
     * <p>
     * When {@code senderConstraint} is a DPoP constraint, the token is presented as an
     * {@code Authorization: DPoP <token>} credential (RFC 9449 §7.1) accompanied by a fresh
     * protected-resource DPoP proof whose {@code ath} claim binds the proof to this exact token
     * (RFC 9449 §4.3). Otherwise — no constraint, or an mTLS constraint that binds at the TLS layer —
     * the token is presented as a plain {@code Bearer} credential.
     *
     * @param userInfoEndpoint the absolute userinfo endpoint URL (from discovery); must be TLS unless
     *                         {@link ClientConfiguration#allowInsecureHttp} is set
     * @param accessToken      the validated access token to present; must not be {@code null}
     * @param senderConstraint the DPoP/mTLS sender-constraint the token was bound under, or
     *                         {@code null} for a plain bearer token
     * @return the normalized userinfo response
     * @throws TransportException if the request fails, the response is not successful, the body cannot
     *         be parsed, or the response omits the {@code sub}
     */
    public UserInfoResponse fetchUserInfo(String userInfoEndpoint, String accessToken,
            @Nullable SenderConstraint senderConstraint) {
        return fetchUserInfo(userInfoEndpoint, accessToken, senderConstraint, null);
    }

    /**
     * Fetches the userinfo document, supporting both a plain JSON response and a signed JWT response
     * (OIDC Core §5.3.2, {@code userinfo_signed_response_alg}, M3).
     * <p>
     * The request advertises {@code Accept: application/json, application/jwt}. When the response is a
     * signed JWT (its {@code Content-Type} is {@code application/jwt}), the body is validated through
     * the supplied {@code signedResponseValidator} — which runs it through the existing token-validation
     * pipeline — rather than parsed as JSON. A signed response with no validator supplied fails closed
     * rather than being mis-parsed. A plain JSON response is parsed exactly as before.
     *
     * @param userInfoEndpoint         the absolute userinfo endpoint URL (from discovery); must be TLS
     *                                 unless {@link ClientConfiguration#allowInsecureHttp} is set
     * @param accessToken              the validated access token to present; must not be {@code null}
     * @param senderConstraint         the DPoP/mTLS sender-constraint the token was bound under, or
     *                                 {@code null} for a plain bearer token
     * @param signedResponseValidator  the validator for a signed JWT userinfo response, or {@code null}
     *                                 when only a plain JSON response is expected
     * @return the normalized userinfo response
     * @throws TransportException if the request fails, the response is not successful, the body cannot
     *         be parsed or validated, the response is a signed JWT but no validator was supplied, or the
     *         response omits the {@code sub}
     */
    public UserInfoResponse fetchUserInfo(String userInfoEndpoint, String accessToken,
            @Nullable SenderConstraint senderConstraint,
            @Nullable SignedUserInfoValidator signedResponseValidator) {
        Objects.requireNonNull(userInfoEndpoint, "userInfoEndpoint must not be null");
        Objects.requireNonNull(accessToken, "accessToken must not be null");

        HttpHandler handler = backChannel.validatedHandler(userInfoEndpoint, FAILURE_CONTEXT);

        HttpRequest.Builder requestBuilder = handler.requestBuilder()
                .setHeader(ACCEPT, ACCEPT_JSON_OR_JWT)
                .GET();
        authorize(requestBuilder, userInfoEndpoint, accessToken, senderConstraint);
        HttpRequest request = requestBuilder.build();

        HttpClient client = backChannel.sharedClient(handler);
        try {
            HttpResponse<String> response = client.send(request, backChannel.bodyHandler());
            if (!HttpStatusFamily.isSuccess(response.statusCode())) {
                throw new TransportException(
                        "userinfo endpoint returned unexpected HTTP status " + response.statusCode());
            }
            return handleResponse(response, signedResponseValidator);
        } catch (IOException e) {
            LOGGER.debug(e, "userinfo request failed: %s", e.getMessage());
            throw new TransportException("userinfo request failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransportException("userinfo request interrupted", e);
        }
    }

    private UserInfoResponse handleResponse(HttpResponse<String> response,
            @Nullable SignedUserInfoValidator signedResponseValidator) {
        boolean signed = response.headers().firstValue(CONTENT_TYPE)
                .map(contentType -> contentType.toLowerCase(Locale.ROOT).contains(APPLICATION_JWT))
                .orElse(false);
        if (!signed) {
            return parse(response.body());
        }
        if (signedResponseValidator == null) {
            throw new TransportException("userinfo endpoint returned a signed JWT "
                    + "(userinfo_signed_response_alg) but no signed-response validator is configured");
        }
        String body = response.body();
        if (body == null || body.isBlank()) {
            throw new TransportException("Empty userinfo endpoint response");
        }
        UserInfoResponse userInfo = signedResponseValidator.validate(body);
        // java:S2589 — the SignedUserInfoValidator functional interface and UserInfoResponse.sub are
        // declared non-null under @NullMarked, but a caller-supplied validator implementation can
        // still violate that contract; kept as a defensive guard against a misbehaving validator.
        @SuppressWarnings("java:S2589")
        boolean missingSub = userInfo == null || userInfo.sub == null || userInfo.sub.isBlank();
        if (missingSub) {
            throw new TransportException("signed userinfo response is missing the 'sub' claim");
        }
        return userInfo;
    }

    /**
     * Sets the {@code Authorization} header under the scheme the sender-constraint requires, and — for
     * a DPoP constraint — adds the accompanying {@code ath}-bound protected-resource proof header.
     */
    private static void authorize(HttpRequest.Builder requestBuilder, String userInfoEndpoint,
            String accessToken, @Nullable SenderConstraint senderConstraint) {
        String scheme = senderConstraint == null ? BEARER_SCHEME : senderConstraint.authorizationScheme();
        requestBuilder.setHeader(AUTHORIZATION, scheme + " " + accessToken);
        if (senderConstraint != null) {
            Map<String, String> proofHeaders = new HashMap<>();
            senderConstraint.applyProtectedResource(HTTP_GET, userInfoEndpoint, accessToken, null, proofHeaders);
            proofHeaders.forEach(requestBuilder::setHeader);
        }
    }

    // java:S2589 — body is non-null by every current caller/handler wiring, but the guard is kept
    // (consistent with the equivalent parse() entry guards in ParClient / TokenEndpointClient) as
    // defensive resilience against a future change to the shared bounded body-handler.
    @SuppressWarnings("java:S2589")
    private UserInfoResponse parse(String body) {
        if (body == null || body.isBlank()) {
            throw new TransportException("Empty userinfo endpoint response");
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > maxContentSize) {
            throw new TransportException("userinfo endpoint response exceeds maximum allowed size of "
                    + maxContentSize + " bytes (" + BackChannelHttp.FIXED_PARSER_CONFIG_ORIGIN + ")");
        }
        try {
            UserInfoResponse userInfo = dslJson.deserialize(UserInfoResponse.class, bytes, bytes.length);
            if (userInfo == null || userInfo.sub == null || userInfo.sub.isBlank()) {
                throw new TransportException("userinfo endpoint response is missing the 'sub' claim");
            }
            return userInfo;
        } catch (IOException e) {
            // The parse-error message can echo an AS-controlled JSON fragment; sanitize it (CWE-117)
            // before it reaches the log appender or the exception message.
            String sanitizedError = LogSanitizer.sanitize(e.getMessage());
            LOGGER.debug("Failed to parse userinfo endpoint response: %s", sanitizedError);
            throw new TransportException("Failed to parse userinfo endpoint response: " + sanitizedError, e);
        }
    }
}

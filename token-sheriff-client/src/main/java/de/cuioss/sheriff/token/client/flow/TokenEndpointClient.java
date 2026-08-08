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
package de.cuioss.sheriff.token.client.flow;

import com.dslplatform.json.DslJson;
import de.cuioss.http.client.handler.HttpHandler;
import de.cuioss.http.client.handler.HttpStatusFamily;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.dpop.ConstraintBinding;
import de.cuioss.sheriff.token.client.dpop.SenderConstraint;
import de.cuioss.sheriff.token.client.internal.BackChannelHttp;
import de.cuioss.sheriff.token.client.internal.FormEncoder;
import de.cuioss.sheriff.token.client.internal.LogSanitizer;
import de.cuioss.sheriff.token.client.token.TokenResponse;
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
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Thin transport wrapper for the OAuth 2.0 back-channel token endpoint.
 * <p>
 * The client composes the commons-blessed cui-http {@link HttpHandler} (design fork 1) to perform
 * the authenticated, form-encoded {@code POST} to the token endpoint over TLS, then normalizes the
 * JSON response into a {@link TokenResponse}. It adds no transport hardening of its own — TLS/SSRF
 * posture is inherited from {@code HttpHandler}. Client authentication is decorated onto the request
 * by the caller (headers and/or form parameters); this class is auth-agnostic transport only.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class TokenEndpointClient {

    private static final CuiLogger LOGGER = new CuiLogger(TokenEndpointClient.class);

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final String HTTP_POST = "POST";
    private static final String DPOP_NONCE_HEADER = "DPoP-Nonce";
    private static final String FAILURE_CONTEXT = "Token endpoint request failed";

    private final DslJson<Object> dslJson;
    private final int maxContentSize;
    private final BackChannelHttp backChannel;

    /**
     * @param configuration the client configuration carrying the TLS policy; must not be {@code null}
     */
    public TokenEndpointClient(ClientConfiguration configuration) {
        Objects.requireNonNull(configuration, "configuration must not be null");
        ParserConfig parserConfig = ParserConfig.builder().build();
        this.dslJson = parserConfig.getDslJson();
        this.maxContentSize = parserConfig.getMaxPayloadSize();
        this.backChannel = new BackChannelHttp(configuration, maxContentSize,
                BackChannelHttp.FIXED_PARSER_CONFIG_ORIGIN);
    }

    /**
     * Performs a form-encoded {@code POST} to the token endpoint with no sender-constraint and
     * normalizes the response.
     *
     * @param tokenEndpoint    the absolute token endpoint URL (from discovery); must be TLS unless
     *                         {@link ClientConfiguration#allowInsecureHttp} is set
     * @param formParameters   the form-encoded request body parameters (e.g. {@code grant_type})
     * @param requestHeaders   additional request headers (e.g. an {@code Authorization} header)
     * @return the normalized token response
     * @throws TransportException if the request fails, the response is not successful, or the body
     *         cannot be parsed
     */
    public TokenResponse requestToken(String tokenEndpoint,
            Map<String, String> formParameters,
            Map<String, String> requestHeaders) {
        return requestToken(tokenEndpoint, formParameters, requestHeaders, null);
    }

    /**
     * Performs a form-encoded {@code POST} to the token endpoint, attaching a DPoP proof when a
     * sender-constraint is supplied, and normalizes the response.
     * <p>
     * When {@code senderConstraint} is a DPoP constraint, a proof is generated for the token endpoint
     * and added as the {@code DPoP} header. If the authorization server rejects the first attempt with
     * a {@code use_dpop_nonce} challenge — a non-success status carrying a {@code DPoP-Nonce} response
     * header (RFC 9449 §8) — the nonce is echoed into a fresh proof and the request is retried once,
     * rather than surfacing the recoverable challenge as an opaque transport failure. mTLS constraints
     * add no header (the binding is transport-level) and never trigger a nonce retry.
     *
     * @param tokenEndpoint    the absolute token endpoint URL (from discovery); must be TLS unless
     *                         {@link ClientConfiguration#allowInsecureHttp} is set
     * @param formParameters   the form-encoded request body parameters (e.g. {@code grant_type})
     * @param requestHeaders   additional request headers (e.g. an {@code Authorization} header)
     * @param senderConstraint the DPoP/mTLS sender-constraint to apply, or {@code null} for a plain
     *                         bearer-token request
     * @return the normalized token response
     * @throws TransportException if the request fails, the response is not successful (after a nonce
     *         retry where applicable), or the body cannot be parsed
     */
    public TokenResponse requestToken(String tokenEndpoint,
            Map<String, String> formParameters,
            Map<String, String> requestHeaders,
            @Nullable SenderConstraint senderConstraint) {
        Objects.requireNonNull(tokenEndpoint, "tokenEndpoint must not be null");
        Objects.requireNonNull(formParameters, "formParameters must not be null");
        Objects.requireNonNull(requestHeaders, "requestHeaders must not be null");

        HttpHandler handler = backChannel.validatedHandler(tokenEndpoint, FAILURE_CONTEXT);
        HttpClient client = backChannel.sharedClient(handler);
        String body = FormEncoder.encode(formParameters);

        HttpResponse<String> response = send(handler, client, body,
                proofHeaders(tokenEndpoint, requestHeaders, senderConstraint, null));
        if (!HttpStatusFamily.isSuccess(response.statusCode())) {
            Optional<String> nonce = dpopNonceChallenge(response, senderConstraint);
            if (nonce.isPresent()) {
                response = send(handler, client, body,
                        proofHeaders(tokenEndpoint, requestHeaders, senderConstraint, nonce.get()));
            }
        }
        if (!HttpStatusFamily.isSuccess(response.statusCode())) {
            throw new TransportException(
                    "Token endpoint returned unexpected HTTP status " + response.statusCode());
        }
        return parse(response.body());
    }

    /**
     * Composes the request headers for one attempt: the caller-supplied headers plus, when a DPoP
     * constraint is present, a fresh single-use {@code DPoP} proof for the token endpoint (optionally
     * echoing a challenged {@code nonce}). A fresh map is returned per attempt so the caller's header
     * map is never mutated and each retry carries its own single-use proof.
     */
    private static Map<String, String> proofHeaders(String tokenEndpoint, Map<String, String> requestHeaders,
            @Nullable SenderConstraint senderConstraint, @Nullable String nonce) {
        Map<String, String> headers = new HashMap<>(requestHeaders);
        if (senderConstraint != null) {
            senderConstraint.apply(HTTP_POST, tokenEndpoint, nonce, headers);
        }
        return headers;
    }

    /**
     * @return the {@code DPoP-Nonce} value when the failed response is a recoverable
     *         {@code use_dpop_nonce} challenge against a DPoP constraint, otherwise empty
     */
    private static Optional<String> dpopNonceChallenge(HttpResponse<String> response,
            @Nullable SenderConstraint senderConstraint) {
        if (senderConstraint == null || senderConstraint.method() != ConstraintBinding.Method.DPOP) {
            return Optional.empty();
        }
        return response.headers().firstValue(DPOP_NONCE_HEADER)
                .filter(nonce -> !nonce.isBlank());
    }

    private HttpResponse<String> send(HttpHandler handler, HttpClient client, String body,
            Map<String, String> requestHeaders) {
        HttpRequest.Builder requestBuilder = handler.requestBuilder()
                .setHeader(CONTENT_TYPE, FORM_URLENCODED)
                .POST(HttpRequest.BodyPublishers.ofString(body));
        requestHeaders.forEach(requestBuilder::setHeader);
        try {
            return client.send(requestBuilder.build(), backChannel.bodyHandler());
        } catch (IOException e) {
            LOGGER.debug(e, "Token endpoint request failed: %s", e.getMessage());
            throw new TransportException("Token endpoint request failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransportException("Token endpoint request interrupted", e);
        }
    }

    // java:S2589 — body is non-null by every current caller/handler wiring, but the guard is kept
    // (consistent with the equivalent parse() entry guards in UserInfoClient / ParClient) as
    // defensive resilience against a future change to the shared bounded body-handler.
    @SuppressWarnings("java:S2589")
    private TokenResponse parse(String body) {
        if (body == null || body.isBlank()) {
            throw new TransportException("Empty token endpoint response");
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > maxContentSize) {
            throw new TransportException("Token endpoint response exceeds maximum allowed size of "
                    + maxContentSize + " bytes (" + BackChannelHttp.FIXED_PARSER_CONFIG_ORIGIN + ")");
        }
        try {
            TokenResponse tokenResponse = dslJson.deserialize(TokenResponse.class, bytes, bytes.length);
            if (tokenResponse == null || tokenResponse.accessToken == null) {
                throw new TransportException("Token endpoint response is missing the access_token");
            }
            if (!tokenResponse.hasRecognizedTokenType()) {
                // RFC 6749 §5.1 makes token_type REQUIRED; a missing or unrecognized type must not be
                // silently consumed as Bearer. tokenType is AS-controlled, so sanitize it (CWE-117)
                // before it reaches the exception message on a plain-text appender path.
                throw new TransportException("Token endpoint response has an unsupported token_type: "
                        + LogSanitizer.sanitize(tokenResponse.tokenType));
            }
            return tokenResponse;
        } catch (IOException e) {
            // The parse-error message can echo an AS-controlled JSON fragment; sanitize it (CWE-117)
            // before it reaches the log appender or the exception message, matching the token_type site.
            String sanitizedError = LogSanitizer.sanitize(e.getMessage());
            LOGGER.debug("Failed to parse token endpoint response: %s", sanitizedError);
            throw new TransportException("Failed to parse token endpoint response: " + sanitizedError, e);
        }
    }

}

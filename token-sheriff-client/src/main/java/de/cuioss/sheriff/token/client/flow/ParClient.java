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
import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.internal.BackChannelHttp;
import de.cuioss.sheriff.token.client.internal.FormEncoder;
import de.cuioss.sheriff.token.client.internal.LogSanitizer;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Pushes an authorization request to the RFC 9126 pushed-authorization-request (PAR) endpoint over
 * the authenticated back channel and returns the opaque {@code request_uri} to carry on the
 * front-channel redirect ({@code CLIENT-10}).
 * <p>
 * Rather than placing the authorization parameters (including PKCE, {@code state}, {@code nonce}) on
 * the front-channel URL where a user agent or network attacker can observe or tamper with them, PAR
 * sends them directly to the AS over TLS with client authentication, and the AS returns a single-use
 * {@code request_uri}. The front-channel redirect then carries only {@code client_id} and that
 * {@code request_uri}, so the raw authorization parameters never traverse the browser
 * ({@code T-PARAM-INTEGRITY}). The transport reuses the commons-blessed cui-http {@link HttpHandler};
 * it adds no transport hardening of its own.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 */
public class ParClient {

    private static final CuiLogger LOGGER = new CuiLogger(ParClient.class);

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final String FAILURE_CONTEXT = "PAR request failed";

    private final DslJson<Object> dslJson;
    private final int maxContentSize;
    private final BackChannelHttp backChannel;

    /**
     * @param configuration the client configuration carrying the TLS policy; must not be {@code null}
     */
    public ParClient(ClientConfiguration configuration) {
        Objects.requireNonNull(configuration, "configuration must not be null");
        ParserConfig parserConfig = ParserConfig.builder().build();
        this.dslJson = parserConfig.getDslJson();
        this.maxContentSize = parserConfig.getMaxPayloadSize();
        this.backChannel = new BackChannelHttp(configuration, maxContentSize,
                BackChannelHttp.FIXED_PARSER_CONFIG_ORIGIN);
    }

    /**
     * Pushes the given authorization parameters and returns the AS-issued {@code request_uri}.
     *
     * @param parEndpoint            the absolute PAR endpoint URL (from discovery); must be TLS unless
     *                               {@link ClientConfiguration#allowInsecureHttp} is set
     * @param authorizationParameters the authorization request parameters to push (for example
     *                                {@code response_type}, {@code redirect_uri}, PKCE, {@code state})
     * @param clientAuthentication    the client authentication strategy to present; must not be
     *                                {@code null}
     * @return the normalized PAR response carrying the {@code request_uri}
     * @throws TransportException if the request fails, the response is not successful, the body cannot
     *         be parsed, or the response omits the {@code request_uri}
     */
    public ParResponse pushAuthorizationRequest(String parEndpoint,
            Map<String, String> authorizationParameters,
            ClientAuthentication clientAuthentication) {
        Objects.requireNonNull(parEndpoint, "parEndpoint must not be null");
        Objects.requireNonNull(authorizationParameters, "authorizationParameters must not be null");
        Objects.requireNonNull(clientAuthentication, "clientAuthentication must not be null");

        HttpHandler handler = backChannel.validatedHandler(parEndpoint, FAILURE_CONTEXT);

        Map<String, String> form = new HashMap<>(authorizationParameters);
        Map<String, String> headers = new HashMap<>();
        clientAuthentication.decorate(form, headers);

        HttpRequest.Builder requestBuilder = handler.requestBuilder()
                .setHeader(CONTENT_TYPE, FORM_URLENCODED)
                .POST(HttpRequest.BodyPublishers.ofString(FormEncoder.encode(form)));
        headers.forEach(requestBuilder::setHeader);

        HttpClient client = backChannel.sharedClient(handler);
        try {
            HttpResponse<String> response = client.send(requestBuilder.build(), backChannel.bodyHandler());
            if (!HttpStatusFamily.isSuccess(response.statusCode())) {
                throw new TransportException(
                        "PAR endpoint returned unexpected HTTP status " + response.statusCode());
            }
            return parse(response.body());
        } catch (IOException e) {
            LOGGER.debug(e, "PAR request failed: %s", e.getMessage());
            throw new TransportException("PAR request failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransportException("PAR request interrupted", e);
        }
    }

    // java:S2589 — body is non-null by every current caller/handler wiring, but the guard is kept
    // (consistent with the equivalent parse() entry guards in UserInfoClient / TokenEndpointClient) as
    // defensive resilience against a future change to the shared bounded body-handler.
    @SuppressWarnings("java:S2589")
    private ParResponse parse(String body) {
        if (body == null || body.isBlank()) {
            throw new TransportException("Empty PAR endpoint response");
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > maxContentSize) {
            throw new TransportException("PAR endpoint response exceeds maximum allowed size of "
                    + maxContentSize + " bytes (" + BackChannelHttp.FIXED_PARSER_CONFIG_ORIGIN + ")");
        }
        try {
            ParResponse parResponse = dslJson.deserialize(ParResponse.class, bytes, bytes.length);
            if (parResponse == null || parResponse.requestUri == null || parResponse.requestUri.isBlank()) {
                throw new TransportException("PAR endpoint response is missing the request_uri");
            }
            return parResponse;
        } catch (IOException e) {
            // The parse-error message can echo an AS-controlled JSON fragment; sanitize it (CWE-117)
            // before it reaches the log appender or the exception message.
            String sanitizedError = LogSanitizer.sanitize(e.getMessage());
            LOGGER.debug("Failed to parse PAR endpoint response: %s", sanitizedError);
            throw new TransportException("Failed to parse PAR endpoint response: " + sanitizedError, e);
        }
    }

}

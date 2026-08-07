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
package de.cuioss.sheriff.token.client.lifecycle;

import de.cuioss.http.client.handler.HttpHandler;
import de.cuioss.http.client.handler.HttpStatusFamily;
import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.internal.BackChannelHttp;
import de.cuioss.sheriff.token.client.internal.FormEncoder;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Revokes a token at the RFC 7009 revocation endpoint over the authenticated back channel
 * ({@code CLIENT-17}).
 * <p>
 * A revocation POST carries the {@code token} and an optional {@code token_type_hint}, authenticated
 * with the configured {@link ClientAuthentication}. Per RFC 7009 §2.2 the AS returns {@code 200} for
 * a successful revocation <em>and</em> for a token it does not recognise, so any {@code 2xx} is
 * treated as success; a non-success status is a transport failure. The transport reuses the
 * commons-blessed cui-http {@link HttpHandler} and adds no transport hardening of its own.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009 - OAuth 2.0 Token Revocation</a>
 */
public class RevocationClient {

    private static final CuiLogger LOGGER = new CuiLogger(RevocationClient.class);

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final String PARAM_TOKEN = "token";
    private static final String PARAM_TOKEN_TYPE_HINT = "token_type_hint";
    private static final String FAILURE_CONTEXT = "Revocation request failed";

    private final BackChannelHttp backChannel;

    /**
     * @param configuration the client configuration carrying the TLS policy; must not be {@code null}
     */
    public RevocationClient(ClientConfiguration configuration) {
        Objects.requireNonNull(configuration, "configuration must not be null");
        this.backChannel = new BackChannelHttp(configuration, ParserConfig.builder().build().getMaxPayloadSize(),
                BackChannelHttp.FIXED_PARSER_CONFIG_ORIGIN);
    }

    /**
     * Revokes a token at the revocation endpoint.
     *
     * @param revocationEndpoint   the absolute revocation endpoint URL (from discovery); must be TLS
     *                             unless {@link ClientConfiguration#allowInsecureHttp} is set
     * @param token                the token to revoke; must not be {@code null} or blank
     * @param tokenTypeHint        the RFC 7009 {@code token_type_hint} (e.g. {@code refresh_token}), or
     *                             {@code null} to omit it
     * @param clientAuthentication the client authentication strategy to present; must not be
     *                             {@code null}
     * @throws TransportException if the request fails or the response is not successful
     */
    public void revoke(String revocationEndpoint, String token, @Nullable String tokenTypeHint,
            ClientAuthentication clientAuthentication) {
        Objects.requireNonNull(revocationEndpoint, "revocationEndpoint must not be null");
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(clientAuthentication, "clientAuthentication must not be null");
        if (token.isBlank()) {
            throw new IllegalArgumentException("token must not be blank");
        }

        HttpHandler handler = backChannel.validatedHandler(revocationEndpoint, FAILURE_CONTEXT);

        Map<String, String> form = new HashMap<>();
        form.put(PARAM_TOKEN, token);
        if (tokenTypeHint != null && !tokenTypeHint.isBlank()) {
            form.put(PARAM_TOKEN_TYPE_HINT, tokenTypeHint);
        }
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
                        "Revocation endpoint returned unexpected HTTP status " + response.statusCode());
            }
        } catch (IOException e) {
            LOGGER.debug(e, "Revocation request failed: %s", e.getMessage());
            throw new TransportException("Revocation request failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransportException("Revocation request interrupted", e);
        }
    }

}

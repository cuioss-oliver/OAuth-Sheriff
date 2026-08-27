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

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.commons.error.InboundErrorNormalizer;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * Validates the {@code authorization_code} redirect callback against its originating
 * {@link FlowContext} and returns the authorization code (RFC 6749 §4.1.2).
 * <p>
 * The handler fails closed on every adversarial condition before the code is ever used:
 * <ul>
 *   <li>an {@code error} callback is rejected;</li>
 *   <li>a missing or non-matching {@code state} is rejected (CSRF defence), compared in constant
 *       time;</li>
 *   <li>a missing authorization {@code code} is rejected.</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2 - Authorization Response</a>
 */
public class CallbackHandler {

    private static final CuiLogger LOGGER = new CuiLogger(CallbackHandler.class);

    /**
     * Validates the callback and returns the authorization code to redeem.
     *
     * @param context    the flow context that issued the request; must not be {@code null}
     * @param parameters the parsed callback parameters; must not be {@code null}
     * @return the validated authorization code
     * @throws ClientProtocolException if the callback signals an error, the {@code state} is missing or
     *                               does not match, or the authorization code is absent
     */
    public String handle(FlowContext context, CallbackParameters parameters) {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(parameters, "parameters must not be null");

        if (parameters.hasError()) {
            // Route both error and error_description through the shared commons normalizer so the
            // inbound and outbound error surfaces render one sanitized contract (COMMONS-11).
            throw InboundErrorNormalizer.normalize(parameters.error(), parameters.errorDescription());
        }
        if (!statesMatch(context.state(), parameters.state())) {
            LOGGER.debug("Rejecting authorization callback: state mismatch");
            throw new ClientProtocolException("authorization callback 'state' does not match the flow context");
        }
        return parameters.getCode()
                .filter(code -> !code.isBlank())
                .orElseThrow(() -> new ClientProtocolException("authorization callback is missing the authorization code"));
    }

    private static boolean statesMatch(String expected, @Nullable String actual) {
        if (actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}

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

import de.cuioss.sheriff.token.client.internal.ClientLogMessages;
import de.cuioss.sheriff.token.client.internal.LogSanitizer;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.tools.logging.CuiLogger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * Validates the RFC 9207 {@code iss} authorization-response parameter against the issuer that
 * initiated the flow — the authorization-server mix-up defence ({@code CLIENT-8}).
 * <p>
 * When a client is registered with more than one authorization server, an attacker AS can trick the
 * client into sending a code (or the PKCE-protected request) to the honest AS's endpoints, or vice
 * versa. RFC 9207 lets the honest AS stamp the authorization response with its own {@code iss}; the
 * client rejects the callback fail-closed whenever the returned {@code iss} does not match the issuer
 * it started the flow with, before the code is ever redeemed. The comparison is constant-time.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9207">RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification</a>
 */
public class IssValidator {

    private static final CuiLogger LOGGER = new CuiLogger(IssValidator.class);

    /**
     * Validates the callback {@code iss} against the initiating issuer.
     * <p>
     * When the callback carries an {@code iss} it MUST equal {@code expectedIssuer}; a mismatch is a
     * mix-up and is rejected. When {@code requireIssuer} is {@code true} the {@code iss} MUST also be
     * present — used when the authorization server is known to advertise
     * {@code authorization_response_iss_parameter_supported}, so an absent {@code iss} is itself a
     * mix-up signal.
     *
     * @param expectedIssuer the issuer the flow was initiated with; must not be {@code null}
     * @param callback       the parsed callback parameters; must not be {@code null}
     * @param requireIssuer  whether a missing {@code iss} must be rejected
     * @throws ClientProtocolException if the {@code iss} does not match, or is absent while required
     */
    public void validate(String expectedIssuer, CallbackParameters callback, boolean requireIssuer) {
        Objects.requireNonNull(expectedIssuer, "expectedIssuer must not be null");
        Objects.requireNonNull(callback, "callback must not be null");

        String actualIssuer = callback.getIssuer().orElse(null);
        if (actualIssuer == null) {
            if (requireIssuer) {
                LOGGER.warn(ClientLogMessages.WARN.ISS_MISMATCH, "<absent>", expectedIssuer);
                throw new ClientProtocolException(
                        "authorization response is missing the required RFC 9207 'iss' parameter");
            }
            return;
        }
        if (!issuersMatch(expectedIssuer, actualIssuer)) {
            // actualIssuer is the attacker-controllable RFC 9207 'iss' callback parameter; sanitize
            // before logging so it cannot forge a log entry (CWE-117).
            LOGGER.warn(ClientLogMessages.WARN.ISS_MISMATCH, LogSanitizer.sanitize(actualIssuer), expectedIssuer);
            throw new ClientProtocolException(
                    "authorization response 'iss' does not match the initiating issuer (mix-up defence)");
        }
    }

    private static boolean issuersMatch(String expected, String actual) {
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}

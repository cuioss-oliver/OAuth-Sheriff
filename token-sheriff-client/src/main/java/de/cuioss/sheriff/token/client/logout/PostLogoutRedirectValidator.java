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
package de.cuioss.sheriff.token.client.logout;

import de.cuioss.sheriff.token.client.internal.ClientLogMessages;
import de.cuioss.sheriff.token.client.internal.LogSanitizer;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.tools.logging.CuiLogger;

import java.util.Objects;
import java.util.Set;

/**
 * Validates a {@code post_logout_redirect_uri} against the set of registered URIs by <em>exact</em>
 * string match ({@code CLIENT-13}, open-redirect defence).
 * <p>
 * RP-initiated logout redirects the user agent to a {@code post_logout_redirect_uri} after the AS
 * ends the session. Matching that URI by prefix or pattern is an open-redirect hazard: an attacker
 * appends or crafts a look-alike that passes a loose check and lands the user on a hostile page. This
 * validator therefore matches only by exact, whole-string equality against a fixed allow-list — no
 * normalization, no prefix, no wildcard. Anything not on the list fails closed ({@code T-LOGOUT}).
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OpenID Connect RP-Initiated Logout 1.0</a>
 */
public class PostLogoutRedirectValidator {

    private static final CuiLogger LOGGER = new CuiLogger(PostLogoutRedirectValidator.class);

    private final Set<String> registeredUris;

    /**
     * @param registeredUris the exact post-logout redirect URIs registered for this client; must not be
     *                       {@code null} or empty, and must contain no {@code null} or blank entries.
     *                       A defensive, immutable copy is taken.
     */
    public PostLogoutRedirectValidator(Set<String> registeredUris) {
        Objects.requireNonNull(registeredUris, "registeredUris must not be null");
        if (registeredUris.isEmpty()) {
            throw new IllegalArgumentException("at least one registered post_logout_redirect_uri is required");
        }
        for (String uri : registeredUris) {
            if (uri == null || uri.isBlank()) {
                throw new IllegalArgumentException("registered post_logout_redirect_uri must not be null or blank");
            }
        }
        this.registeredUris = Set.copyOf(registeredUris);
    }

    /**
     * @param candidate the candidate {@code post_logout_redirect_uri}
     * @return whether the candidate exactly matches a registered URI
     */
    public boolean isRegistered(String candidate) {
        return candidate != null && registeredUris.contains(candidate);
    }

    /**
     * Validates a candidate {@code post_logout_redirect_uri}, returning it when it exactly matches a
     * registered URI and failing closed otherwise.
     *
     * @param candidate the candidate URI; must not be {@code null} or blank
     * @return the candidate URI, unchanged, when it is registered
     * @throws ClientProtocolException if the candidate does not exactly match any registered URI
     */
    public String validate(String candidate) {
        Objects.requireNonNull(candidate, "post_logout_redirect_uri must not be null");
        if (candidate.isBlank()) {
            throw new IllegalArgumentException("post_logout_redirect_uri must not be blank");
        }
        if (!registeredUris.contains(candidate)) {
            // candidate is caller-supplied and unvalidated at this point; sanitize before logging so
            // it cannot forge a log entry (CWE-117).
            LOGGER.warn(ClientLogMessages.WARN.POST_LOGOUT_REDIRECT_MISMATCH, LogSanitizer.sanitize(candidate));
            throw new ClientProtocolException(
                    "post_logout_redirect_uri does not exactly match a registered URI; refusing RP-initiated logout");
        }
        return candidate;
    }
}

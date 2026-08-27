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

import org.jspecify.annotations.Nullable;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The parsed query parameters of an {@code authorization_code} redirect callback (RFC 6749 §4.1.2).
 * <p>
 * A successful callback carries {@code code} and {@code state}; an error callback carries
 * {@code error} (and optionally {@code error_description}). The {@code iss} authorization-server
 * identifier (RFC 9207) is captured when present so a later mix-up defence (deliverable 6) can
 * check it. Parsing never trusts the values — {@link CallbackHandler} validates {@code state} and
 * fails closed on an error before the code is used.
 *
 * @param code             the authorization code, or {@code null} on an error callback
 * @param state            the echoed CSRF state, or {@code null} if absent
 * @param error            the error code, or {@code null} on success
 * @param errorDescription the human-readable error description, or {@code null}
 * @param issuer           the RFC 9207 {@code iss} identifier, or {@code null} if absent
 * @since 1.0
 * @author Oliver Wolff
 */
public record CallbackParameters(@Nullable
        String code, @Nullable
        String state, @Nullable
        String error,
@Nullable
String errorDescription, @Nullable
        String issuer) {

    private static final String PARAM_CODE = "code";
    private static final String PARAM_STATE = "state";
    private static final String PARAM_ERROR = "error";
    private static final String PARAM_ERROR_DESCRIPTION = "error_description";
    private static final String PARAM_ISS = "iss";

    /**
     * Parses the raw {@code application/x-www-form-urlencoded} query string of a redirect callback.
     *
     * @param rawQuery the callback query string (without a leading {@code ?}); must not be
     *                 {@code null}
     * @return the parsed callback parameters
     * @throws IllegalArgumentException if the query repeats a parameter name; a duplicate key is
     *         rejected rather than silently last-wins, so a smuggled second {@code state}/{@code code}
     *         cannot override the first (RFC 9700 §4.7.3 parameter-injection defence-in-depth)
     */
    public static CallbackParameters parse(String rawQuery) {
        Objects.requireNonNull(rawQuery, "rawQuery must not be null");
        Map<String, String> params = new HashMap<>();
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            if (params.put(decode(key), decode(value)) != null) {
                throw new IllegalArgumentException(
                        "duplicate callback parameter rejected (RFC 9700 §4.7.3 parameter injection)");
            }
        }
        return of(params);
    }

    /**
     * Builds callback parameters from an already-decoded parameter map.
     * <p>
     * <strong>Duplicate-parameter defense (L8):</strong> unlike {@link #parse(String)}, this factory
     * cannot re-apply the RFC 9700 §4.7.3 duplicate-key rejection — a {@link Map} key is unique by
     * construction, so any duplicate {@code state}/{@code code} in the original wire representation has
     * already been collapsed (silently last-wins) before it reaches this method. Callers that build the
     * map from a raw callback query are therefore responsible for rejecting duplicate parameter names
     * themselves; {@link #parse(String)} does this and is the safe entry point for untrusted wire input.
     * Use {@code of(Map)} only when the map is known to have been assembled with that defense already
     * applied.
     *
     * @param params the decoded callback parameters; must not be {@code null}
     * @return the callback parameters
     */
    public static CallbackParameters of(Map<String, String> params) {
        Objects.requireNonNull(params, "params must not be null");
        return new CallbackParameters(params.get(PARAM_CODE), params.get(PARAM_STATE), params.get(PARAM_ERROR),
                params.get(PARAM_ERROR_DESCRIPTION), params.get(PARAM_ISS));
    }

    /**
     * @return whether the callback signals an authorization error
     */
    public boolean hasError() {
        return error != null && !error.isBlank();
    }

    /**
     * @return the authorization code, if present
     */
    public Optional<String> getCode() {
        return Optional.ofNullable(code);
    }

    /**
     * @return the RFC 9207 issuer identifier, if present
     */
    public Optional<String> getIssuer() {
        return Optional.ofNullable(issuer);
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    /**
     * Renders the parameters without exposing the secret-carrying fields: the authorization
     * {@code code} and the CSRF {@code state} are redacted so a stray {@code toString()} — a log
     * statement, an exception message, or a debugger dump — never leaks a usable authorization code or
     * the anti-CSRF token (H8). The non-secret error and issuer fields are shown for diagnostics.
     *
     * @return a redacted string representation carrying no authorization code or state
     */
    @Override
    public String toString() {
        return "CallbackParameters[code=" + redact(code) + ", state=" + redact(state)
                + ", error=" + error + ", errorDescription=" + errorDescription
                + ", issuer=" + issuer + "]";
    }

    private static String redact(@Nullable String secret) {
        return secret == null ? "null" : "<redacted>";
    }
}

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

import de.cuioss.sheriff.token.client.internal.LogSanitizer;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Parses an RFC 9470 step-up authentication challenge from a resource server's
 * {@code WWW-Authenticate} response header.
 * <p>
 * When a resource server rejects a request because the authentication is insufficient it responds
 * with {@code WWW-Authenticate: Bearer error="insufficient_user_authentication"} and — per RFC 9470
 * — the {@code acr_values} and/or {@code max_age} it requires. This parser extracts that challenge
 * so {@link StepUpHandler} can drive a fresh, stronger authorization request. Any header that is not
 * an {@code insufficient_user_authentication} Bearer challenge yields {@link Optional#empty()}.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9470">RFC 9470 - OAuth 2.0 Step Up Authentication Challenge</a>
 */
public class StepUpChallengeParser {

    /** The RFC 9470 error code that signals a step-up is required. */
    public static final String INSUFFICIENT_USER_AUTHENTICATION = "insufficient_user_authentication";

    private static final CuiLogger LOGGER = new CuiLogger(StepUpChallengeParser.class);
    private static final String BEARER_PREFIX = "bearer ";

    /**
     * Parses the {@code WWW-Authenticate} header value into a step-up challenge.
     *
     * @param wwwAuthenticate the raw header value, or {@code null}
     * @return the parsed challenge, or {@link Optional#empty()} if the header is absent or is not an
     *         {@code insufficient_user_authentication} Bearer challenge
     */
    public Optional<StepUpChallenge> parse(@Nullable String wwwAuthenticate) {
        if (wwwAuthenticate == null || wwwAuthenticate.isBlank()) {
            return Optional.empty();
        }
        String trimmed = wwwAuthenticate.strip();
        if (!trimmed.toLowerCase(Locale.ROOT).startsWith(BEARER_PREFIX)) {
            return Optional.empty();
        }
        Optional<Map<String, String>> parsed = parseParams(trimmed.substring(BEARER_PREFIX.length()));
        if (parsed.isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> params = parsed.get();
        if (!INSUFFICIENT_USER_AUTHENTICATION.equals(params.get("error"))) {
            return Optional.empty();
        }
        // Blank-normalise acr_values exactly as parseMaxAge already does for max_age: a whitespace-only
        // value constrains nothing, so treating it as present would make the challenge actionable while
        // leaving StepUpResultVerifier with no constraint to check — verify() would then return normally
        // having verified nothing, and a caller reading that as proof of elevation would grant a
        // privileged operation on an unelevated authentication. Fail closed instead (CLIENT-12 / H1).
        String acrValues = blankToNull(params.get("acr_values"));
        Integer maxAge = parseMaxAge(params.get("max_age"));
        if (acrValues == null && maxAge == null) {
            LOGGER.debug("Ignoring step-up challenge without acr_values or max_age");
            return Optional.empty();
        }
        return Optional.of(new StepUpChallenge(acrValues, maxAge));
    }

    /**
     * Parses the RFC 9110 {@code auth-param} list of a Bearer challenge into a case-insensitive map.
     * The list is split on commas that sit <em>outside</em> a quoted-string, so a quoted value may
     * itself contain commas and backslash-escaped quotes without being torn apart. A duplicate
     * {@code auth-param} name is malformed per RFC 9110 §11.2, so the whole challenge is rejected
     * (fail-closed) rather than silently taking a last-wins value an attacker could inject.
     *
     * @param paramList the comma-separated {@code auth-param} list following the {@code Bearer} scheme
     * @return the parsed parameters, or {@link Optional#empty()} if a duplicate parameter is present
     */
    private static Optional<Map<String, String>> parseParams(String paramList) {
        Map<String, String> params = new HashMap<>();
        for (String segment : splitTopLevel(paramList)) {
            String pair = segment.strip();
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = pair.substring(0, eq).strip().toLowerCase(Locale.ROOT);
            String value = unquote(pair.substring(eq + 1).strip());
            if (params.putIfAbsent(key, value) != null) {
                LOGGER.debug("Ignoring step-up challenge with duplicate auth-param '%s'",
                        LogSanitizer.sanitize(key));
                return Optional.empty();
            }
        }
        return Optional.of(params);
    }

    /**
     * Splits {@code input} on top-level commas — commas that are not inside a double-quoted string.
     * Backslash escapes are honoured inside quotes so {@code \"} does not prematurely close the
     * quoted-string and a comma inside the quotes stays with its value.
     */
    private static List<String> splitTopLevel(String input) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        boolean escaped = false;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (escaped) {
                current.append(c);
                escaped = false;
            } else if (c == '\\' && inQuotes) {
                current.append(c);
                escaped = true;
            } else if (c == '"') {
                inQuotes = !inQuotes;
                current.append(c);
            } else if (c == ',' && !inQuotes) {
                parts.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        parts.add(current.toString());
        return parts;
    }

    private static @Nullable String blankToNull(@Nullable String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static @Nullable Integer parseMaxAge(@Nullable String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Integer.valueOf(value.strip());
        } catch (NumberFormatException e) {
            LOGGER.debug("Ignoring non-numeric step-up max_age '%s'", LogSanitizer.sanitize(value));
            return null;
        }
    }

    /**
     * Strips the surrounding double-quotes from a {@code quoted-string} value and unescapes its
     * backslash escapes ({@code \"} → {@code "}, {@code \\} → {@code \}), per RFC 9110 §5.6.4.
     * An unquoted {@code token} value is returned unchanged.
     */
    private static String unquote(String value) {
        if (value.length() < 2 || value.charAt(0) != '"' || value.charAt(value.length() - 1) != '"') {
            return value;
        }
        String inner = value.substring(1, value.length() - 1);
        StringBuilder sb = new StringBuilder(inner.length());
        boolean escaped = false;
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (escaped) {
                sb.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * A parsed RFC 9470 step-up challenge: the required {@code acr_values} and/or {@code max_age}.
     *
     * @param acrValues the requested authentication context class values, or {@code null}
     * @param maxAge    the maximum authentication age in seconds, or {@code null}
     */
    public record StepUpChallenge(@Nullable
    String acrValues, @Nullable
    Integer maxAge) {

        /**
         * @return the requested {@code acr_values}, if the challenge constrained them
         */
        public Optional<String> getAcrValues() {
            return Optional.ofNullable(acrValues);
        }

        /**
         * @return the maximum authentication age in seconds, if the challenge constrained it
         */
        public Optional<Integer> getMaxAge() {
            return Optional.ofNullable(maxAge);
        }
    }
}

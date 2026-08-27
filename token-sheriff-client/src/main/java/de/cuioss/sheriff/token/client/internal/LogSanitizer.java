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
package de.cuioss.sheriff.token.client.internal;

import org.jspecify.annotations.Nullable;

/**
 * Sanitizes an externally-sourced value before it is interpolated into a {@code %s} log template,
 * defending against log injection / log forging (CWE-117).
 * <p>
 * Several call sites log a value that crossed a trust boundary before it was rejected — the RFC 9207
 * {@code iss} authorization-response parameter (fully attacker-controlled via the browser callback),
 * a caller-supplied {@code post_logout_redirect_uri}, or the {@code issuer} of an authorization
 * server's discovery document. Parameterized logging alone does not neutralize embedded {@code CR} /
 * {@code LF} on a plain-text appender — the substituted value is still written verbatim, so an
 * attacker who embeds {@code %0d%0a} can forge a new, seemingly legitimate log entry. This sanitizer
 * escapes (rather than drops) {@code CR}, {@code LF}, tab, and the remaining ASCII control characters,
 * preserving the value's investigative content while making it impossible to inject a line break.
 * <p>
 * The value is also truncated to {@value #MAX_LENGTH} characters before escaping, so an attacker
 * cannot flood the log with an arbitrarily long value (L18). When truncation occurs the marker
 * {@value #TRUNCATION_MARKER} is appended so the elision is visible in the log.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://owasp.org/www-community/attacks/Log_Injection">OWASP Log Injection</a>
 */
public final class LogSanitizer {

    /** Maximum number of source characters retained; longer values are truncated to bound flooding. */
    private static final int MAX_LENGTH = 256;

    /** Appended when a value is truncated, so the elision is visible in the log. */
    private static final String TRUNCATION_MARKER = "...[truncated]";

    private LogSanitizer() {
        // utility class — never instantiated
    }

    /**
     * Escapes {@code CR}, {@code LF} and every other ASCII control character in {@code value} so it
     * cannot forge a new log line when substituted into a log template, and truncates the value to
     * {@value #MAX_LENGTH} characters to bound log flooding.
     *
     * @param value the untrusted value to sanitize; may be {@code null}
     * @return the sanitized (and, when over-long, truncated) value, or {@code null} when {@code value}
     *         is {@code null}
     */
    public static @Nullable String sanitize(@Nullable String value) {
        if (value == null) {
            return null;
        }
        boolean truncated = value.length() > MAX_LENGTH;
        String bounded = truncated ? value.substring(0, MAX_LENGTH) : value;
        StringBuilder sanitized = new StringBuilder(bounded.length());
        for (int i = 0; i < bounded.length(); i++) {
            char c = bounded.charAt(i);
            switch (c) {
                case '\r' -> sanitized.append("\\r");
                case '\n' -> sanitized.append("\\n");
                case '\t' -> sanitized.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x7F) {
                        sanitized.append(String.format("\\u%04x", (int) c));
                    } else {
                        sanitized.append(c);
                    }
                }
            }
        }
        if (truncated) {
            sanitized.append(TRUNCATION_MARKER);
        }
        return sanitized.toString();
    }
}

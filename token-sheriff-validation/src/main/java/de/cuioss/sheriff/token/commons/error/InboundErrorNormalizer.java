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
package de.cuioss.sheriff.token.commons.error;

import org.jspecify.annotations.Nullable;

import java.util.Set;

/**
 * Normalizes an inbound OAuth 2.0 error response ({@code error} plus optional
 * {@code error_description}, RFC 6749 §4.1.2.1 / §5.2) into the typed {@link ClientProtocolException}
 * the error model renders — <em>one contract, both directions</em> (COMMONS-11).
 * <p>
 * The raw upstream {@code error} and {@code error_description} are authorization-server-controlled and
 * are never surfaced verbatim: both are neutralized for log/response injection (CWE-117) before they
 * reach the caller-safe exception message. Because the {@code commons} base layer must not depend on
 * the client engine (the ArchUnit boundary), this normalizer carries its own minimal CR/LF /
 * control-character neutralization rather than the client-internal sanitizer.
 * <p>
 * The utility is stateless and has no configuration surface.
 *
 * @since 1.0
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</a>
 */
public final class InboundErrorNormalizer {

    /** Maximum number of source characters retained per field; longer values are truncated. */
    private static final int MAX_LENGTH = 256;

    /** Appended when a field is truncated, so the elision is visible. */
    private static final String TRUNCATION_MARKER = "...[truncated]";

    /**
     * The registered OAuth 2.0 error codes across the authorization endpoint (RFC 6749 §4.1.2.1) and
     * the token endpoint (RFC 6749 §5.2). A code outside this set is reported as unrecognized rather
     * than trusted as a known protocol condition.
     */
    private static final Set<String> REGISTERED_ERROR_CODES = Set.of(
            "invalid_request",
            "invalid_client",
            "invalid_grant",
            "unauthorized_client",
            "unsupported_grant_type",
            "unsupported_response_type",
            "access_denied",
            "invalid_scope",
            "server_error",
            "temporarily_unavailable");

    private InboundErrorNormalizer() {
        // utility class — never instantiated
    }

    /**
     * Normalizes a raw inbound error response into a caller-safe {@link ClientProtocolException}.
     *
     * @param error            the raw {@code error} code from the authorization server, or {@code null}
     * @param errorDescription the raw {@code error_description}, or {@code null}
     * @return a {@link ClientProtocolException} whose message names the (recognized-or-unrecognized)
     *         error code and, when present, the sanitized description — never the raw upstream content
     */
    public static ClientProtocolException normalize(@Nullable String error, @Nullable String errorDescription) {
        String safeError = sanitize(error);
        String message;
        if (safeError == null || safeError.isBlank()) {
            message = "authorization server returned an error callback without an error code";
        } else if (isRegistered(error)) {
            message = "authorization server returned an error callback: " + safeError;
        } else {
            message = "authorization server returned an unrecognized error callback: " + safeError;
        }
        String safeDescription = sanitize(errorDescription);
        if (safeDescription != null && !safeDescription.isBlank()) {
            message = message + " (" + safeDescription + ")";
        }
        return new ClientProtocolException(message);
    }

    private static boolean isRegistered(@Nullable String error) {
        return error != null && REGISTERED_ERROR_CODES.contains(error);
    }

    /**
     * Escapes {@code CR}, {@code LF}, tab and every other ASCII control character so an
     * authorization-server-controlled value cannot forge a new log/response line, and truncates the
     * value to {@value #MAX_LENGTH} characters to bound flooding.
     *
     * @param value the untrusted value to sanitize; may be {@code null}
     * @return the sanitized value, or {@code null} when {@code value} is {@code null}
     */
    private static @Nullable String sanitize(@Nullable String value) {
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

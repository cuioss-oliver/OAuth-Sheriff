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

import java.io.Serial;

/**
 * Root of the typed exception hierarchy that Token-Sheriff library code throws.
 * <p>
 * Library code (the {@code commons} and {@code validation} packages, and the future client
 * engine — pure Java) signals failure by throwing a subtype of this exception. Library code
 * MUST NOT produce HTTP problem documents; mapping to {@code application/problem+json} per
 * <a href="https://www.rfc-editor.org/rfc/rfc9457">RFC 9457</a> is the responsibility of each
 * HTTP edge (see {@code doc/commons/specification/error-model.adoc}).
 * <p>
 * Known branches:
 * <ul>
 *   <li>{@link TransportException} — outbound IdP transport failures (TLS rejected, SSRF
 *       blocked, timeout, unreachable, oversized response).</li>
 *   <li>{@code de.cuioss.sheriff.token.validation.exception.TokenValidationException} —
 *       token-validation failures, categorized by
 *       {@code de.cuioss.sheriff.token.commons.events.EventCategory}.</li>
 * </ul>
 * <p>
 * The message carried by any subtype is expected to be caller-safe; edges must still avoid
 * leaking internal detail (RFC 9457 rendering strips stack traces and internal identifiers).
 *
 * @since 1.0
 */
public abstract class TokenSheriffException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * @param message the caller-safe detail message
     */
    protected TokenSheriffException(String message) {
        super(message);
    }

    /**
     * @param message the caller-safe detail message
     * @param cause the underlying cause
     */
    protected TokenSheriffException(String message, Throwable cause) {
        super(message, cause);
    }
}

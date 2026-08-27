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
 * Signals a client-side OAuth 2.0 / OIDC protocol rejection: an authorization-server
 * error callback, a {@code state}/{@code nonce} mismatch, a missing mandatory response
 * parameter, an unsupported client-authentication method, or any other adversarial or
 * malformed condition the client engine fails closed on before a token is ever trusted.
 * <p>
 * These rejections are protocol-level, not transport-level: the outbound request itself
 * succeeded, but the response (or the caller-supplied flow input) violated the OAuth/OIDC
 * contract. At an HTTP edge this maps to a 4xx {@code application/problem+json} document per
 * <a href="https://www.rfc-editor.org/rfc/rfc9457">RFC 9457</a> (typically 400/401), distinct
 * from {@link TransportException} (5xx) and from token-validation failures. Throwing this typed
 * exception — rather than a bare {@link IllegalStateException}/{@link IllegalArgumentException} —
 * lets the RESTEasy edge map the rejection to the correct problem-document status instead of a
 * generic 500 (see {@code doc/commons/specification/error-model.adoc}).
 * <p>
 * The message MUST be caller-safe; edges still strip stack traces and internal identifiers when
 * rendering RFC 9457.
 *
 * @since 1.0
 */
public class ClientProtocolException extends TokenSheriffException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * @param message the caller-safe detail message
     */
    public ClientProtocolException(String message) {
        super(message);
    }

    /**
     * @param message the caller-safe detail message
     * @param cause the underlying cause
     */
    public ClientProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}

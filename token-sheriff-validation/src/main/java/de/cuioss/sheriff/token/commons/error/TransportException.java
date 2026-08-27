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
 * Signals a failure of outbound IdP transport in the {@code commons.transport} layer.
 * <p>
 * The branches this layer currently raises are:
 * <ul>
 *   <li>an SSRF-blocked egress target — the URL has no resolvable host, or it resolves to a
 *       loopback/link-local/site-local/any-local/multicast/unique-local address (see
 *       {@code EgressPolicy})</li>
 *   <li>an oversized or malformed IdP response — the well-known/JWKS payload exceeds the configured
 *       size ceiling or trips a parser security limit (see {@code WellKnownConfigurationConverter})</li>
 * </ul>
 * <p>
 * At an HTTP edge this maps to a 5xx {@code application/problem+json} document (typically
 * 502/503), distinct from token-validation failures which map to 401 (see
 * {@code doc/commons/specification/error-model.adoc}).
 *
 * @since 1.0
 */
public class TransportException extends TokenSheriffException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * @param message the caller-safe detail message
     */
    public TransportException(String message) {
        super(message);
    }

    /**
     * @param message the caller-safe detail message
     * @param cause the underlying cause
     */
    public TransportException(String message, Throwable cause) {
        super(message, cause);
    }
}

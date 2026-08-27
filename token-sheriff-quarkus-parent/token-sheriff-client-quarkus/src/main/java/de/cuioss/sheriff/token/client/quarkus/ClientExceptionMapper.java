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
package de.cuioss.sheriff.token.client.quarkus;

import de.cuioss.sheriff.token.commons.error.TransportException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Maps the client engine's outbound {@link TransportException} to {@code application/problem+json}
 * per <a href="https://www.rfc-editor.org/rfc/rfc9457">RFC 9457</a> at the Quarkus HTTP edge
 * ({@code CLIENT-20}, {@code COMMONS-10}).
 * <p>
 * The pure-Java client engine ({@code token-sheriff-client}) throws typed exceptions only and renders
 * no problem document itself ({@code CLIENT-21}); this edge mapper is the client-quarkus realization
 * of the error-model split. A failed back-channel call to the identity provider — TLS rejected, SSRF
 * blocked, timeout, unreachable, or an oversized/malformed response — surfaces as a
 * {@code 502 Bad Gateway} problem document built from controlled constants: never the underlying
 * exception message, stack trace, or any internal identifier ({@code T-LEAK}).
 * <p>
 * This mapper is intentionally scoped to {@link TransportException} — more specific than the root
 * {@code TokenSheriffException} mapper the {@code token-sheriff-validation-quarkus} extension already
 * contributes — so JAX-RS resolves it deterministically for the client's outbound-transport failures
 * while the inherited mapper continues to render the remaining branches (for example token-validation
 * failures).
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@Provider
public class ClientExceptionMapper implements ExceptionMapper<TransportException> {

    /** The RFC 9457 media type. */
    public static final String PROBLEM_JSON = "application/problem+json";

    /** Base URI under which problem {@code type} values are published. */
    static final String TYPE_BASE = "https://cuioss.github.io/TokenSheriff/problems/";

    private static final String SLUG = "idp-communication";
    private static final String TITLE = "Upstream identity provider error";
    private static final String DETAIL =
            "The identity provider could not be reached or returned an invalid response.";

    @Override
    public Response toResponse(TransportException exception) {
        return Response.status(status())
                .type(PROBLEM_JSON)
                .entity(problemJson())
                .build();
    }

    /**
     * @return the HTTP status for an outbound-transport failure ({@code 502 Bad Gateway})
     */
    static int status() {
        return Response.Status.BAD_GATEWAY.getStatusCode();
    }

    /**
     * Builds the RFC 9457 problem document from controlled, constant values. No part of the incoming
     * exception is interpolated, so the document cannot leak internal detail by construction.
     * Package-visible so the rendering and no-leak invariants can be unit-tested without bootstrapping
     * a JAX-RS runtime.
     *
     * @return the RFC 9457 {@code application/problem+json} body
     */
    static String problemJson() {
        return "{\"type\":\"" + TYPE_BASE + SLUG + "\","
                + "\"title\":\"" + TITLE + "\","
                + "\"status\":" + status() + ","
                + "\"detail\":\"" + DETAIL + "\"}";
    }
}

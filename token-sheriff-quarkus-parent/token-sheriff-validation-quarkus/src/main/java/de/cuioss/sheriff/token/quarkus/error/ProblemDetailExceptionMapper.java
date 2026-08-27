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
package de.cuioss.sheriff.token.quarkus.error;

import de.cuioss.sheriff.token.commons.error.TokenSheriffException;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Maps the Token-Sheriff typed exception hierarchy ({@link TokenSheriffException} and its
 * subtypes) to {@code application/problem+json} per
 * <a href="https://www.rfc-editor.org/rfc/rfc9457">RFC 9457</a> at the Quarkus HTTP edge.
 * <p>
 * This is the edge realization of the error-model split (see
 * {@code doc/commons/specification/error-model.adoc}): library code throws typed exceptions;
 * the edge renders them. The rendered problem document carries only a stable {@code type},
 * a generic {@code title}/{@code detail} and the {@code status} — never the underlying
 * exception message, stack trace or any internal identifier (COMMONS-12, threat T-LEAK).
 *
 * @since 1.0
 */
@Provider
public class ProblemDetailExceptionMapper implements ExceptionMapper<TokenSheriffException> {

    /** The RFC 9457 media type. */
    public static final String PROBLEM_JSON = "application/problem+json";

    /** Base URI under which problem {@code type} values are published. */
    static final String TYPE_BASE = "https://cuioss.github.io/TokenSheriff/problems/";

    @Override
    public Response toResponse(TokenSheriffException exception) {
        final int status;
        final String slug;
        final String title;
        final String detail;
        if (exception instanceof TransportException) {
            status = Response.Status.BAD_GATEWAY.getStatusCode();
            slug = "idp-communication";
            title = "Upstream identity provider error";
            detail = "The identity provider could not be reached or returned an invalid response.";
        } else if (exception instanceof TokenValidationException) {
            status = Response.Status.UNAUTHORIZED.getStatusCode();
            slug = "token-invalid";
            title = "Token validation failed";
            detail = "The presented token could not be validated.";
        } else {
            status = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
            slug = "internal-error";
            title = "Request could not be processed";
            detail = "The request could not be processed.";
        }
        return Response.status(status)
                .type(PROBLEM_JSON)
                .entity(problemJson(TYPE_BASE + slug, title, status, detail))
                .build();
    }

    /**
     * Builds a minimal RFC 9457 problem document from controlled, constant values (no user
     * input is interpolated, so the result is safe by construction).
     */
    private static String problemJson(String type, String title, int status, String detail) {
        return "{\"type\":\"" + type + "\","
                + "\"title\":\"" + title + "\","
                + "\"status\":" + status + ","
                + "\"detail\":\"" + detail + "\"}";
    }
}

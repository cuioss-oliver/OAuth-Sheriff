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
package de.cuioss.sheriff.token.quarkus.producer;

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.experimental.UtilityClass;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Factory class for creating HTTP responses based on bearer token validation results.
 * <p>
 * This factory follows OAuth 2.0 Bearer Token specification (RFC 6750) and OAuth Step-Up
 * Authentication Challenge (draft-ietf-oauth-step-up-authn-challenge-17) best practices
 * to create appropriate HTTP responses for different validation scenarios.
 * <p>
 * HTTP Status Code mappings:
 * <ul>
 *   <li>FULLY_VERIFIED: 200 (OK) - Should not be called for successful validation</li>
 *   <li>NO_TOKEN_GIVEN: 401 (Unauthorized) - Missing Bearer token</li>
 *   <li>PARSING_ERROR: 401 (Unauthorized) - Invalid or expired token</li>
 *   <li>CONSTRAINT_VIOLATION: 401 (Unauthorized) for required scopes, 403 (Forbidden) for required roles/groups</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@UtilityClass
public class BearerTokenResponseFactory {

    static final String TOKEN_NOT_PRESENT = "Bearer token validation failed or token not present";

    // HTTP Header Constants
    private static final String HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String HEADER_CACHE_CONTROL = "Cache-Control";
    private static final String HEADER_PRAGMA = "Pragma";

    // Header Values
    private static final String CACHE_CONTROL_VALUE = "no-store, no-cache, must-revalidate";
    private static final String PRAGMA_VALUE = "no-cache";

    // OAuth Constants
    private static final String BEARER_REALM = "Bearer realm=\"protected-resource\"";
    private static final String BEARER_SCHEME = "Bearer";
    private static final String REALM_PARAMETER = "realm=\"protected-resource\"";

    // OAuth Error Codes
    private static final String ERROR_INVALID_TOKEN = "invalid_token";
    private static final String ERROR_INSUFFICIENT_SCOPE = "insufficient_scope";
    private static final String ERROR_INSUFFICIENT_PRIVILEGES = "insufficient_privileges";

    // OAuth Parameters
    private static final String PARAM_ERROR = "error";
    private static final String PARAM_ERROR_DESCRIPTION = "error_description";
    private static final String PARAM_SCOPE = "scope";
    private static final String PARAM_REQUIRED_ROLES = "required_roles";
    private static final String PARAM_REQUIRED_GROUPS = "required_groups";

    // Error Messages
    private static final String ERROR_MSG_INVALID_TOKEN = "The access token is invalid";
    private static final String ERROR_MSG_HIGHER_PRIVILEGES = "The request requires higher privileges than provided by the access token";


    /**
     * Creates an appropriate HTTP response for the given bearer token validation result.
     *
     * @param result The bearer token validation result containing status and context information
     * @return Response object with appropriate HTTP status code, headers, and body
     */
    static Response createResponse(BearerTokenResult result) {
        return switch (result.getStatus()) {
            case FULLY_VERIFIED -> throw new IllegalStateException(
                    "FULLY_VERIFIED is handled by BearerTokenResult directly, not the error response factory");
            case NO_TOKEN_GIVEN -> createNoTokenResponse();
            case PARSING_ERROR -> createParsingErrorResponse();
            case CONSTRAINT_VIOLATION -> createConstraintViolationResponse(result);
            case INVALID_REQUEST -> createInvalidRequestResponse(result);
        };
    }

    /**
     * Creates an unauthorized response when no token is provided.
     */
    private static Response createNoTokenResponse() {
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON)
                .header(HEADER_WWW_AUTHENTICATE, BEARER_REALM)
                .header(HEADER_CACHE_CONTROL, CACHE_CONTROL_VALUE)
                .header(HEADER_PRAGMA, PRAGMA_VALUE)
                .entity(createErrorEntity(TOKEN_NOT_PRESENT))
                .build();
    }

    /**
     * Creates an unauthorized response for token parsing errors.
     */
    private static Response createParsingErrorResponse() {
        String wwwAuthenticate = buildInvalidTokenHeader();
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON)
                .header(HEADER_WWW_AUTHENTICATE, wwwAuthenticate)
                .header(HEADER_CACHE_CONTROL, CACHE_CONTROL_VALUE)
                .header(HEADER_PRAGMA, PRAGMA_VALUE)
                .entity(createErrorEntity(TOKEN_NOT_PRESENT))
                .build();
    }

    /**
     * Creates a bad request response for invalid bearer token format (RFC 6750 violation).
     * <p>
     * According to RFC 6750, malformed bearer token requests (e.g., empty token)
     * should return 400 Bad Request with error code "invalid_request".
     */
    private static Response createInvalidRequestResponse(BearerTokenResult result) {
        String wwwAuthenticate = buildInvalidRequestHeader(result.getErrorMessage().orElse("Invalid bearer token format"));
        return Response.status(Response.Status.BAD_REQUEST)
                .type(MediaType.APPLICATION_JSON)
                .header(HEADER_WWW_AUTHENTICATE, wwwAuthenticate)
                .header(HEADER_CACHE_CONTROL, CACHE_CONTROL_VALUE)
                .header(HEADER_PRAGMA, PRAGMA_VALUE)
                .entity(createErrorEntity(result.getErrorMessage().orElse("Invalid bearer token format")))
                .build();
    }

    /**
     * Creates a response for constraint violations (missing scopes, roles, or groups).
     * <p>
     * Design Decision: Scope violations (401) take priority over role/group violations (403).
     * Per RFC 9470 (Step-Up Authentication) and RFC 6750 Section 3.1, an {@code insufficient_scope}
     * 401 is an actionable challenge — the client can re-authenticate with higher scope/ACR.
     * Role/group violations are terminal (no re-authentication will fix them) and result in 403.
     * When both are present, returning 401 first gives the client a chance to step up; if the
     * subsequent request satisfies scopes but still lacks roles/groups, the server then returns 403.
     * The {@code WWW-Authenticate} header schema only accommodates scope/ACR info per the RFCs.
     * </p>
     */
    private static Response createConstraintViolationResponse(BearerTokenResult result) {
        // Scope violation → 401 (actionable step-up per RFC 9470), role/group → 403 (terminal)
        // Use getMissingScopes() for the WWW-Authenticate header — RFC 6750 requires the missing scopes
        boolean hasScopeViolation = !result.getMissingScopes().isEmpty();

        if (hasScopeViolation) {
            // OAuth Step-Up Authentication Challenge for insufficient scope (RFC 9470)
            // RFC 6750 Section 3.1: scope parameter contains the full scope necessary for access
            String wwwAuthenticate = buildInsufficientScopeHeader(result.getRequiredScopes());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .type(MediaType.APPLICATION_JSON)
                    .header(HEADER_WWW_AUTHENTICATE, wwwAuthenticate)
                    .header(HEADER_CACHE_CONTROL, CACHE_CONTROL_VALUE)
                    .header(HEADER_PRAGMA, PRAGMA_VALUE)
                    .entity(createErrorEntity(TOKEN_NOT_PRESENT))
                    .build();
        } else {
            // Role/group violation - 403 Forbidden with OAuth-style error structure
            String wwwAuthenticate = buildInsufficientPrivilegesHeader(result.getMissingRoles(), result.getMissingGroups());
            return Response.status(Response.Status.FORBIDDEN)
                    .type(MediaType.APPLICATION_JSON)
                    .header(HEADER_WWW_AUTHENTICATE, wwwAuthenticate)
                    .header(HEADER_CACHE_CONTROL, CACHE_CONTROL_VALUE)
                    .header(HEADER_PRAGMA, PRAGMA_VALUE)
                    .entity(createErrorEntity(TOKEN_NOT_PRESENT))
                    .build();
        }
    }

    /**
     * Builds a WWW-Authenticate header for invalid token errors.
     *
     * @return Formatted WWW-Authenticate header value for invalid tokens
     */
    private static String buildInvalidTokenHeader() {
        return "%s %s, %s=\"%s\", %s=\"%s\"".formatted(
                BEARER_SCHEME, REALM_PARAMETER, PARAM_ERROR, ERROR_INVALID_TOKEN,
                PARAM_ERROR_DESCRIPTION, ERROR_MSG_INVALID_TOKEN);
    }

    /**
     * Builds a WWW-Authenticate header for invalid request errors (RFC 6750).
     * Used when the bearer token format is invalid (e.g., empty token).
     *
     * @param errorDescription The error description
     * @return Formatted WWW-Authenticate header value for invalid requests
     */
    private static String buildInvalidRequestHeader(String errorDescription) {
        return "%s %s, %s=\"%s\", %s=\"%s\"".formatted(
                BEARER_SCHEME, REALM_PARAMETER, PARAM_ERROR, "invalid_request",
                PARAM_ERROR_DESCRIPTION, errorDescription);
    }

    /**
     * Builds a WWW-Authenticate header for insufficient scope errors.
     * Follows OAuth Step-Up Authentication Challenge specification.
     *
     * @param requiredScopes The collection of required scopes
     * @return Formatted WWW-Authenticate header value for insufficient scope
     */
    private static String buildInsufficientScopeHeader(Collection<String> requiredScopes) {
        StringBuilder sb = buildBaseAuthenticateHeader(ERROR_INSUFFICIENT_SCOPE);

        if (!requiredScopes.isEmpty()) {
            String scopeValue = joinAndEscape(requiredScopes);
            sb.append(", ").append(PARAM_SCOPE).append("=\"").append(scopeValue).append("\"");
        }

        return sb.toString();
    }

    /**
     * Builds a WWW-Authenticate header for insufficient privileges errors.
     * Uses OAuth-style error structure adapted for role/group privileges.
     *
     * @param requiredRoles The collection of required roles
     * @param requiredGroups The collection of required groups
     * @return Formatted WWW-Authenticate header value for insufficient privileges
     */
    private static String buildInsufficientPrivilegesHeader(Collection<String> requiredRoles, Collection<String> requiredGroups) {
        StringBuilder sb = buildBaseAuthenticateHeader(ERROR_INSUFFICIENT_PRIVILEGES);

        // Add missing roles and groups as custom parameters
        if (!requiredRoles.isEmpty()) {
            String rolesValue = joinAndEscape(requiredRoles);
            sb.append(", ").append(PARAM_REQUIRED_ROLES).append("=\"").append(rolesValue).append("\"");
        }

        if (!requiredGroups.isEmpty()) {
            String groupsValue = joinAndEscape(requiredGroups);
            sb.append(", ").append(PARAM_REQUIRED_GROUPS).append("=\"").append(groupsValue).append("\"");
        }

        return sb.toString();
    }

    /**
     * Builds the base WWW-Authenticate header structure with bearer scheme, realm, and error.
     *
     * @param errorCode The OAuth error code
     * @return StringBuilder with base header structure
     */
    private static StringBuilder buildBaseAuthenticateHeader(String errorCode) {
        StringBuilder sb = new StringBuilder();
        sb.append(BEARER_SCHEME).append(" ").append(REALM_PARAMETER);
        sb.append(", ").append(PARAM_ERROR).append("=\"").append(errorCode).append("\"");
        sb.append(", ").append(PARAM_ERROR_DESCRIPTION).append("=\"").append(ERROR_MSG_HIGHER_PRIVILEGES).append("\"");
        return sb;
    }

    /**
     * Joins a collection of strings with spaces after escaping quotes.
     *
     * @param values The collection of strings to join
     * @return Space-separated string with escaped quotes
     */
    private static String joinAndEscape(Collection<String> values) {
        return values.stream()
                .map(BearerTokenResponseFactory::escapeQuotes)
                .collect(Collectors.joining(" "));
    }

    /**
     * Escapes double quotes in strings for use in HTTP header values.
     *
     * @param input The input string
     * @return String with escaped quotes
     */
    private static String escapeQuotes(String input) {
        return input == null ? "" : input.replace("\"", "\\\"");
    }

    /**
     * Creates a standardized error entity for JSON responses.
     * This ensures consistent error response format across all status types.
     *
     * @param message The error message
     * @return A formatted error entity with consistent structure
     */
    private static ErrorEntity createErrorEntity(String message) {
        return new ErrorEntity(false, message);
    }

    /**
     * Simple error entity for JSON responses.
     * Provides a consistent structure for error responses.
     */
    @RegisterForReflection
    public record ErrorEntity(boolean valid, String message) {
    }
}
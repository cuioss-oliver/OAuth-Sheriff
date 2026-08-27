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

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.quarkus.annotation.BearerToken;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.ws.rs.core.Response;
import lombok.Builder;
import lombok.Value;

import java.io.Serial;
import java.io.Serializable;
import java.util.Optional;
import java.util.Set;

/**
 * Result object containing comprehensive information about bearer token validation.
 * <p>
 * This class provides detailed information about the outcome of bearer token processing,
 * including the validation status, the validated token content (if successful),
 * required scopes/roles/groups (if constraint violations occurred), and
 * error details (if validation failed).
 * <p>
 * The result includes:
 * <ul>
 *   <li>The validation status indicating what happened during processing</li>
 *   <li>The validated AccessTokenContent if successful</li>
 *   <li>Required scopes, roles, and groups that caused constraint violations</li>
 *   <li>Error details from TokenValidationException if parsing failed</li>
 * </ul>
 * <p>
 * Usage example with CDI injection:
 * <pre>{@code
 * @Inject
 * @BearerToken(requiredScopes = {"read"}, requiredRoles = {"user"})
 * BearerTokenResult tokenResult;
 *
 * public Response handleRequest() {
 *     if (tokenResult.isNotSuccessfullyAuthorized()) {
 *         return tokenResult.createErrorResponse();
 *     }
 *     AccessTokenContent token = tokenResult.getAccessTokenContent()
 *             .orElseThrow(() -> new IllegalStateException("Token content missing after successful authorization"));
 *     // Use validated token
 *     return Response.ok().build();
 * }
 * }</pre>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@Value
@Builder
@RegisterForReflection
@SuppressWarnings("java:S1948") // owolff: All implementations are Serializable
public class BearerTokenResult implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;


    BearerTokenStatus status;

    /**
     * The full set of scopes required by the {@link BearerToken} annotation.
     * Always populated for non-FULLY_VERIFIED statuses.
     */
    @Builder.Default
    Set<String> requiredScopes = Set.of();

    /**
     * The full set of roles required by the {@link BearerToken} annotation.
     * Always populated for non-FULLY_VERIFIED statuses.
     */
    @Builder.Default
    Set<String> requiredRoles = Set.of();

    /**
     * The full set of groups required by the {@link BearerToken} annotation.
     * Always populated for non-FULLY_VERIFIED statuses.
     */
    @Builder.Default
    Set<String> requiredGroups = Set.of();

    /**
     * The scopes that the token is missing. Only populated for {@link BearerTokenStatus#CONSTRAINT_VIOLATION}.
     * Empty for all other statuses (where no validation occurred, so the missing set is unknown).
     */
    @Builder.Default
    Set<String> missingScopes = Set.of();

    /**
     * The roles that the token is missing. Only populated for {@link BearerTokenStatus#CONSTRAINT_VIOLATION}.
     */
    @Builder.Default
    Set<String> missingRoles = Set.of();

    /**
     * The groups that the token is missing. Only populated for {@link BearerTokenStatus#CONSTRAINT_VIOLATION}.
     */
    @Builder.Default
    Set<String> missingGroups = Set.of();

    AccessTokenContent accessTokenContent;

    EventType errorEventType;

    String errorMessage;


    /**
     * Creates a BearerTokenResult for failed token validation due to parsing error.
     *
     * @param exception      the TokenValidationException that occurred during parsing
     * @param requiredScopes the scopes that were required for validation
     * @param requiredRoles  the roles that were required for validation
     * @param requiredGroups the groups that were required for validation
     * @return a BearerTokenResult indicating parsing error
     */
   
    public static BearerTokenResult parsingError(TokenValidationException exception,
            Set<String> requiredScopes, Set<String> requiredRoles, Set<String> requiredGroups) {
        return builder()
                .status(BearerTokenStatus.PARSING_ERROR)
                .errorEventType(exception.getEventType())
                .errorMessage(exception.getMessage())
                .requiredScopes(requiredScopes)
                .requiredRoles(requiredRoles)
                .requiredGroups(requiredGroups)
                .build();
    }


    /**
     * Creates a BearerTokenResult for cases where no token was provided.
     *
     * @param requiredScopes the scopes that were required for validation
     * @param requiredRoles  the roles that were required for validation
     * @param requiredGroups the groups that were required for validation
     * @return a BearerTokenResult indicating no token was given
     */
   
    public static BearerTokenResult noTokenGiven(Set<String> requiredScopes,
            Set<String> requiredRoles, Set<String> requiredGroups) {
        return builder()
                .status(BearerTokenStatus.NO_TOKEN_GIVEN)
                .requiredScopes(requiredScopes)
                .requiredRoles(requiredRoles)
                .requiredGroups(requiredGroups)
                .build();
    }


    /**
     * Creates a BearerTokenResult for invalid bearer token requests (RFC 6750 violation).
     * <p>
     * This is used when the Authorization header contains "Bearer " but the token
     * is empty or contains invalid characters according to RFC 6750 section 2.1.
     *
     * @param errorMessage   the error message describing the invalid request
     * @param requiredScopes the scopes that were required for validation
     * @param requiredRoles  the roles that were required for validation
     * @param requiredGroups the groups that were required for validation
     * @return a BearerTokenResult indicating an invalid request
     */
   
    public static BearerTokenResult invalidRequest(String errorMessage, Set<String> requiredScopes,
            Set<String> requiredRoles, Set<String> requiredGroups) {
        return builder()
                .status(BearerTokenStatus.INVALID_REQUEST)
                .errorMessage(errorMessage)
                .requiredScopes(requiredScopes)
                .requiredRoles(requiredRoles)
                .requiredGroups(requiredGroups)
                .build();
    }

    /**
     * Gets the validated AccessTokenContent if validation was successful.
     *
     * @return Optional containing the AccessTokenContent, or empty if validation failed
     */
    public Optional<AccessTokenContent> getAccessTokenContent() {
        return Optional.ofNullable(accessTokenContent);
    }

    /**
     * Gets the EventType from TokenValidationException if a parsing error occurred.
     *
     * @return Optional containing the EventType, or empty if no parsing error occurred
     */
    public Optional<EventType> getErrorEventType() {
        return Optional.ofNullable(errorEventType);
    }

    /**
     * Gets the error message from TokenValidationException if a parsing error occurred.
     *
     * @return Optional containing the error message, or empty if no parsing error occurred
     */
    public Optional<String> getErrorMessage() {
        return Optional.ofNullable(errorMessage);
    }

    /**
     * Checks if the token validation was successful, and all configured claims like
     * {@link BearerToken#requiredRoles()}, {@link BearerToken#requiredScopes()} and {@link BearerToken#requiredGroups()}
     * are successfully verified.
     *
     * @return true if status is FULLY_VERIFIED, false otherwise
     */
    public boolean isSuccessfullyAuthorized() {
        return status == BearerTokenStatus.FULLY_VERIFIED;
    }

    /**
     * Checks if the token validation was unsuccessful.
     *
     * @return true if status is not FULLY_VERIFIED, false otherwise
     */
    public boolean isNotSuccessfullyAuthorized() {
        return status != BearerTokenStatus.FULLY_VERIFIED;
    }

    /**
     * Creates an appropriate error response based on the token validation result.
     * <p>
     * This method simplifies error handling by directly creating the HTTP response
     * for failed validations. It follows OAuth 2.0 Bearer Token specification (RFC 6750)
     * and OAuth Step-Up Authentication Challenge best practices.
     * <p>
     * Standard usage pattern:
     * <pre>{@code
     * if (tokenResult.isNotSuccessfullyAuthorized()) {
     *     return tokenResult.createErrorResponse();
     * }
     * // ... positive case business logic
     * }</pre>
     *
     * @return Response object with appropriate HTTP status code, headers, and body
     * @throws IllegalStateException if called on a successfully authorized token
     */
    public Response createErrorResponse() {
        if (isSuccessfullyAuthorized()) {
            throw new IllegalStateException("Cannot create error response for successfully authorized token, status=" + status);
        }
        return BearerTokenResponseFactory.createResponse(this);
    }

}
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
package de.cuioss.sheriff.token.quarkus.annotation;

import jakarta.enterprise.util.Nonbinding;
import jakarta.inject.Qualifier;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * CDI qualifier for injecting BearerTokenResult with validated token information from HTTP Authorization header.
 * <p>
 * This annotation allows specifying required scopes, roles, and groups that the bearer token
 * must contain for successful validation. The producer always returns a {@link de.cuioss.sheriff.token.quarkus.producer.BearerTokenResult}
 * object containing the validation status, the validated token (if successful), and detailed
 * error information (if validation failed).
 * <p>
 * <strong>Note:</strong> For declarative security with automatic validation, use {@link BearerAuth} instead.
 *
 * <h2>Usage Pattern: CDI Producer Pattern (Explicit Validation)</h2>
 * Inject {@link de.cuioss.sheriff.token.quarkus.producer.BearerTokenResult} and manually check authorization:
 * <pre>{@code
 * @RequestScoped
 * @Path("/api")
 * public class DataResource {
 *
 *     @Inject
 *     @BearerToken(requiredScopes = {"read", "write"}, requiredRoles = {"admin"})
 *     BearerTokenResult tokenResult;
 *
 *     @GET
 *     public Response getData() {
 *         if (tokenResult.isNotSuccessfullyAuthorized()) {
 *             return tokenResult.createErrorResponse();
 *         }
 *         AccessTokenContent token = tokenResult.getAccessTokenContent()
 *                 .orElseThrow(() -> new IllegalStateException("Token content missing after successful authorization"));
 *         // Use validated token
 *         return Response.ok(token.getSubject().orElse("unknown")).build();
 *     }
 * }
 * }</pre>
 *
 * <h2>Constructor Injection (Recommended for Producer Pattern):</h2>
 * <pre>{@code
 * @RequestScoped
 * public class SecureService {
 *     private final BearerTokenResult tokenResult;
 *
 *     @Inject
 *     public SecureService(@BearerToken(requiredRoles = {"admin"}) BearerTokenResult tokenResult) {
 *         this.tokenResult = tokenResult;
 *     }
 * }
 * }</pre>
 *
 * <h2>For Application-Scoped beans, use Provider:</h2>
 * <pre>{@code
 * @ApplicationScoped
 * public class GlobalService {
 *
 *     @Inject
 *     @BearerToken(requiredGroups = {"managers"})
 *     Provider<BearerTokenResult> tokenResultProvider;
 *
 *     public void doSomething() {
 *         BearerTokenResult result = tokenResultProvider.get();
 *         if (result.isSuccessfullyAuthorized()) {
 *             // Process with validated token
 *         }
 *     }
 * }
 * }</pre>
 *
 * <h2>Token Validation Process:</h2>
 * <ul>
 *   <li>Extracts the token from the HTTP Authorization header</li>
 *   <li>Validates the JWT signature and claims using the configured TokenValidator</li>
 *   <li>Checks that all required scopes, roles, and groups are present</li>
 *   <li>Returns a BearerTokenResult with detailed status information</li>
 * </ul>
 * <p>
 * <strong>Declarative Alternative:</strong> For automatic validation without manual checks, use {@link BearerAuth} annotation.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see BearerAuth
 */
@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE})
public @interface BearerToken {

    /**
     * Specifies the required scopes that the bearer token must contain.
     * <p>
     * All listed scopes must be present in the token's scope claim for successful validation.
     * If this array is empty, no scope validation is performed.
     *
     * @return array of required scope names
     */
    @Nonbinding
    String[] requiredScopes() default {};

    /**
     * Specifies the required roles that the bearer token must contain.
     * <p>
     * All listed roles must be present in the token's roles claim for successful validation.
     * If this array is empty, no role validation is performed.
     *
     * @return array of required role names
     */
    @Nonbinding
    String[] requiredRoles() default {};

    /**
     * Specifies the required groups that the bearer token must contain.
     * <p>
     * All listed groups must be present in the token's groups claim for successful validation.
     * If this array is empty, no group validation is performed.
     *
     * @return array of required group names
     */
    @Nonbinding
    String[] requiredGroups() default {};
}

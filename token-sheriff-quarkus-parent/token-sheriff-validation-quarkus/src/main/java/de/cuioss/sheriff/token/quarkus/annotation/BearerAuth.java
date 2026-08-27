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

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.util.Nonbinding;
import jakarta.interceptor.InterceptorBinding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Interceptor binding for declarative Bearer token validation at method or class level.
 * <p>
 * This annotation enables automatic Bearer token validation and error handling when applied
 * to methods or classes. It provides a declarative security approach where validation
 * happens automatically before method execution.
 * <p>
 * The annotation allows specifying required scopes, roles, and groups that the bearer token
 * must contain for successful validation. All members are marked as {@link Nonbinding} to
 * ensure they don't affect interceptor binding resolution in CDI.
 *
 * <h2>Usage Pattern: Declarative Security (Interceptor)</h2>
 * Apply annotation to methods for automatic validation and error response handling:
 * <pre>{@code
 * @Path("/api")
 * public class SecureResource {
 *
 *     @GET
 *     @BearerAuth(requiredScopes = {"read"}, requiredRoles = {"user"})
 *     public Response getData() {
 *         // Only business logic - security handled by interceptor
 *         // If validation fails, error response is returned automatically
 *         return Response.ok(data).build();
 *     }
 * }
 * }</pre>
 *
 * <h2>Class-Level Application and Merging:</h2>
 * When both class-level and method-level {@code @BearerAuth} annotations are present,
 * their requirements are <strong>merged</strong> (union). The resulting required scopes,
 * roles, and groups are the union of both annotation levels. This allows defining
 * baseline security requirements at the class level and adding method-specific
 * requirements on individual endpoints.
 * <pre>{@code
 * @Path("/api")
 * @BearerAuth(requiredRoles = {"admin"})
 * public class AdminResource {
 *
 *     @GET
 *     @Path("/users")
 *     public Response getUsers() {
 *         // All methods in this class require admin role
 *         return Response.ok(users).build();
 *     }
 *
 *     @GET
 *     @Path("/settings")
 *     @BearerAuth(requiredScopes = {"admin:settings"})
 *     public Response getSettings() {
 *         // Merged: requires admin role (from class) AND admin:settings scope (from method)
 *         return Response.ok(settings).build();
 *     }
 * }
 * }</pre>
 *
 * <h2>Accessing Validated Token:</h2>
 * Use parameter injection with {@link BearerToken} to access the validated token:
 * <pre>{@code
 * @GET
 * @BearerAuth(requiredScopes = {"read"})
 * public Response getData(@BearerToken BearerTokenResult tokenResult) {
 *     AccessTokenContent token = tokenResult.getAccessTokenContent()
 *         .orElseThrow(() -> new IllegalStateException("Token not available"));
 *
 *     String userId = token.getSubject().orElse("unknown");
 *
 *     return Response.ok(data).build();
 * }
 * }</pre>
 *
 * <h2>Error Handling:</h2>
 * <ul>
 *   <li>Methods returning {@link jakarta.ws.rs.core.Response}: Automatic error response via {@link de.cuioss.sheriff.token.quarkus.producer.BearerTokenResponseFactory}</li>
 *   <li>Other return types: Validation still occurs, access token via {@link BearerToken} parameter injection</li>
 * </ul>
 *
 * <h2>HTTP Response Codes:</h2>
 * <ul>
 *   <li>401 Unauthorized: Missing token, invalid token, or missing required scopes</li>
 *   <li>403 Forbidden: Missing required roles or groups</li>
 *   <li>400 Bad Request: Malformed bearer token (empty token, invalid format)</li>
 * </ul>
 *
 * <h2>Comparison with Producer Pattern:</h2>
 * For explicit validation control, use {@link BearerToken} with CDI injection instead:
 * <pre>{@code
 * @Inject
 * @BearerToken(requiredScopes = {"read"})
 * BearerTokenResult tokenResult;
 *
 * @GET
 * public Response getData() {
 *     if (tokenResult.isNotSuccessfullyAuthorized()) {
 *         return tokenResult.createErrorResponse();
 *     }
 *     // Business logic
 * }
 * }</pre>
 *
 * <h2>Token Validation Process:</h2>
 * <ul>
 *   <li>Extracts token from HTTP Authorization header</li>
 *   <li>Validates JWT signature and claims using configured TokenValidator</li>
 *   <li>Checks all required scopes, roles, and groups are present</li>
 *   <li>Returns automatic error response if validation fails (for Response return types)</li>
 *   <li>Stores validated token in request context for method access</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see BearerToken
 * @see de.cuioss.sheriff.token.quarkus.interceptor.BearerTokenInterceptor
 * @see de.cuioss.sheriff.token.quarkus.producer.BearerTokenResult
 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@RegisterForReflection(methods = true, fields = false)
public @interface BearerAuth {

    /**
     * Specifies the required scopes that the bearer token must contain.
     * <p>
     * All listed scopes must be present in the token's scope claim for successful validation.
     * If this array is empty, no scope validation is performed.
     * <p>
     * Missing scopes result in HTTP 401 Unauthorized with error code "insufficient_scope".
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
     * <p>
     * Missing roles result in HTTP 403 Forbidden with error code "insufficient_privileges".
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
     * <p>
     * Missing groups result in HTTP 403 Forbidden with error code "insufficient_privileges".
     *
     * @return array of required group names
     */
    @Nonbinding
    String[] requiredGroups() default {};
}

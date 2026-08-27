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
package de.cuioss.sheriff.token.quarkus.interceptor;

import de.cuioss.sheriff.token.quarkus.annotation.BearerAuth;
import de.cuioss.sheriff.token.quarkus.producer.BearerTokenProducer;
import de.cuioss.sheriff.token.quarkus.producer.BearerTokenResult;
import de.cuioss.tools.logging.CuiLogger;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.ws.rs.WebApplicationException;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Interceptor for declarative Bearer token validation at method level.
 * <p>
 * This interceptor provides automatic Bearer token validation and error handling
 * when methods or classes are annotated with {@link BearerAuth}. It follows
 * Quarkus 2025 best practices for security interceptors.
 * <p>
 * The interceptor:
 * <ul>
 *   <li>Extracts annotation parameters (requiredScopes, requiredRoles, requiredGroups)</li>
 *   <li>Delegates validation to {@link BearerTokenProducer}</li>
 *   <li>Throws WebApplicationException with error response for failed validation</li>
 *   <li>Proceeds with method execution if validation succeeds</li>
 *   <li>Makes validated token available via CDI event for intercepted methods</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>{@code
 * @Path("/api")
 * public class SecureResource {
 *
 *     @GET
 *     @BearerAuth(requiredScopes = {"read"}, requiredRoles = {"user"})
 *     public Response getData() {
 *         // Only business logic - security handled by interceptor
 *         return Response.ok(data).build();
 *     }
 * }
 * }</pre>
 * <p>
 * <strong>Priority:</strong> PLATFORM_BEFORE + 200 ensures security validation
 * runs after platform infrastructure but before business logic interceptors.
 * <p>
 * <strong>Performance:</strong> Minimal object allocation, reuses existing
 * BearerTokenProducer infrastructure, fast-path execution for successful validation.
 * <p>
 * <strong>Error Handling:</strong>
 * <ul>
 *   <li>Failed validation throws WebApplicationException with appropriate error response</li>
 *   <li>Works for any method return type (Response, String, DTO, etc.)</li>
 *   <li>Successful validation allows method to proceed and access token via CDI event</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@BearerAuth
@Interceptor
@Priority(Interceptor.Priority.PLATFORM_BEFORE + 200)
@RegisterForReflection
public class BearerTokenInterceptor {

    private static final CuiLogger LOGGER = new CuiLogger(BearerTokenInterceptor.class);

    private final BearerTokenProducer bearerTokenProducer;

    @Inject
    public BearerTokenInterceptor(BearerTokenProducer bearerTokenProducer) {
        this.bearerTokenProducer = bearerTokenProducer;
    }

    /**
     * Holds the merged authentication requirements from class-level and method-level
     * {@link BearerAuth} annotations.
     *
     * @param requiredScopes the union of required scopes from both annotation levels
     * @param requiredRoles  the union of required roles from both annotation levels
     * @param requiredGroups the union of required groups from both annotation levels
     */
    private record MergedAuth(Set<String> requiredScopes, Set<String> requiredRoles, Set<String> requiredGroups) {

        /**
         * Creates a MergedAuth from a single BearerAuth annotation.
         */
        static MergedAuth fromAnnotation(BearerAuth annotation) {
            return new MergedAuth(
                    annotation.requiredScopes().length > 0 ? Set.copyOf(List.of(annotation.requiredScopes())) : Set.of(),
                    annotation.requiredRoles().length > 0 ? Set.copyOf(List.of(annotation.requiredRoles())) : Set.of(),
                    annotation.requiredGroups().length > 0 ? Set.copyOf(List.of(annotation.requiredGroups())) : Set.of()
            );
        }

        /**
         * Creates a MergedAuth by computing the union of two BearerAuth annotations.
         */
        static MergedAuth merge(BearerAuth classLevel, BearerAuth methodLevel) {
            return new MergedAuth(
                    unionOf(classLevel.requiredScopes(), methodLevel.requiredScopes()),
                    unionOf(classLevel.requiredRoles(), methodLevel.requiredRoles()),
                    unionOf(classLevel.requiredGroups(), methodLevel.requiredGroups())
            );
        }

        private static Set<String> unionOf(String[] first, String[] second) {
            return Stream.concat(Arrays.stream(first), Arrays.stream(second))
                    .collect(Collectors.toUnmodifiableSet());
        }
    }

    /**
     * Intercepts method calls to validate bearer tokens declaratively.
     * <p>
     * This method follows the interceptor pattern for security validation:
     * <ol>
     *   <li>Extract and merge annotation parameters from method and class level</li>
     *   <li>Delegate to BearerTokenProducer for validation</li>
     *   <li>If validation fails, throw WebApplicationException with error response</li>
     *   <li>If validation succeeds, proceed with method execution</li>
     * </ol>
     *
     * @param ctx the invocation context containing method and annotation information
     * @return the result of the intercepted method
     * @throws jakarta.ws.rs.WebApplicationException if validation fails
     * @throws Exception if the intercepted method throws an exception
     */
    @AroundInvoke
    public Object validateBearerToken(InvocationContext ctx) throws Exception {
        // Extract and merge annotations from method and class level
        MergedAuth mergedAuth = extractMergedAuth(ctx);

        LOGGER.debug("Validating bearer token with scopes: %s, roles: %s, groups: %s",
                mergedAuth.requiredScopes(), mergedAuth.requiredRoles(), mergedAuth.requiredGroups());

        // Delegate validation to BearerTokenProducer
        BearerTokenResult result = bearerTokenProducer.getBearerTokenResult(
                mergedAuth.requiredScopes(), mergedAuth.requiredRoles(), mergedAuth.requiredGroups());

        // Handle validation failure
        if (result.isNotSuccessfullyAuthorized()) {
            LOGGER.debug("Bearer token validation failed: %s", result.getStatus());
            throw new WebApplicationException(result.createErrorResponse());
        }

        // Validation successful - proceed with method execution
        // Token is available via @BearerToken injection if needed
        return ctx.proceed();
    }

    /**
     * Extracts and merges {@link BearerAuth} annotations from both the method and its
     * declaring class. If both levels are annotated, the requirements are merged (union
     * of requiredScopes, requiredRoles, requiredGroups). If only one level is annotated,
     * its values are used directly.
     *
     * @param ctx the invocation context
     * @return the merged authentication requirements
     * @throws IllegalStateException if no {@code @BearerAuth} annotation is found at either level
     */
    private MergedAuth extractMergedAuth(InvocationContext ctx) {
        BearerAuth methodAnnotation = ctx.getMethod().getAnnotation(BearerAuth.class);
        BearerAuth classAnnotation = ctx.getTarget().getClass().getAnnotation(BearerAuth.class);

        if (methodAnnotation != null && classAnnotation != null) {
            return MergedAuth.merge(classAnnotation, methodAnnotation);
        }
        if (methodAnnotation != null) {
            return MergedAuth.fromAnnotation(methodAnnotation);
        }
        if (classAnnotation != null) {
            return MergedAuth.fromAnnotation(classAnnotation);
        }

        // Fail closed: missing annotation means security configuration error
        throw new IllegalStateException(
                "@BearerAuth annotation not found on method '%s' or its declaring class. "
                        .formatted(ctx.getMethod().getName())
                        + "Security interceptor cannot proceed without authentication configuration.");
    }
}

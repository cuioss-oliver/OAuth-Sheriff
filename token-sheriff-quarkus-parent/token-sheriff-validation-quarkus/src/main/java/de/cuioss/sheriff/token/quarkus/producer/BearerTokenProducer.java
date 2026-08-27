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

import de.cuioss.sheriff.token.commons.metrics.MetricIdentifier;
import de.cuioss.sheriff.token.quarkus.annotation.BearerToken;
import de.cuioss.sheriff.token.quarkus.annotation.ServletObjectsResolver;
import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.servlet.HttpRequestResolver;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.tools.logging.CuiLogger;
import io.micrometer.core.annotation.Timed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.CreationException;
import jakarta.enterprise.inject.Produces;
import jakarta.enterprise.inject.spi.InjectionPoint;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.WARN.*;

/**
 * CDI producer for extracting and validating bearer tokens from HTTP Authorization headers.
 * <p>
 * This producer extracts bearer tokens from the HTTP Authorization header using HttpRequestResolver,
 * validates them using the configured TokenValidator, and checks for required scopes, roles, and groups.
 * <p>
 * The producer provides both service methods that return {@link BearerTokenResult} with comprehensive
 * validation information and a CDI producer method that returns {@link BearerTokenResult} directly for injection.
 * <p>
 * CDI injection usage example:
 * <pre>{@code
 * @RequestScoped
 * @Path("/api")
 * public class MyResource {
 *
 *     @Inject
 *     @BearerToken(requiredScopes = {"read", "write"})
 *     BearerTokenResult tokenResult;
 *
 *     @GET
 *     public Response getData() {
 *         if (tokenResult.isNotSuccessfullyAuthorized()) {
 *             return tokenResult.createErrorResponse();
 *         }
 *         AccessTokenContent token = tokenResult.getAccessTokenContent()
 *                 .orElseThrow(() -> new IllegalStateException("Token content missing after successful authorization"));
 *         // Use validated token - getSubject() returns Optional&lt;String&gt;
 *         return Response.ok(token.getSubject().orElse("unknown")).build();
 *     }
 * }
 * }</pre>
 * <p>
 * <strong>Important:</strong> For Application-Scoped beans, use {@link jakarta.inject.Provider} since
 * BearerTokenResult is RequestScoped. The preferred way is for the containing class to be RequestScoped
 * as well, then you can use constructor injection:
 * <pre>{@code
 * @RequestScoped
 * public class MyService {
 *     private final BearerTokenResult tokenResult;
 *
 *     @Inject
 *     public MyService(@BearerToken(requiredRoles = {"admin"}) BearerTokenResult tokenResult) {
 *         this.tokenResult = tokenResult;
 *     }
 * }
 * }</pre>
 * <p>
 * For direct service usage, use the CDI producer method with annotations:
 * <pre>{@code
 * @Inject
 * @BearerToken(requiredScopes = {"read"}, requiredRoles = {"user"})
 * BearerTokenResult tokenResult;
 *
 * public Response someMethod() {
 *     if (tokenResult.isNotSuccessfullyAuthorized()) {
 *         return tokenResult.createErrorResponse();
 *     }
 *     AccessTokenContent content = tokenResult.getAccessTokenContent()
 *             .orElseThrow(() -> new IllegalStateException("Token content missing after successful authorization"));
 *     // Use validated token
 *     return Response.ok().build();
 * }
 * }</pre>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@ApplicationScoped
public class BearerTokenProducer {

    private static final CuiLogger LOGGER = new CuiLogger(BearerTokenProducer.class);
    static final String BEARER_PREFIX = "Bearer ";
    static final String AUTHORIZATION_HEADER_VALUE = "Authorization";
    static final String COOKIE_HEADER_VALUE = "Cookie";

    private final TokenValidator tokenValidator;
    private final HttpRequestResolver servletObjectsResolver;
    private final Provider<JsonWebToken> jsonWebTokenProvider;
    private final String tokenHeader;
    private final String tokenCookieName;

    @Inject
    public BearerTokenProducer(TokenValidator tokenValidator,
            @ServletObjectsResolver HttpRequestResolver servletObjectsResolver,
            Provider<JsonWebToken> jsonWebTokenProvider,
            @ConfigProperty(name = JwtPropertyKeys.TOKEN.HEADER, defaultValue = AUTHORIZATION_HEADER_VALUE) String tokenHeader,
            @ConfigProperty(name = JwtPropertyKeys.TOKEN.COOKIE_NAME, defaultValue = "Bearer") String tokenCookieName) {
        // Property values may carry accidental surrounding whitespace — trim before validating
        String trimmedHeader = tokenHeader.trim();
        if (!AUTHORIZATION_HEADER_VALUE.equalsIgnoreCase(trimmedHeader)
                && !COOKIE_HEADER_VALUE.equalsIgnoreCase(trimmedHeader)) {
            throw new IllegalStateException(
                    "Invalid value '%s' for property '%s'. Supported values are '%s' and '%s'."
                            .formatted(tokenHeader, JwtPropertyKeys.TOKEN.HEADER,
                                    AUTHORIZATION_HEADER_VALUE, COOKIE_HEADER_VALUE));
        }
        this.tokenValidator = tokenValidator;
        this.servletObjectsResolver = servletObjectsResolver;
        this.jsonWebTokenProvider = jsonWebTokenProvider;
        this.tokenHeader = trimmedHeader;
        this.tokenCookieName = tokenCookieName.trim();
    }

    /**
     * Gets the current request's AccessTokenContent from the HTTP Authorization header.
     * This method handles tokens without specific requirements.
     *
     * @return Optional containing validated AccessTokenContent, or empty if validation fails
     */
    private Optional<AccessTokenContent> getAccessTokenContent() {
        return getBearerTokenResult(Set.of(), Set.of(), Set.of()).getAccessTokenContent();
    }

    /**
     * Gets comprehensive bearer token validation result with detailed status information.
     *
     * @param requiredScopes Required scopes for the token
     * @param requiredRoles Required roles for the token
     * @param requiredGroups Required groups for the token
     * @return BearerTokenResult containing detailed validation information
     */

    @Timed(value = MetricIdentifier.BEARERTOKEN.VALIDATION, description = "Bearer token validation duration")
    public BearerTokenResult getBearerTokenResult(
            Set<String> requiredScopes, Set<String> requiredRoles, Set<String> requiredGroups) {

        LOGGER.debug("Validating bearer token with required scopes: %s, roles: %s, groups: %s",
                requiredScopes, requiredRoles, requiredGroups);

        // Resolve headers once and reuse for both extraction and validation request
        Map<String, List<String>> headerMap = servletObjectsResolver.resolveHeaderMap();

        Optional<String> tokenResult = extractBearerTokenFromHeaderMap(headerMap);

        // When token.header=Cookie, fall back to cookie extraction if no Authorization token
        if (tokenResult.isEmpty() && COOKIE_HEADER_VALUE.equalsIgnoreCase(tokenHeader)) {
            tokenResult = extractTokenFromCookieHeader(headerMap);
        }

        if (tokenResult.isEmpty()) {
            if (COOKIE_HEADER_VALUE.equalsIgnoreCase(tokenHeader)) {
                LOGGER.debug("Bearer token not found in Authorization header or '%s' cookie", tokenCookieName);
            } else {
                LOGGER.debug("Bearer token missing or invalid in Authorization header");
            }
            return BearerTokenResult.noTokenGiven(requiredScopes, requiredRoles, requiredGroups);
        }

        String bearerToken = tokenResult.get();

        // Check for empty bearer token (RFC 6750 violation - should return 400 Bad Request)
        if (bearerToken.trim().isEmpty()) {
            LOGGER.debug("Bearer token is empty - invalid request per RFC 6750");
            return BearerTokenResult.invalidRequest(
                    "Bearer token is empty", requiredScopes, requiredRoles, requiredGroups);
        }

        try {
            // Pass HTTP headers and request context through for DPoP htu/htm validation (RFC 9449)
            RequestContext requestContext = resolveRequestContext();
            AccessTokenContent tokenContent = tokenValidator.createAccessToken(
                    new AccessTokenRequest(bearerToken, headerMap, requestContext.uri(), requestContext.method()));

            // Determine missing scopes, roles, and groups
            Set<String> missingScopes = tokenContent.determineMissingScopes(requiredScopes);
            Set<String> missingRoles = tokenContent.determineMissingRoles(requiredRoles);
            Set<String> missingGroups = tokenContent.determineMissingGroups(requiredGroups);

            if (missingScopes.isEmpty() && missingRoles.isEmpty() && missingGroups.isEmpty()) {
                LOGGER.debug("Bearer token validation successful");
                return BearerTokenResult.builder()
                        .status(BearerTokenStatus.FULLY_VERIFIED)
                        .accessTokenContent(tokenContent)
                        .build();
            } else {
                LOGGER.warn(BEARER_TOKEN_REQUIREMENTS_NOT_MET_DETAILED, missingScopes, missingRoles, missingGroups);
                return BearerTokenResult.builder()
                        .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                        .requiredScopes(requiredScopes)
                        .requiredRoles(requiredRoles)
                        .requiredGroups(requiredGroups)
                        .missingScopes(missingScopes)
                        .missingRoles(missingRoles)
                        .missingGroups(missingGroups)
                        .build();
            }
        } catch (TokenValidationException e) {
            /*~~(TODO: WARN needs LogRecord. Suppress: // cui-rewrite:disable CuiLogRecordPatternRecipe)~~>*/
            LOGGER.warn(e, BEARER_TOKEN_VALIDATION_FAILED, e.getMessage(), e.getEventType());
            return BearerTokenResult.parsingError(e, requiredScopes, requiredRoles, requiredGroups);
        }
    }


    /**
     * Holds the resolved HTTP request URI and method for DPoP htu/htm validation.
     */
    private record RequestContext(String uri, String method) {
    }

    /**
     * Resolves the HTTP request URI and method for DPoP htu/htm validation.
     * Both values default to {@code null} if resolution fails.
     *
     * @return a RequestContext with the resolved URI and method
     */
    private RequestContext resolveRequestContext() {
        try {
            return new RequestContext(
                    servletObjectsResolver.resolveRequestUri(),
                    servletObjectsResolver.resolveRequestMethod()
            );
        }
        catch (IllegalStateException | UnsupportedOperationException | CreationException e) {
            LOGGER.debug("Could not resolve request URI/method for DPoP htu/htm validation: %s", e.getMessage());
            return new RequestContext(null, null);
        }
    }

    /**
     * Extracts the bearer token from the provided HTTP header map.
     * <p>
     * Two-state return model:
     * <ul>
     *   <li>Optional.empty() - No token found, missing token, or infrastructure error</li>
     *   <li>Optional.of(token) - Token found (may be empty string for "Bearer ")</li>
     * </ul>
     *
     * @param headerMap the resolved HTTP header map
     * @return Optional containing the bearer token, or empty Optional if no token found
     */
    private Optional<String> extractBearerTokenFromHeaderMap(Map<String, List<String>> headerMap) {
        // Header names are normalized to lowercase by HttpRequestResolver per RFC 9113 (HTTP/2)
        // and RFC 7230 (HTTP/1.1). Direct lookup with lowercase key is sufficient.
        List<String> authHeaders = headerMap.get("authorization");

        if (authHeaders == null || authHeaders.isEmpty()) {
            LOGGER.debug("Authorization header not found in headerMap");
            return Optional.empty(); // No Authorization header - missing token
        }

        String authHeader = authHeaders.getFirst();
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return Optional.empty(); // Not a Bearer token - missing token
        }

        // Bearer token found - extract the token part (may be empty string for "Bearer ")
        String token = authHeader.substring(BEARER_PREFIX.length());
        return Optional.of(token);
    }

    /**
     * Extracts a JWT token from the HTTP Cookie header.
     * <p>
     * Parses the Cookie header value according to RFC 6265 and looks for a cookie
     * matching the configured {@link #tokenCookieName}. Cookie values may optionally
     * be enclosed in double quotes per RFC 6265 Section 4.1.1.
     * </p>
     *
     * @param headerMap the resolved HTTP header map (keys are lowercase)
     * @return Optional containing the token value, or empty if cookie not found
     */
    Optional<String> extractTokenFromCookieHeader(Map<String, List<String>> headerMap) {
        List<String> cookieHeaders = headerMap.get("cookie");
        if (cookieHeaders == null || cookieHeaders.isEmpty()) {
            LOGGER.debug("Cookie header not found in headerMap");
            return Optional.empty();
        }

        // Cookie header format: "name1=value1; name2=value2"
        for (String cookieHeader : cookieHeaders) {
            if (cookieHeader == null) {
                continue;
            }
            Optional<String> result = findCookieValue(cookieHeader);
            if (result.isPresent()) {
                return result;
            }
        }

        LOGGER.debug("Cookie '%s' not found in Cookie header", tokenCookieName);
        return Optional.empty();
    }

    private Optional<String> findCookieValue(String cookieHeader) {
        String[] cookies = cookieHeader.split(";");
        for (String cookie : cookies) {
            String trimmed = cookie.trim();
            int eqIndex = trimmed.indexOf('=');
            if (eqIndex > 0 && tokenCookieName.equals(trimmed.substring(0, eqIndex).trim())) {
                String value = trimmed.substring(eqIndex + 1).trim();
                // Remove optional surrounding double quotes per RFC 6265
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                if (value.isEmpty()) {
                    LOGGER.debug("Cookie '%s' found but value is empty", tokenCookieName);
                    return Optional.empty();
                }
                LOGGER.debug("Token extracted from cookie '%s'", tokenCookieName);
                return Optional.of(value);
            }
        }
        return Optional.empty();
    }

    /**
     * Produces the current request's BearerTokenResult as a CDI bean.
     * <p>
     * This producer method provides comprehensive bearer token validation information
     * including detailed status, error information, and the validated token content.
     * This method extracts the bearer token from the HTTP Authorization header
     * and validates it using the configured TokenValidator.
     * <p>
     * The producer method is @Dependent scoped, which means it will be created fresh
     * for each injection point. Unlike the AccessTokenContent producer, this method
     * always returns a valid BearerTokenResult object containing detailed information
     * about the validation outcome.
     * <p>
     * Usage example:
     * <pre>{@code
     * @Inject
     * @BearerToken(requiredScopes = {"read", "write"})
     * BearerTokenResult tokenResult;
     *
     * public void someMethod() {
     *     switch (tokenResult.getStatus()) {
     *         case FULLY_VERIFIED:
     *             AccessTokenContent token = tokenResult.getAccessTokenContent().get();
     *             // Use validated token
     *             break;
     *         case PARSING_ERROR:
     *             // Handle parsing errors with detailed information
     *             EventType eventType = tokenResult.getEventType().get();
     *             String message = tokenResult.getMessage().get();
     *             break;
     *         default:
     *             // Handle other validation failures
     *     }
     * }
     * }</pre>
     *
     * @param injectionPoint the CDI injection point containing the BearerToken annotation
     * @return the BearerTokenResult containing detailed validation information
     */
   
    @Produces
    @BearerToken
    public BearerTokenResult produceBearerTokenResult(InjectionPoint injectionPoint) {
        BearerToken annotation = injectionPoint.getAnnotated().getAnnotation(BearerToken.class);

        Set<String> requiredScopes = annotation != null ? Set.copyOf(List.of(annotation.requiredScopes())) : Set.of();
        Set<String> requiredRoles = annotation != null ? Set.copyOf(List.of(annotation.requiredRoles())) : Set.of();
        Set<String> requiredGroups = annotation != null ? Set.copyOf(List.of(annotation.requiredGroups())) : Set.of();

        return getBearerTokenResult(requiredScopes, requiredRoles, requiredGroups);
    }

    /**
     * Produces the current request's {@link JsonWebToken} for standard MP-JWT injection.
     * <p>
     * This enables the standard MicroProfile JWT Auth injection pattern:
     * <pre>{@code
     * @Inject JsonWebToken callerPrincipal;
     * }</pre>
     * <p>
     * The produced token is the validated {@link AccessTokenContent} (which implements
     * {@link JsonWebToken}) from the current HTTP request. If no valid token is present,
     * returns an empty {@link JsonWebToken} where all method calls return null/empty
     * (per MP-JWT spec: "an empty JsonWebToken is injected").
     *
     * @return the validated JsonWebToken, or an empty token if not authenticated
     */
    @Produces
    @RequestScoped
    public JsonWebToken produceJsonWebToken() {
        return getAccessTokenContent()
                .<JsonWebToken>map(JsonWebTokenAdapter::new)
                .orElse(EmptyJsonWebToken.INSTANCE);
    }

    /**
     * Produces the current request's {@link Principal} for standard Jakarta Security injection.
     * <p>
     * This enables the standard Jakarta Security injection pattern:
     * <pre>{@code
     * @Inject Principal principal;
     * }</pre>
     * <p>
     * The {@link JsonWebToken} is resolved through the CDI container (rather than by
     * calling {@link #produceJsonWebToken()} directly) so that the container caches the
     * {@code @RequestScoped} instance and the token is validated at most once per request,
     * even when both {@code Principal} and {@code JsonWebToken} are injected.
     *
     * @return the validated Principal (which is the JsonWebToken), or an empty principal
     */
    @Produces
    @RequestScoped
    public Principal producePrincipal() {
        return jsonWebTokenProvider.get();
    }
}
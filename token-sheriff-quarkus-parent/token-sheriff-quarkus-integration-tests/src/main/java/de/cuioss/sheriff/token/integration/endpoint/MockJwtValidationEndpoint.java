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
package de.cuioss.sheriff.token.integration.endpoint;

import de.cuioss.sheriff.token.integration.endpoint.JwtValidationEndpoint.ValidationResponse;
import de.cuioss.sheriff.token.quarkus.annotation.ServletObjectsResolver;
import de.cuioss.sheriff.token.quarkus.servlet.HttpRequestResolver;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.tools.logging.CuiLogger;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.smallrye.common.annotation.RunOnVirtualThread;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.*;

/**
 * Mock JWT validation endpoint for performance decomposition benchmarking.
 * <p>
 * Replicates the full processing path of {@link JwtValidationEndpoint} — same CDI
 * wiring, HTTP header extraction, and JSON response serialization — but skips the
 * actual JWT library validation ({@code tokenValidator.createAccessToken()}).
 * <p>
 * This isolates the JWT integration-specific overhead (CDI producers, header
 * extraction, claims map construction, JSON serialization) from the library
 * validation cost (77µs measured by JMH).
 *
 * @see JwtValidationEndpoint
 */
@Path("/mock-jwt")
@Produces(MediaType.APPLICATION_JSON)
@ApplicationScoped
@RegisterForReflection
@RunOnVirtualThread
public class MockJwtValidationEndpoint {

    private static final CuiLogger LOGGER = new CuiLogger(MockJwtValidationEndpoint.class);
    private static final String BEARER_PREFIX = "Bearer ";

    // Hardcoded claims matching the benchmark-user token structure
    private static final String MOCK_SUBJECT = "benchmark-user";
    private static final Set<String> MOCK_SCOPES = Set.of("read");
    private static final Set<String> MOCK_ROLES = Set.of("user");
    private static final Set<String> MOCK_GROUPS = Set.of("test-group");
    private static final String MOCK_EMAIL = "benchmark@test.com";

    // Pre-built response — avoids per-request HashMap allocation for ablation variants
    private static final ValidationResponse PREBUILT_RESPONSE =
            new ValidationResponse(true, "Ablation baseline (no per-request processing)",
                    Map.of("subject", MOCK_SUBJECT, "scopes", MOCK_SCOPES,
                            "roles", MOCK_ROLES, "groups", MOCK_GROUPS, "email", MOCK_EMAIL));

    // Injected to replicate CDI wiring cost — same beans as BearerTokenProducer
    private final TokenValidator tokenValidator;
    private final HttpRequestResolver servletObjectsResolver;

    @Inject
    public MockJwtValidationEndpoint(
            TokenValidator tokenValidator,
            @ServletObjectsResolver HttpRequestResolver servletObjectsResolver) {
        this.tokenValidator = tokenValidator;
        this.servletObjectsResolver = servletObjectsResolver;
        LOGGER.debug("MockJwtValidationEndpoint initialized with TokenValidator and HttpRequestResolver");
    }

    /**
     * Mock JWT validation endpoint that mirrors {@code /jwt/validate} processing
     * but skips {@code tokenValidator.createAccessToken()}.
     * <p>
     * Processing flow:
     * <ol>
     *   <li>Resolve HTTP header map via {@code HttpRequestResolver}</li>
     *   <li>Extract Authorization header, parse Bearer prefix</li>
     *   <li>Skip JWT library validation</li>
     *   <li>Build same response structure with hardcoded claims</li>
     * </ol>
     *
     * @return Validation result with hardcoded claims or 401 if no Bearer token
     */
    @POST
    @Path("/validate")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response validateToken() {
        Map<String, List<String>> headerMap = servletObjectsResolver.resolveHeaderMap();

        var extraction = extractBearerToken(headerMap);
        if (extraction.isError()) {
            return extraction.errorResponse();
        }

        // SKIP tokenValidator.createAccessToken() — token extracted but not validated

        var data = new HashMap<String, Object>();
        data.put("subject", MOCK_SUBJECT);
        data.put("scopes", MOCK_SCOPES);
        data.put("roles", MOCK_ROLES);
        data.put("groups", MOCK_GROUPS);
        data.put("email", MOCK_EMAIL);

        return Response.ok(new ValidationResponse(true, "Mock validation (no JWT library call)", data)).build();
    }

    /**
     * Ablation variant D: Direct JWT validation without CDI producer chain.
     * <p>
     * Extracts the Bearer token from the Authorization header (same as {@link #validateToken()})
     * and calls {@code tokenValidator.createAccessToken()} directly — bypassing the CDI
     * {@code Instance.get()} producer chain and {@code @Timed} interceptor used by
     * {@link JwtValidationEndpoint#validateToken()}.
     * <p>
     * This isolates the measured cost of JWT validation under concurrency from the CDI overhead:
     * <ul>
     *   <li>Mock JWT → Direct Validation = {@code createAccessToken()} under concurrency</li>
     *   <li>Direct Validation → JWT = CDI {@code Instance.get()} + {@code @Timed}</li>
     * </ul>
     *
     * @return Validation result with real token claims, or 401 if validation fails
     */
    @POST
    @Path("/direct-validation")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response directValidation() {
        Map<String, List<String>> headerMap = servletObjectsResolver.resolveHeaderMap();

        var extraction = extractBearerToken(headerMap);
        if (extraction.isError()) {
            return extraction.errorResponse();
        }

        // Call tokenValidator.createAccessToken() DIRECTLY — no Instance.get(), no CDI producer, no @Timed
        try {
            AccessTokenContent token = tokenValidator.createAccessToken(
                    AccessTokenRequest.of(extraction.token(), headerMap));

            var data = new HashMap<String, Object>();
            data.put("subject", token.getSubject().orElse("not-present"));
            data.put("scopes", token.getScopes());
            data.put("roles", token.getRoles());
            data.put("groups", token.getGroups());
            data.put("email", token.getEmail().orElse("not-present"));

            return Response.ok(new ValidationResponse(true, "Direct validation (no CDI producer)", data)).build();
        } catch (TokenValidationException e) {
            LOGGER.debug("Direct validation failed: %s", e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ValidationResponse(false, "Token validation failed: " + e.getMessage()))
                    .build();
        }
    }

    /**
     * Ablation variant B: JAX-RS baseline with CDI-injected class.
     * <p>
     * Returns a pre-built response without any per-request processing.
     * No header access, no config access, no HashMap construction.
     * <p>
     * Compared to variant A (health endpoint baseline), this confirms that
     * {@code @ApplicationScoped} constructor injection has zero per-request cost.
     *
     * @return Pre-built validation response
     */
    @POST
    @Path("/baseline")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response baseline() {
        // resolveHeaderMap() — not called (no servlet object access)
        // header parsing — not called (no header access)
        // HashMap construction — not called (pre-built response)
        return Response.ok(PREBUILT_RESPONSE).build();
    }

    /**
     * Ablation variant C: Header resolution only.
     * <p>
     * Calls {@code resolveHeaderMap()} to measure Vert.x context resolution cost,
     * but does not parse the Authorization header or construct a HashMap.
     * Returns a pre-built response.
     * <p>
     * The cost difference between this and {@link #baseline()} isolates the
     * Vert.x context resolution overhead.
     *
     * @return Pre-built validation response
     */
    @POST
    @Path("/header-only")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response headerOnly() {
        // Step 1: Resolve header map — KEPT (measures Vert.x context access cost)
        servletObjectsResolver.resolveHeaderMap();
        // Authorization parsing — not called
        // HashMap construction — not called (pre-built response)
        return Response.ok(PREBUILT_RESPONSE).build();
    }

    /**
     * Extracts the Bearer token from the Authorization header in the given header map.
     *
     * @param headerMap resolved HTTP headers
     * @return extraction result containing either the token string or an error response
     */
    private static TokenExtractionResult extractBearerToken(Map<String, List<String>> headerMap) {
        List<String> authHeaders = headerMap.get("authorization");
        if (authHeaders == null || authHeaders.isEmpty()) {
            return TokenExtractionResult.error(Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ValidationResponse(false, "Bearer token missing")).build());
        }

        String authHeader = authHeaders.getFirst();
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return TokenExtractionResult.error(Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ValidationResponse(false, "Not a Bearer token")).build());
        }

        String bearerToken = authHeader.substring(BEARER_PREFIX.length());
        if (bearerToken.trim().isEmpty()) {
            return TokenExtractionResult.error(Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ValidationResponse(false, "Bearer token is empty")).build());
        }

        return TokenExtractionResult.success(bearerToken);
    }

    /**
     * Result of bearer token extraction — either a token string or an error response.
     */
    private record TokenExtractionResult(String token, Response errorResponse) {
        static TokenExtractionResult success(String token) {
            return new TokenExtractionResult(token, null);
        }

        static TokenExtractionResult error(Response errorResponse) {
            return new TokenExtractionResult(null, errorResponse);
        }

        boolean isError() {
            return errorResponse != null;
        }
    }
}

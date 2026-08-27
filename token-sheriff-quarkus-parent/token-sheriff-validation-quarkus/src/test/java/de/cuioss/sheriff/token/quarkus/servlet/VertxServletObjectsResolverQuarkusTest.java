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
package de.cuioss.sheriff.token.quarkus.servlet;

import de.cuioss.sheriff.token.quarkus.annotation.ServletObjectsResolver;
import de.cuioss.sheriff.token.quarkus.config.JwtTestProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Quarkus integration tests for {@link VertxServletObjectsResolver}.
 *
 * <p>These tests verify the functionality of the VertxServletObjectsResolver in a real Quarkus environment
 * with actual HTTP requests, using the {@link HttpRequestResolver} interface methods:
 * {@code resolveHeaderMap()}, {@code resolveRequestUri()}, and {@code resolveRequestMethod()}.</p>
 *
 * @author Oliver Wolff
 */
@QuarkusTest
@TestProfile(JwtTestProfile.class)
@DisplayName("VertxServletObjectsResolver Integration Tests")
class VertxServletObjectsResolverQuarkusTest {

    @Test
    @DisplayName("Should resolve headers, URI, and method during active REST request")
    void shouldResolveRequestDataDuringActiveRestRequest() {
        String response = given()
                .header("Authorization", "Bearer vertx-test-token")
                .header("X-Test-Header", "test-value")
                .when()
                .get("/test/vertx-resolver")
                .then()
                .statusCode(200)
                .contentType("text/plain")
                .extract()
                .asString();

        assertTrue(response.contains("HeaderMap available: true"),
                "HeaderMap should be available during active REST request");
        assertTrue(response.contains("HeaderCount: "),
                "Header count should be reported");
        assertTrue(response.contains("AuthHeader: Bearer vertx-test-token"),
                "Authorization header should be correctly retrieved");
        assertTrue(response.contains("RequestUri: http"),
                "Request URI should be available");
        assertTrue(response.contains("RequestMethod: GET"),
                "Request method should be available");
    }

    @Test
    @DisplayName("Should correctly handle request URI and method")
    void shouldHandleRequestUriAndMethod() {
        String response = given()
                .when()
                .get("/test/uri-method")
                .then()
                .statusCode(200)
                .contentType("text/plain")
                .extract()
                .asString();

        assertTrue(response.contains("URI: http"),
                "Request URI should contain scheme");
        assertTrue(response.contains("/test/uri-method"),
                "Request URI should contain path");
        assertTrue(response.contains("Method: GET"),
                "Request method should be correctly retrieved");
    }

    /**
     * Test endpoint that uses the Vertx servlet resolver during HTTP request.
     * This is a proper JAX-RS resource with @RequestScoped to ensure it's in the right context.
     */
    @Path("/test")
    @RequestScoped
    public static class TestEndpoint {

        @Inject
        @ServletObjectsResolver
        HttpRequestResolver resolver;

        @GET
        @Path("/vertx-resolver")
        @Produces(MediaType.TEXT_PLAIN)
        public Response testVertxResolver() {
            String result;
            try {
                Map<String, List<String>> headerMap = resolver.resolveHeaderMap();
                String requestUri = resolver.resolveRequestUri();
                String requestMethod = resolver.resolveRequestMethod();

                List<String> authValues = headerMap.get("authorization");
                String authHeader = authValues != null && !authValues.isEmpty() ? authValues.getFirst() : "null";

                result = "HeaderMap available: true, HeaderCount: %d, AuthHeader: %s, RequestUri: %s, RequestMethod: %s".formatted(
                        headerMap.size(), authHeader, requestUri, requestMethod);
            } catch (IllegalStateException e) {
                result = "HeaderMap available: false, HeaderCount: 0";
            }

            return Response.ok(result).build();
        }

        @GET
        @Path("/uri-method")
        @Produces(MediaType.TEXT_PLAIN)
        public Response testUriAndMethod() {
            try {
                String uri = resolver.resolveRequestUri();
                String method = resolver.resolveRequestMethod();

                String result = "URI: %s\nMethod: %s".formatted(uri, method);
                return Response.ok(result).build();
            } catch (IllegalStateException e) {
                return Response.serverError().entity("Error: " + e.getMessage()).build();
            }
        }
    }
}

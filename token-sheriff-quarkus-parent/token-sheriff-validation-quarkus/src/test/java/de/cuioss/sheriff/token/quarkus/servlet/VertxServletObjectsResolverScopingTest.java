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
import java.util.Set;
import java.util.concurrent.*;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test for verifying CDI scoping behavior of VertxServletObjectsResolver.
 *
 * <p>This test verifies that:</p>
 * <ul>
 *   <li>Instance&lt;HttpServerRequest&gt; correctly resolves per-request instances</li>
 *   <li>@ApplicationScoped VertxServletObjectsResolver handles concurrent requests safely</li>
 *   <li>No cross-request contamination occurs</li>
 *   <li>Request context isolation is maintained</li>
 * </ul>
 *
 * @author Oliver Wolff
 */
@QuarkusTest
@TestProfile(JwtTestProfile.class)
@DisplayName("VertxServletObjectsResolver CDI Scoping Tests")
class VertxServletObjectsResolverScopingTest {

    @Inject
    @ServletObjectsResolver
    HttpRequestResolver resolver;

    @Test
    @DisplayName("Should verify request isolation in single-threaded scenario")
    void shouldVerifyRequestIsolationSingleThreaded() {
        // Make multiple sequential requests and verify each gets its own request instance
        String firstResponse = given()
                .header("X-Request-ID", "request-1")
                .header("X-Test-Data", "data-1")
                .when()
                .get("/test/scoping/request-info")
                .then()
                .statusCode(200)
                .extract()
                .asString();

        String secondResponse = given()
                .header("X-Request-ID", "request-2")
                .header("X-Test-Data", "data-2")
                .when()
                .get("/test/scoping/request-info")
                .then()
                .statusCode(200)
                .extract()
                .asString();

        // Verify that each request got different data
        assertTrue(firstResponse.contains("request-1"), "First request should contain its own ID");
        assertTrue(firstResponse.contains("data-1"), "First request should contain its own data");

        assertTrue(secondResponse.contains("request-2"), "Second request should contain its own ID");
        assertTrue(secondResponse.contains("data-2"), "Second request should contain its own data");

        assertNotEquals(firstResponse, secondResponse, "Each request should get different responses");
    }

    @Test
    @DisplayName("Should verify request isolation in concurrent scenario")
    void shouldVerifyRequestIsolationConcurrent() throws Exception {
        final int numberOfRequests = 10;
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch completeLatch = new CountDownLatch(numberOfRequests);
        final ExecutorService executor = Executors.newFixedThreadPool(numberOfRequests);
        final Set<String> responses = ConcurrentHashMap.newKeySet();
        try {
            // Submit concurrent requests
            for (int i = 0; i < numberOfRequests; i++) {
                final String requestId = "concurrent-request-" + i;
                final String testData = "concurrent-data-" + i;

                executor.submit(() -> {
                    try {
                        startLatch.await(); // Wait for all threads to be ready

                        String response = given()
                                .header("X-Request-ID", requestId)
                                .header("X-Test-Data", testData)
                                .when()
                                .get("/test/scoping/request-info")
                                .then()
                                .statusCode(200)
                                .extract()
                                .asString();

                        responses.add(response);
                        return response;
                    } finally {
                        completeLatch.countDown();
                    }
                });
            }

            // Start all requests simultaneously
            startLatch.countDown();

            // Wait for all requests to complete
            assertTrue(completeLatch.await(30, TimeUnit.SECONDS),
                    "All concurrent requests should complete within 30 seconds");

            // Verify each request got its own data
            assertEquals(numberOfRequests, responses.size(),
                    "Should have received " + numberOfRequests + " unique responses");

            // Verify each response contains its own request-specific data
            for (int i = 0; i < numberOfRequests; i++) {
                final String expectedRequestId = "concurrent-request-" + i;
                final String expectedTestData = "concurrent-data-" + i;

                boolean foundMatchingResponse = responses.stream()
                        .anyMatch(response ->
                                response.contains(expectedRequestId) && response.contains(expectedTestData));

                assertTrue(foundMatchingResponse,
                        "Should find response containing " + expectedRequestId + " and " + expectedTestData);
            }

            // Verify no cross-contamination (no response should contain data from other requests)
            for (String response : responses) {
                String[] lines = response.split("\n");
                String requestIdLine = null;
                String testDataLine = null;

                for (String line : lines) {
                    if (line.startsWith("X-Request-ID:")) {
                        requestIdLine = line;
                    } else if (line.startsWith("X-Test-Data:")) {
                        testDataLine = line;
                    }
                }

                assertNotNull(requestIdLine, "Response should contain X-Request-ID");
                assertNotNull(testDataLine, "Response should contain X-Test-Data");

                // Extract the request number from both headers and verify they match
                String requestIdNumber = requestIdLine.replaceAll(".*concurrent-request-(\\d+).*", "$1");
                String testDataNumber = testDataLine.replaceAll(".*concurrent-data-(\\d+).*", "$1");

                assertEquals(requestIdNumber, testDataNumber,
                        "Request ID and test data should belong to the same request: " + response);
            }

        } finally {
            executor.shutdown();
        }
    }

    @Test
    @DisplayName("Should verify ApplicationScoped resolver instance reuse")
    void shouldVerifyApplicationScopedResolverInstanceReuse() {
        // Make multiple requests and verify the resolver instance itself is reused
        String firstResolverInfo = given()
                .when()
                .get("/test/scoping/resolver-info")
                .then()
                .statusCode(200)
                .extract()
                .asString();

        String secondResolverInfo = given()
                .when()
                .get("/test/scoping/resolver-info")
                .then()
                .statusCode(200)
                .extract()
                .asString();

        assertEquals(firstResolverInfo, secondResolverInfo,
                "ApplicationScoped resolver should be the same instance across requests");
    }

    /**
     * Test endpoint that demonstrates CDI scoping behavior.
     * This endpoint is RequestScoped to ensure proper request context handling.
     */
    @Path("/test/scoping")
    @RequestScoped
    public static class ScopingTestEndpoint {

        @Inject
        @ServletObjectsResolver
        HttpRequestResolver resolver;

        @GET
        @Path("/request-info")
        @Produces(MediaType.TEXT_PLAIN)
        public Response getRequestInfo() {
            try {
                Map<String, List<String>> headerMap = resolver.resolveHeaderMap();
                String requestUri = resolver.resolveRequestUri();
                String requestMethod = resolver.resolveRequestMethod();

                List<String> requestIdValues = headerMap.get("x-request-id");
                List<String> testDataValues = headerMap.get("x-test-data");

                StringBuilder info = new StringBuilder();
                info.append("Request Method: ").append(requestMethod).append("\n");
                info.append("Request URI: ").append(requestUri).append("\n");
                info.append("X-Request-ID: ").append(requestIdValues != null ? requestIdValues.getFirst() : "null").append("\n");
                info.append("X-Test-Data: ").append(testDataValues != null ? testDataValues.getFirst() : "null").append("\n");
                info.append("Thread: ").append(Thread.currentThread().getName()).append("\n");
                info.append("Timestamp: ").append(System.currentTimeMillis()).append("\n");

                return Response.ok(info.toString()).build();
            } catch (IllegalStateException e) {
                return Response.status(500)
                        .entity("Error resolving request: " + e.getMessage())
                        .build();
            }
        }

        @GET
        @Path("/resolver-info")
        @Produces(MediaType.TEXT_PLAIN)
        public Response getResolverInfo() {
            StringBuilder info = new StringBuilder();
            info.append("Resolver Instance: ").append(resolver.hashCode()).append("\n");
            info.append("Resolver Class: ").append(resolver.getClass().getName()).append("\n");
            info.append("Thread: ").append(Thread.currentThread().getName()).append("\n");

            return Response.ok(info.toString()).build();
        }
    }
}

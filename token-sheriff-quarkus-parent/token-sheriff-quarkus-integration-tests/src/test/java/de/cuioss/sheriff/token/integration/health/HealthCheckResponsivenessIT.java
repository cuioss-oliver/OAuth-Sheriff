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
package de.cuioss.sheriff.token.integration.health;

import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration test that validates health checks are responsive and do not exhibit blocking behavior.
 */
class HealthCheckResponsivenessIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(HealthCheckResponsivenessIT.class);
    private static final int MAX_ACCEPTABLE_RESPONSE_TIME_MS = 5000;
    private static final int CONCURRENT_HEALTH_CHECKS = 10;

    @Test
    void shouldHandleConcurrentHealthChecksWithoutBlocking() {
        LOGGER.debug("Testing concurrent health check responsiveness");

        List<HealthCheckTimingResult> results = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(CONCURRENT_HEALTH_CHECKS);

        try {
            List<Future<HealthCheckTimingResult>> futures = new ArrayList<>();

            for (int i = 1; i <= CONCURRENT_HEALTH_CHECKS; i++) {
                final int checkId = i;
                Future<HealthCheckTimingResult> future = executor.submit(() ->
                        performTimedHealthCheck("readiness", "/q/health/ready", checkId));
                futures.add(future);
            }

            for (int i = 0; i < futures.size(); i++) {
                try {
                    HealthCheckTimingResult result = futures.get(i).get(5, TimeUnit.SECONDS);
                    results.add(result);
                } catch (TimeoutException e) {
                    results.add(new HealthCheckTimingResult(i + 1, "readiness",
                            Duration.ofSeconds(5), false, "TIMEOUT"));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    results.add(new HealthCheckTimingResult(i + 1, "readiness",
                            Duration.ZERO, false, "INTERRUPTED"));
                } catch (ExecutionException e) {
                    results.add(new HealthCheckTimingResult(i + 1, "readiness",
                            Duration.ZERO, false, "ERROR"));
                }
            }
        } finally {
            executor.shutdown();
        }

        validateHealthCheckResponsiveness(results);
    }

    @Test
    void shouldRespondQuicklyForAllHealthCheckTypes() {
        List<HealthCheckType> healthCheckTypes = List.of(
                new HealthCheckType("liveness", "/q/health/live"),
                new HealthCheckType("readiness", "/q/health/ready"),
                new HealthCheckType("startup", "/q/health/started"),
                new HealthCheckType("overall", "/q/health")
        );

        for (HealthCheckType checkType : healthCheckTypes) {
            Instant start = Instant.now();

            String status = given()
                    .when()
                    .get(checkType.url)
                    .then()
                    .extract().path("status");

            Duration responseTime = Duration.between(start, Instant.now());

            assertTrue("UP".equals(status) || "DOWN".equals(status),
                    "Health check %s should return a valid status but was %s".formatted(
                            checkType.name, status));

            assertTrue(responseTime.toMillis() < MAX_ACCEPTABLE_RESPONSE_TIME_MS,
                    "Health check %s took %dms, exceeding max of %dms".formatted(
                            checkType.name, responseTime.toMillis(), MAX_ACCEPTABLE_RESPONSE_TIME_MS));
        }
    }

    private HealthCheckTimingResult performTimedHealthCheck(String type, String url, int checkId) {
        Instant startTime = Instant.now();

        String responseStatus = given()
                .when()
                .get(url)
                .then()
                .extract().path("status");

        Duration responseTime = Duration.between(startTime, Instant.now());
        return new HealthCheckTimingResult(checkId, type, responseTime,
                "UP".equals(responseStatus), responseStatus);
    }

    private void validateHealthCheckResponsiveness(List<HealthCheckTimingResult> results) {
        long slowResponses = results.stream()
                .filter(r -> r.responseTime.toMillis() > MAX_ACCEPTABLE_RESPONSE_TIME_MS)
                .count();

        Duration maxResponseTime = results.stream()
                .map(r -> r.responseTime)
                .max(Duration::compareTo)
                .orElse(Duration.ZERO);

        assertEquals(0, slowResponses, "%d health checks exceeded %dms response time limit".formatted(
                slowResponses, MAX_ACCEPTABLE_RESPONSE_TIME_MS));

        assertTrue(maxResponseTime.toMillis() <= MAX_ACCEPTABLE_RESPONSE_TIME_MS,
                "Maximum response time %dms exceeded limit of %dms".formatted(
                        maxResponseTime.toMillis(), MAX_ACCEPTABLE_RESPONSE_TIME_MS));
    }

    private record HealthCheckTimingResult(int checkId, String type, Duration responseTime,
    boolean success, String status) {
    }

    private record HealthCheckType(String name, String url) {
    }
}

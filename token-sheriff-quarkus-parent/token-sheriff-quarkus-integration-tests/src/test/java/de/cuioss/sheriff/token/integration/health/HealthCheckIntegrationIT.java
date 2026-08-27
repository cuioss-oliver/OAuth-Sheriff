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
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * REST API tests for health check endpoints against external application.
 * <p>
 * All configured issuers should be reachable:
 * <ul>
 *     <li>{@code integration-tests} profile: only Keycloak issuers (Dex disabled)</li>
 *     <li>{@code multi-idp-tests} profile: Keycloak + Dex (Dex enabled via {@code %multi-idp} Quarkus profile)</li>
 * </ul>
 */
class HealthCheckIntegrationIT extends BaseIntegrationTest {

    @Test
    void shouldProvideOverallHealthStatus() {
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .contentType("application/json")
                .body("status", equalTo("UP"));
    }

    @Test
    void shouldProvideReadinessCheck() {
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void shouldProvideLivenessCheck() {
        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void shouldProvideStartupCheck() {
        given()
                .when()
                .get("/q/health/started")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }
}

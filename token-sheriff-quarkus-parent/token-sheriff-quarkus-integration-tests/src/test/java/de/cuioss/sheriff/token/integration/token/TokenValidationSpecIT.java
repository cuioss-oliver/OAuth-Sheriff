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
package de.cuioss.sheriff.token.integration.token;

import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestProviders;
import de.cuioss.sheriff.token.integration.TestRealm;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static de.cuioss.sheriff.token.integration.TestConstants.*;
import static io.restassured.RestAssured.given;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Token validation spec — parameterized over all available OIDC providers.
 * Each {@code @ParameterizedTest} receives a {@link TestRealm} from
 * {@link de.cuioss.sheriff.token.integration.TestProviders#allProviders()}.
 * <p>
 * Tests cover provider-agnostic JWT validation: access tokens, ID tokens,
 * refresh tokens, basic interceptor, and error cases.
 */
@DisplayName("Token Validation Spec")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TokenValidationSpecIT extends BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidationSpecIT.class);

    static final String JWT_VALIDATE_ID_TOKEN_PATH = "/jwt/validate/id-token";
    static final String JWT_VALIDATE_REFRESH_TOKEN_PATH = "/jwt/validate/refresh-token";
    static final String ACCESS_TOKEN_VALID_MESSAGE = "Access token is valid";

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#jwtAccessTokenProviders")
    @Order(1)
    @DisplayName("Validate access token via Authorization header")
    void validateAccessToken(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        given()
                .contentType(CONTENT_TYPE_JSON)
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo(ACCESS_TOKEN_VALID_MESSAGE));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#allProviders")
    @Order(2)
    @DisplayName("Validate ID token via request body")
    void validateIdToken(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();
        // client_credentials grant (Zitadel) doesn't return an ID token
        Assumptions.assumeTrue(tokenResponse.idToken() != null,
                "Skipping ID token validation — " + realm + " did not return an ID token");

        given()
                .contentType(CONTENT_TYPE_JSON)
                .body(Map.of(TOKEN_FIELD_NAME, tokenResponse.idToken()))
                .when()
                .post(JWT_VALIDATE_ID_TOKEN_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("ID token is valid"));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#allProviders")
    @Order(3)
    @DisplayName("Validate refresh token — skip if provider doesn't issue one")
    void validateRefreshToken(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        Assumptions.assumeTrue(tokenResponse.refreshToken() != null,
                realm + " did not issue a refresh token");

        given()
                .contentType(CONTENT_TYPE_JSON)
                .body(Map.of(TOKEN_FIELD_NAME, tokenResponse.refreshToken()))
                .when()
                .post(JWT_VALIDATE_REFRESH_TOKEN_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Refresh token is valid"));
    }

    @TestFactory
    @Order(4)
    @DisplayName("Validate refresh token with offline_access scope")
    void validateRefreshTokenWithOfflineAccess() {
        TestProviders.offlineAccessProviders()
                .map(realm -> DynamicTest.dynamicTest("[" + realm + "]", () -> {
                    var tokenResponse = realm.obtainValidTokenWithScopes(
                            "openid profile email offline_access");
                    assertNotNull(tokenResponse.refreshToken(),
                            realm + " should issue refresh token with offline_access scope");

                    given()
                            .contentType(CONTENT_TYPE_JSON)
                            .body(Map.of(TOKEN_FIELD_NAME, tokenResponse.refreshToken()))
                            .when()
                            .post(JWT_VALIDATE_REFRESH_TOKEN_PATH)
                            .then()
                            .statusCode(200)
                            .body("valid", equalTo(true))
                            .body("message", equalTo("Refresh token is valid"));
                }));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#jwtAccessTokenProviders")
    @Order(5)
    @DisplayName("Validate access token with multiple consecutive requests")
    void validateAccessTokenMultipleRequests(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        for (int i = 0; i < 3; i++) {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                    .when()
                    .post(JWT_VALIDATE_PATH)
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true))
                    .body("message", equalTo(ACCESS_TOKEN_VALID_MESSAGE));
        }
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#jwtAccessTokenProviders")
    @Order(6)
    @DisplayName("Basic interceptor validation — any valid token")
    void interceptorValidationBasic(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/interceptor/basic")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Interceptor validation successful (basic)"));
    }

    @Test
    @Order(10)
    @DisplayName("Missing token returns 401")
    void missingTokenReturns401() {
        given()
                .contentType(CONTENT_TYPE_JSON)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401)
                .body("valid", equalTo(false));
    }

    @Test
    @Order(11)
    @DisplayName("Invalid token returns 401")
    void invalidTokenReturns401() {
        given()
                .contentType(CONTENT_TYPE_JSON)
                .header(AUTHORIZATION, BEARER_PREFIX + "invalid.token.here")
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401)
                .body("valid", equalTo(false));
    }

    @Test
    @Order(99)
    @DisplayName("Verify SecurityEventCounter metrics have sensible bounds after all tests")
    void verifySecurityEventCounterMetrics() {
        LOGGER.debug("Verifying SecurityEventCounter metrics bounds after all integration tests");

        await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofSeconds(1))
                .until(() -> {
                    String response = given()
                            .when()
                            .get("/q/metrics")
                            .then()
                            .statusCode(200)
                            .extract()
                            .body()
                            .asString();
                    return response.contains("sheriff_token_validation");
                });

        String metricsResponse = given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .asString();

        assertTrue(metricsResponse.contains("sheriff_token_validation_errors_total"),
                "Should contain error metrics");

        boolean hasSuccessMetrics = metricsResponse.contains("sheriff_token_validation_success_total");

        Map<String, Double> parsedMetrics = parseMetricsResponse(metricsResponse);

        if (hasSuccessMetrics) {
            double accessTokensCreated = getMetricValue(parsedMetrics,
                    "sheriff_token_validation_success_total", "ACCESS_TOKEN_CREATED");
            assertTrue(accessTokensCreated >= 10,
                    "Should have created at least 10 access tokens, got: " + accessTokensCreated);
            assertTrue(accessTokensCreated <= 10000,
                    "Access token creation count seems unreasonably high: " + accessTokensCreated);

            double accessTokenCacheHits = getMetricValue(parsedMetrics,
                    "sheriff_token_validation_success_total", "ACCESS_TOKEN_CACHE_HIT");
            assertTrue(accessTokenCacheHits >= 0,
                    "Cache hits should be non-negative: " + accessTokenCacheHits);

            double totalSuccess = accessTokensCreated + accessTokenCacheHits
                    + getMetricValue(parsedMetrics, "sheriff_token_validation_success_total", "ID_TOKEN_CREATED")
                    + getMetricValue(parsedMetrics, "sheriff_token_validation_success_total", "REFRESH_TOKEN_CREATED");
            assertTrue(totalSuccess >= 10,
                    "Total successful operations should be at least 10: " + totalSuccess);
        } else {
            assertFalse(parsedMetrics.isEmpty(), "Should have some metrics available");
        }
    }

    private Map<String, Double> parseMetricsResponse(String metricsResponse) {
        Map<String, Double> metrics = new HashMap<>();
        for (String line : metricsResponse.split("\n")) {
            line = line.trim();
            if (line.startsWith("#") || line.isEmpty()) {
                continue;
            }
            int spaceIndex = line.lastIndexOf(' ');
            if (spaceIndex > 0) {
                try {
                    metrics.put(line.substring(0, spaceIndex),
                            Double.parseDouble(line.substring(spaceIndex + 1)));
                } catch (NumberFormatException e) {
                    // Ignore invalid metrics
                }
            }
        }
        return metrics;
    }

    private double getMetricValue(Map<String, Double> metrics, String metricPrefix, String eventType) {
        for (var entry : metrics.entrySet()) {
            if (entry.getKey().startsWith(metricPrefix)
                    && entry.getKey().contains("event_type=\"" + eventType + "\"")) {
                return entry.getValue();
            }
        }
        return 0.0;
    }
}

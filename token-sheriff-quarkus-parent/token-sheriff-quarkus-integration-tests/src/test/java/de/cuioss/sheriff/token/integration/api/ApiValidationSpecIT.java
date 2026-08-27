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
package de.cuioss.sheriff.token.integration.api;

import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import org.junit.jupiter.api.*;

import java.util.Map;

import static de.cuioss.sheriff.token.integration.TestConstants.*;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * API contract spec — provider-independent input validation tests.
 * Tests null, empty, blank string handling and basic input validation.
 */
@DisplayName("API Validation Spec")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ApiValidationSpecIT extends BaseIntegrationTest {

    private static final String JWT_VALIDATE_EXPLICIT_PATH = "/jwt/validate-explicit";
    private static final String JWT_VALIDATE_ID_TOKEN_PATH = "/jwt/validate/id-token";
    private static final String JWT_VALIDATE_REFRESH_TOKEN_PATH = "/jwt/validate/refresh-token";

    @Nested
    @DisplayName("Missing Request Body Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class MissingRequestBodyTests {

        @Test
        @Order(1)
        @DisplayName("validateExplicitToken should return 400 for missing request body")
        void validateExplicitTokenMissingBody() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .when()
                    .post(JWT_VALIDATE_EXPLICIT_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty access token in request body"));
        }

        @Test
        @Order(2)
        @DisplayName("validateIdToken should return 400 for missing request body")
        void validateIdTokenMissingBody() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .when()
                    .post(JWT_VALIDATE_ID_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty ID token in request body"));
        }

        @Test
        @Order(3)
        @DisplayName("validateRefreshToken should return 400 for missing request body")
        void validateRefreshTokenMissingBody() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .when()
                    .post(JWT_VALIDATE_REFRESH_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty refresh token in request body"));
        }
    }

    @Nested
    @DisplayName("Empty Token Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class EmptyTokenTests {

        @Test
        @Order(10)
        @DisplayName("validateExplicitToken should return 400 for empty token")
        void validateExplicitTokenEmptyToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, ""))
                    .when()
                    .post(JWT_VALIDATE_EXPLICIT_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty access token in request body"));
        }

        @Test
        @Order(11)
        @DisplayName("validateIdToken should return 400 for empty token")
        void validateIdTokenEmptyToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, ""))
                    .when()
                    .post(JWT_VALIDATE_ID_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty ID token in request body"));
        }

        @Test
        @Order(12)
        @DisplayName("validateRefreshToken should return 400 for empty token")
        void validateRefreshTokenEmptyToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, ""))
                    .when()
                    .post(JWT_VALIDATE_REFRESH_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty refresh token in request body"));
        }
    }

    @Nested
    @DisplayName("Whitespace Token Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class WhitespaceTokenTests {

        @Test
        @Order(20)
        @DisplayName("validateExplicitToken should return 400 for whitespace-only token")
        void validateExplicitTokenWhitespaceToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, "   "))
                    .when()
                    .post(JWT_VALIDATE_EXPLICIT_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty access token in request body"));
        }

        @Test
        @Order(21)
        @DisplayName("validateIdToken should return 400 for whitespace-only token")
        void validateIdTokenWhitespaceToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, "   "))
                    .when()
                    .post(JWT_VALIDATE_ID_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty ID token in request body"));
        }

        @Test
        @Order(22)
        @DisplayName("validateRefreshToken should return 400 for whitespace-only token")
        void validateRefreshTokenWhitespaceToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, "   "))
                    .when()
                    .post(JWT_VALIDATE_REFRESH_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty refresh token in request body"));
        }

        @Test
        @Order(23)
        @DisplayName("validateExplicitToken should return 400 for tab and newline whitespace")
        void validateExplicitTokenTabNewlineWhitespace() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, "\t\n  "))
                    .when()
                    .post(JWT_VALIDATE_EXPLICIT_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty access token in request body"));
        }
    }

    @Nested
    @DisplayName("Null Token Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class NullTokenTests {

        @Test
        @Order(30)
        @DisplayName("validateExplicitToken should handle null token field gracefully")
        void validateExplicitTokenNullToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body("{\"token\": null}")
                    .when()
                    .post(JWT_VALIDATE_EXPLICIT_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty access token in request body"));
        }

        @Test
        @Order(31)
        @DisplayName("validateIdToken should handle null token field gracefully")
        void validateIdTokenNullToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body("{\"token\": null}")
                    .when()
                    .post(JWT_VALIDATE_ID_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty ID token in request body"));
        }

        @Test
        @Order(32)
        @DisplayName("validateRefreshToken should handle null token field gracefully")
        void validateRefreshTokenNullToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body("{\"token\": null}")
                    .when()
                    .post(JWT_VALIDATE_REFRESH_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty refresh token in request body"));
        }
    }

    @Nested
    @DisplayName("Malformed JSON Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class MalformedJsonTests {

        @Test
        @Order(40)
        @DisplayName("validateExplicitToken should handle malformed JSON gracefully")
        void validateExplicitTokenMalformedJson() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body("{\"invalid\":\"json\"}")
                    .when()
                    .post(JWT_VALIDATE_EXPLICIT_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty access token in request body"));
        }

        @Test
        @Order(41)
        @DisplayName("validateIdToken should handle missing token field gracefully")
        void validateIdTokenMissingTokenField() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body("{\"notToken\": \"someValue\"}")
                    .when()
                    .post(JWT_VALIDATE_ID_TOKEN_PATH)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo("Missing or empty ID token in request body"));
        }
    }

    @Nested
    @DisplayName("Invalid Token Format Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class InvalidTokenFormatTests {

        @Test
        @Order(50)
        @DisplayName("validateExplicitToken should return 401 for invalid token format")
        void validateExplicitTokenInvalidFormat() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, "invalid.token.here"))
                    .when()
                    .post(JWT_VALIDATE_EXPLICIT_PATH)
                    .then()
                    .statusCode(401)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, containsString("Token validation failed"));
        }

        @Test
        @Order(51)
        @DisplayName("validateIdToken should return 401 for invalid token format")
        void validateIdTokenInvalidFormat() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, "invalid.token.here"))
                    .when()
                    .post(JWT_VALIDATE_ID_TOKEN_PATH)
                    .then()
                    .statusCode(401)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, containsString("ID token validation failed"));
        }

        @Test
        @Order(52)
        @DisplayName("validateRefreshToken should return 200 for refresh token (opaque validation)")
        void validateRefreshTokenOpaqueValidation() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, "invalid.token.here"))
                    .when()
                    .post(JWT_VALIDATE_REFRESH_TOKEN_PATH)
                    .then()
                    .statusCode(200)
                    .body(VALID, equalTo(true))
                    .body(MESSAGE, containsString("Refresh token is valid"));
        }
    }

    @Nested
    @DisplayName("Bearer Token Authorization Header Tests")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class BearerTokenAuthorizationTests {

        @Test
        @Order(60)
        @DisplayName("validateToken should return 401 for missing Authorization header")
        void validateTokenMissingAuthorizationHeader() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .when()
                    .post(JWT_VALIDATE_PATH)
                    .then()
                    .statusCode(401)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, containsString("Bearer token validation failed"));
        }

        @Test
        @Order(61)
        @DisplayName("validateToken should return 401 for invalid Authorization header format")
        void validateTokenInvalidAuthorizationHeader() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .header(AUTHORIZATION, "InvalidFormat token")
                    .when()
                    .post(JWT_VALIDATE_PATH)
                    .then()
                    .statusCode(401)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, containsString("Bearer token validation failed"));
        }

        @Test
        @Order(62)
        @DisplayName("validateToken should return 401 for invalid token in Authorization header")
        void validateTokenInvalidAuthorizationToken() {
            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .header(AUTHORIZATION, BEARER_PREFIX + "invalid.token.here")
                    .when()
                    .post(JWT_VALIDATE_PATH)
                    .then()
                    .statusCode(401)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, containsString("Bearer token validation failed"));
        }
    }

    @Test
    @Order(100)
    @DisplayName("TokenRequest.isEmpty() consistency test across all endpoints")
    void tokenRequestIsEmptyConsistency() {
        String[] endpoints = {
                JWT_VALIDATE_EXPLICIT_PATH,
                JWT_VALIDATE_ID_TOKEN_PATH,
                JWT_VALIDATE_REFRESH_TOKEN_PATH
        };

        String[] expectedMessages = {
                "Missing or empty access token in request body",
                "Missing or empty ID token in request body",
                "Missing or empty refresh token in request body"
        };

        for (int i = 0; i < endpoints.length; i++) {
            String endpoint = endpoints[i];
            String expectedMessage = expectedMessages[i];

            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, ""))
                    .when()
                    .post(endpoint)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo(expectedMessage));

            given()
                    .contentType(CONTENT_TYPE_JSON)
                    .body(Map.of(TOKEN_FIELD_NAME, "  \t  "))
                    .when()
                    .post(endpoint)
                    .then()
                    .statusCode(400)
                    .body(VALID, equalTo(false))
                    .body(MESSAGE, equalTo(expectedMessage));
        }
    }
}

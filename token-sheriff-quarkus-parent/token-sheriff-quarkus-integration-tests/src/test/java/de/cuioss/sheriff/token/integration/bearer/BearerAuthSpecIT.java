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
package de.cuioss.sheriff.token.integration.bearer;

import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collection;

import static de.cuioss.sheriff.token.integration.TestConstants.AUTHORIZATION;
import static de.cuioss.sheriff.token.integration.TestConstants.BEARER_PREFIX;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Bearer auth spec — parameterized over providers with matching capabilities.
 * Tests are split by capability gate so providers like Zitadel (roles + groups
 * but no custom scopes) participate in roles-only and groups-only tests while
 * only Keycloak runs the full with-all suite.
 */
@DisplayName("Bearer Auth Spec")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class BearerAuthSpecIT extends BaseIntegrationTest {


    // === Bearer Token Producer Tests ===

    @ParameterizedTest(name = "[{0}] {1}")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#customScopesProviders")
    @Order(1)
    @DisplayName("Bearer token producer — with-scopes")
    void bearerTokenWithScopes(TestRealm realm) {
        var tokenResponse = realm.obtainValidTokenWithAllScopes();
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/bearer-token/with-scopes")
                .then()
                .statusCode(200);
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#rolesProviders")
    @Order(2)
    @DisplayName("Bearer token producer — with-roles")
    void bearerTokenWithRoles(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/bearer-token/with-roles")
                .then()
                .statusCode(200);
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#groupsProviders")
    @Order(3)
    @DisplayName("Bearer token producer — with-groups")
    void bearerTokenWithGroups(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/bearer-token/with-groups")
                .then()
                .statusCode(200);
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#bearerAuthProviders")
    @Order(4)
    @DisplayName("Bearer token producer — with-all")
    void bearerTokenWithAll(TestRealm realm) {
        var tokenResponse = realm.obtainValidTokenWithAllScopes();
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/bearer-token/with-all")
                .then()
                .statusCode(200);
    }

    // === Bearer Token Interceptor Tests ===

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#customScopesProviders")
    @Order(10)
    @DisplayName("Interceptor — with scopes")
    void interceptorWithScopes(TestRealm realm) {
        var tokenResponse = realm.obtainValidTokenWithAllScopes();
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/interceptor/with-scopes")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Interceptor validation successful (with scopes)"));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#rolesProviders")
    @Order(11)
    @DisplayName("Interceptor — with roles")
    void interceptorWithRoles(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/interceptor/with-roles")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Interceptor validation successful (with roles)"));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#groupsProviders")
    @Order(12)
    @DisplayName("Interceptor — with groups")
    void interceptorWithGroups(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/interceptor/with-groups")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Interceptor validation successful (with groups)"));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#bearerAuthProviders")
    @Order(13)
    @DisplayName("Interceptor — with all requirements")
    void interceptorWithAll(TestRealm realm) {
        var tokenResponse = realm.obtainValidTokenWithAllScopes();
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/interceptor/with-all")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Interceptor validation successful (with all requirements)"));
    }

    @ParameterizedTest(name = "[{0}] {1}")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#bearerAuthProviders")
    @Order(14)
    @DisplayName("Interceptor — default permissions succeed (all capabilities)")
    void interceptorDefaultPermissions(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        for (String endpoint : new String[]{
                "/jwt/interceptor/with-scopes",
                "/jwt/interceptor/with-roles",
                "/jwt/interceptor/with-groups"}) {
            given()
                    .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                    .when()
                    .get(endpoint)
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true));
        }
    }

    // === CDI Token Access Tests ===

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#bearerAuthProviders")
    @Order(20)
    @DisplayName("CDI token access — validates userId, scopes, roles, groups")
    void cdiTokenAccess(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        var response = given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/interceptor/with-token-access")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Token access successful"))
                .extract()
                .response();

        var data = response.jsonPath().getMap("data");
        assertNotNull(data, "Response data should not be null");

        String userId = (String) data.get("userId");
        assertNotNull(userId, "userId should be present");
        assertFalse(userId.isBlank(), "userId should not be blank");

        @SuppressWarnings("unchecked")
        var scopes = (Collection<String>) data.get("scopes");
        assertNotNull(scopes, "scopes should be present");
        assertTrue(scopes.contains("read"), "scopes should contain 'read'");

        assertNotNull(data.get("roles"), "roles should be present");
        assertNotNull(data.get("groups"), "groups should be present");
    }

    // === String Return Type Tests ===

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#customScopesProviders")
    @Order(30)
    @DisplayName("Interceptor — String return type success")
    void stringReturnSuccess(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        String response = given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/interceptor/string-return")
                .then()
                .statusCode(200)
                .contentType("text/plain")
                .extract()
                .asString();

        assertEquals("String return type validation successful", response);
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("de.cuioss.sheriff.token.integration.TestProviders#customScopesProviders")
    @Order(31)
    @DisplayName("Interceptor — String return type failure throws WebApplicationException")
    void stringReturnFailure(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        given()
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .get("/jwt/interceptor/string-return-fail")
                .then()
                .statusCode(401);
    }

    // === Missing/Invalid Token Tests ===

    @Test
    @Order(40)
    @DisplayName("Interceptor — missing token returns 401")
    void interceptorMissingToken() {
        given()
                .when()
                .get("/jwt/interceptor/basic")
                .then()
                .statusCode(401);
    }

    @Test
    @Order(41)
    @DisplayName("Interceptor — invalid token returns 401")
    void interceptorInvalidToken() {
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + "invalid.token.here")
                .when()
                .get("/jwt/interceptor/basic")
                .then()
                .statusCode(401);
    }

    @Test
    @Order(42)
    @DisplayName("Interceptor — String return missing token returns 401")
    void stringReturnMissingToken() {
        given()
                .when()
                .get("/jwt/interceptor/string-return")
                .then()
                .statusCode(401);
    }

    @Test
    @Order(43)
    @DisplayName("CDI injection — missing token returns 401")
    void cdiMissingToken() {
        given()
                .when()
                .get("/jwt/interceptor/with-token-access")
                .then()
                .statusCode(401);
    }

    @Test
    @Order(44)
    @DisplayName("CDI injection — invalid token returns 401")
    void cdiInvalidToken() {
        given()
                .header(AUTHORIZATION, BEARER_PREFIX + "invalid.jwt.token")
                .when()
                .get("/jwt/interceptor/with-token-access")
                .then()
                .statusCode(401);
    }
}

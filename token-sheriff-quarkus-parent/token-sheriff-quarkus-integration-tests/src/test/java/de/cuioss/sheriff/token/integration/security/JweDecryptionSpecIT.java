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
package de.cuioss.sheriff.token.integration.security;

import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static de.cuioss.sheriff.token.integration.TestConstants.*;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * JWE decryption spec (RFC 7516) — parameterized over JWE-capable providers.
 * Currently only Keycloak's {@code jwe-client} supports encrypted ID tokens,
 * but the design accommodates future JWE-capable providers.
 */
@DisplayName("JWE Decryption Spec (RFC 7516)")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JweDecryptionSpecIT extends BaseIntegrationTest {

    private static final String ID_TOKEN_VALIDATE_PATH = "/jwt/validate/id-token";

    static Stream<TestRealm> jweProviders() {
        // Add future JWE-capable providers here
        return Stream.of(TestRealm.createJweRealm());
    }

    // === Positive Tests ===

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("jweProviders")
    @Order(1)
    @DisplayName("Should obtain tokens — ID token is JWE, access token is JWS")
    void shouldObtainTokensFromJweClient(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();
        assertNotNull(tokenResponse.accessToken(), "Access token should not be null");
        assertNotNull(tokenResponse.idToken(), "ID token should not be null");

        // Verify ID token is JWE (5 parts)
        String idToken = tokenResponse.idToken();
        int dotCount = idToken.split("\\.", -1).length - 1;
        assertEquals(4, dotCount,
                "ID token should be JWE (5 parts, 4 dots), got " + (dotCount + 1) + " parts");

        // Access token remains JWS (3 parts)
        String accessToken = tokenResponse.accessToken();
        int accessDotCount = accessToken.split("\\.", -1).length - 1;
        assertEquals(2, accessDotCount,
                "Access token should remain JWS (3 parts), got " + (accessDotCount + 1) + " parts");
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("jweProviders")
    @Order(2)
    @DisplayName("Should validate JWE-encrypted ID token")
    void shouldValidateJweEncryptedIdToken(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        given()
                .contentType("application/json")
                .body(Map.of("token", tokenResponse.idToken()))
                .when()
                .post(ID_TOKEN_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("ID token is valid"));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("jweProviders")
    @Order(3)
    @DisplayName("Should validate access token from JWE-enabled client (stays JWS)")
    void shouldValidateAccessTokenFromJweClient(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Access token is valid"));
    }

    @Test
    @Order(4)
    @DisplayName("Should still validate regular JWS tokens when JWE config is present")
    void shouldStillValidateRegularJwsTokens() {
        var tokenResponse = TestRealm.createIntegrationRealm().obtainValidToken();

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("jweProviders")
    @Order(5)
    @DisplayName("Should validate JWE ID token multiple times (cache integration)")
    void shouldValidateJweIdTokenMultipleTimes(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();

        for (int i = 0; i < 3; i++) {
            given()
                    .contentType("application/json")
                    .body(Map.of("token", tokenResponse.idToken()))
                    .when()
                    .post(ID_TOKEN_VALIDATE_PATH)
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true));
        }
    }

    // === Negative Tests ===

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("jweProviders")
    @Order(10)
    @DisplayName("Should reject tampered JWE token")
    void shouldRejectTamperedJweToken(TestRealm realm) {
        var tokenResponse = realm.obtainValidToken();
        String idToken = tokenResponse.idToken();

        String[] parts = idToken.split("\\.");
        assertEquals(5, parts.length, "Should be 5-part JWE");
        char[] cipherChars = parts[3].toCharArray();
        cipherChars[0] = cipherChars[0] == 'A' ? 'B' : 'A';
        parts[3] = new String(cipherChars);
        String tamperedToken = String.join(".", parts);

        given()
                .contentType("application/json")
                .body(Map.of("token", tamperedToken))
                .when()
                .post(ID_TOKEN_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }
}

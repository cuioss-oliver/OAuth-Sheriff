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
import io.restassured.RestAssured;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.UUID;
import java.util.stream.Stream;

import static de.cuioss.sheriff.token.integration.TestConstants.*;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * DPoP (RFC 9449) spec — parameterized over DPoP-capable providers.
 * Currently only Keycloak's {@code dpop-client} supports DPoP, but the design
 * accommodates future DPoP-capable providers (Zitadel, etc.).
 */
@DisplayName("DPoP Spec (RFC 9449)")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DpopSpecIT extends BaseIntegrationTest {


    private static String resourceUri() {
        return RestAssured.baseURI + ":" + RestAssured.port + JWT_VALIDATE_PATH;
    }

    static Stream<TestRealm> dpopProviders() {
        // Add future DPoP-capable providers here
        return Stream.of(TestRealm.createDpopRealm());
    }

    // === Positive Tests ===

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("dpopProviders")
    @Order(1)
    @DisplayName("Should obtain DPoP-bound token")
    void shouldObtainDpopBoundToken(TestRealm realm) {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = realm.obtainDpopBoundToken(dpopHelper);
        assertNotNull(tokenResponse.accessToken(), "DPoP-bound access token should not be null");
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("dpopProviders")
    @Order(2)
    @DisplayName("Should validate DPoP-bound token with valid proof")
    void shouldValidateDpopBoundToken(TestRealm realm) {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = realm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();
        String resourceProof = dpopHelper.createResourceProof(accessToken, "POST", resourceUri());

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", resourceProof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Access token is valid"));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("dpopProviders")
    @Order(3)
    @DisplayName("Should validate multiple requests with fresh DPoP proofs")
    void shouldValidateMultipleRequestsWithFreshProofs(TestRealm realm) {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = realm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        for (int i = 0; i < 3; i++) {
            String freshProof = dpopHelper.createResourceProof(accessToken, "POST", resourceUri());
            given()
                    .contentType("application/json")
                    .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                    .header("DPoP", freshProof)
                    .when()
                    .post(JWT_VALIDATE_PATH)
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true));
        }
    }

    @Test
    @Order(4)
    @DisplayName("Should still accept bearer token without DPoP (dpop.required=false)")
    void shouldStillAcceptBearerTokenWithoutDpop() {
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

    // === Negative Tests ===

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("dpopProviders")
    @Order(10)
    @DisplayName("Should reject DPoP-bound token without DPoP header")
    void shouldRejectDpopTokenWithoutDpopHeader(TestRealm realm) {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = realm.obtainDpopBoundToken(dpopHelper);

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("dpopProviders")
    @Order(11)
    @DisplayName("Should reject DPoP proof signed with wrong key")
    void shouldRejectDpopTokenWithWrongKey(TestRealm realm) {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = realm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        var wrongKeyHelper = DpopProofHelper.createWithDifferentKey();
        String wrongProof = wrongKeyHelper.createResourceProof(accessToken, "POST", resourceUri());

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", wrongProof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("dpopProviders")
    @Order(12)
    @DisplayName("Should reject replayed DPoP proof (same jti)")
    void shouldRejectReplayedDpopProof(TestRealm realm) {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = realm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        String fixedJti = "replay-test-" + UUID.randomUUID();
        String proof = dpopHelper.createResourceProofWithJti(accessToken, fixedJti, "POST", resourceUri());

        // First request — should succeed
        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", proof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(200);

        // Second request with same proof (same jti) — should be rejected
        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", proof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("dpopProviders")
    @Order(13)
    @DisplayName("Should reject stale DPoP proof (iat too old)")
    void shouldRejectStaleDpopProof(TestRealm realm) {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = realm.obtainDpopBoundToken(dpopHelper);
        String accessToken = tokenResponse.accessToken();

        long staleIat = (System.currentTimeMillis() / 1000) - 600;
        String staleProof = dpopHelper.createResourceProofWithIat(accessToken, staleIat);

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + accessToken)
                .header("DPoP", staleProof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("dpopProviders")
    @Order(14)
    @DisplayName("Should reject DPoP proof with wrong ath")
    void shouldRejectDpopProofWithWrongAth(TestRealm realm) {
        var dpopHelper = new DpopProofHelper();
        var tokenResponse = realm.obtainDpopBoundToken(dpopHelper);

        String wrongAth = "dGhpc19pc19hX3dyb25nX2F0aF92YWx1ZQ";
        String wrongAthProof = dpopHelper.createResourceProofWithAth(wrongAth);

        given()
                .contentType("application/json")
                .header(AUTHORIZATION, BEARER_PREFIX + tokenResponse.accessToken())
                .header("DPoP", wrongAthProof)
                .when()
                .post(JWT_VALIDATE_PATH)
                .then()
                .statusCode(401);
    }
}

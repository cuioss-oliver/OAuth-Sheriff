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
 * TokenRequest integration spec — tests TokenRequest record deserialization and isEmpty() logic.
 */
@DisplayName("TokenRequest Spec")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TokenRequestSpecIT extends BaseIntegrationTest {


    @Test
    @Order(1)
    @DisplayName("TokenRequest record should be properly deserialized from JSON")
    void tokenRequestDeserialization() {
        given()
                .contentType(CONTENT_TYPE_JSON)
                .body(Map.of(TOKEN_FIELD_NAME, "test.token.value"))
                .when()
                .post("/jwt/validate-explicit")
                .then()
                .statusCode(401)
                .body(VALID, equalTo(false))
                .body(MESSAGE, containsString("Token validation failed"));
    }

    @Test
    @Order(2)
    @DisplayName("TokenRequest.isEmpty() should work correctly with token trimming")
    void tokenRequestIsEmptyWithTokenTrimming() {
        given()
                .contentType(CONTENT_TYPE_JSON)
                .body(Map.of(TOKEN_FIELD_NAME, "  valid.token.value  "))
                .when()
                .post("/jwt/validate-explicit")
                .then()
                .statusCode(401)
                .body(VALID, equalTo(false))
                .body(MESSAGE, containsString("Token validation failed"));
    }
}

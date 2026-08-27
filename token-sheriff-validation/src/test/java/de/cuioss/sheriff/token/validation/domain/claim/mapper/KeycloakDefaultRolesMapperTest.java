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
package de.cuioss.sheriff.token.validation.domain.claim.mapper;

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValueType;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests KeycloakDefaultRolesMapper functionality")
class KeycloakDefaultRolesMapperTest {

    private static final String CLAIM_NAME = "roles";
    private final KeycloakDefaultRolesMapper underTest = new KeycloakDefaultRolesMapper();

    /**
     * Converts a JsonObject to MapRepresentation using DSL-JSON parsing.
     * This ensures proper DSL-JSON validation and type handling.
     */
    private static MapRepresentation convertJsonObjectToMapRepresentation(JsonObject jsonObject) {
        try {
            String json = jsonObject.toString();
            DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
            return MapRepresentation.fromJson(dslJson, json);
        } catch (IOException e) {
            throw new AssertionError("Failed to convert JsonObject to MapRepresentation", e);
        }
    }

    @Test
    @DisplayName("Map realm_access.roles to roles claim")
    void shouldMapRealmAccessRoles() {
        List<String> expectedRoles = List.of("user", "admin", "read-only");
        JsonObject jsonObject = createKeycloakTokenWithRealmRoles(expectedRoles);

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNotNull(result);
        assertEquals(ClaimValueType.STRING_LIST, result.getType());
        assertEquals(expectedRoles, result.getAsList());
        assertNotNull(result.getOriginalString());
    }

    @Test
    @DisplayName("Handle missing realm_access claim")
    void shouldHandleMissingRealmAccess() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .add("iss", "https://keycloak.example.com")
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNull(result, "Should return null for missing realm_access claim");
    }

    @Test
    @DisplayName("Handle realm_access without roles")
    void shouldHandleRealmAccessWithoutRoles() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .add("realm_access", Json.createObjectBuilder()
                        .add("verify_caller", true)
                        .build())
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNull(result, "Should return null when realm_access has no roles");
    }

    @Test
    @DisplayName("Handle empty roles array")
    void shouldHandleEmptyRolesArray() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .add("realm_access", Json.createObjectBuilder()
                        .add("roles", Json.createArrayBuilder().build())
                        .build())
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNotNull(result);
        assertEquals(ClaimValueType.STRING_LIST, result.getType());
        assertTrue(result.getAsList().isEmpty());
        assertEquals("[]", result.getOriginalString());
    }

    @Test
    @DisplayName("Handle non-object realm_access")
    void shouldHandleNonObjectRealmAccess() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .add("realm_access", "invalid")
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNull(result, "Should return null for non-object realm_access");
    }

    @Test
    @DisplayName("Handle non-array roles value")
    void shouldHandleNonArrayRoles() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .add("realm_access", Json.createObjectBuilder()
                        .add("roles", "user")
                        .build())
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNull(result, "Should return null for non-array roles value");
    }

    @Test
    @DisplayName("Handle null realm_access")
    void shouldHandleNullRealmAccess() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .addNull("realm_access")
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNull(result, "Should return null for null realm_access");
    }

    @Test
    @DisplayName("Handle single role in array")
    void shouldHandleSingleRole() {
        List<String> expectedRoles = List.of("user");
        JsonObject jsonObject = createKeycloakTokenWithRealmRoles(expectedRoles);

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNotNull(result);
        assertEquals(ClaimValueType.STRING_LIST, result.getType());
        assertEquals(expectedRoles, result.getAsList());
        assertEquals(1, result.getAsList().size());
        assertEquals("user", result.getAsList().getFirst());
    }

    @Test
    @DisplayName("Handle complex role names")
    void shouldHandleComplexRoleNames() {
        List<String> expectedRoles = List.of("realm-admin", "account-view-profile", "offline_access");
        JsonObject jsonObject = createKeycloakTokenWithRealmRoles(expectedRoles);

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNotNull(result);
        assertEquals(ClaimValueType.STRING_LIST, result.getType());
        assertEquals(expectedRoles, result.getAsList());
    }

    private JsonObject createKeycloakTokenWithRealmRoles(List<String> roles) {
        JsonArrayBuilder rolesArrayBuilder = Json.createArrayBuilder();
        roles.forEach(rolesArrayBuilder::add);

        return Json.createObjectBuilder()
                .add("sub", "user123")
                .add("iss", "https://keycloak.example.com")
                .add("realm_access", Json.createObjectBuilder()
                        .add("roles", rolesArrayBuilder.build())
                        .build())
                .build();
    }
}
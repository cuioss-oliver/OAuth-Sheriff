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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests KeycloakDefaultGroupsMapper functionality")
class KeycloakDefaultGroupsMapperTest {

    private static final String CLAIM_NAME = "groups";
    private final KeycloakDefaultGroupsMapper underTest = new KeycloakDefaultGroupsMapper();

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
    @DisplayName("Map groups claim to group list")
    void shouldMapGroupsClaim() {
        List<String> expectedGroups = List.of("/test-group", "/admin-group", "/user-group");
        JsonObject jsonObject = createKeycloakTokenWithGroups(expectedGroups);

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNotNull(result);
        assertEquals(ClaimValueType.STRING_LIST, result.getType());
        assertEquals(expectedGroups, result.getAsList());
        assertNotNull(result.getOriginalString());
    }

    @Test
    @DisplayName("Handle missing groups claim - returns null")
    void shouldHandleMissingGroupsClaim() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .add("iss", "https://keycloak.example.com")
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNull(result, "Should return null for missing groups claim");
    }

    @Test
    @DisplayName("Handle empty groups array")
    void shouldHandleEmptyGroupsArray() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .add("groups", Json.createArrayBuilder().build())
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNotNull(result);
        assertEquals(ClaimValueType.STRING_LIST, result.getType());
        assertTrue(result.getAsList().isEmpty());
        assertEquals("[]", result.getOriginalString());
    }

    @Test
    @DisplayName("Handle non-array groups value - returns null")
    void shouldHandleNonArrayGroupsValue() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .add("groups", "test-group")
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNull(result, "Should return null for non-array groups value");
    }

    @Test
    @DisplayName("Handle null groups - returns null")
    void shouldHandleNullGroups() {
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("sub", "user123")
                .addNull("groups")
                .build();

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNull(result, "Should return null for null groups");
    }

    @Test
    @DisplayName("Handle single group in array")
    void shouldHandleSingleGroup() {
        List<String> expectedGroups = List.of("/admin-group");
        JsonObject jsonObject = createKeycloakTokenWithGroups(expectedGroups);

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNotNull(result);
        assertEquals(ClaimValueType.STRING_LIST, result.getType());
        assertEquals(expectedGroups, result.getAsList());
        assertEquals(1, result.getAsList().size());
        assertEquals("/admin-group", result.getAsList().getFirst());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("groupNameFormatsProvider")
    @DisplayName("Handle various group name formats")
    void shouldHandleVariousGroupNameFormats(String testCase, List<String> expectedGroups) {
        JsonObject jsonObject = createKeycloakTokenWithGroups(expectedGroups);

        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);

        assertNotNull(result);
        assertEquals(ClaimValueType.STRING_LIST, result.getType());
        assertEquals(expectedGroups, result.getAsList());
    }

    private static Stream<Arguments> groupNameFormatsProvider() {
        return Stream.of(
                Arguments.of("groups without path prefix",
                        List.of("test-group", "admin-group", "user-group")),
                Arguments.of("mixed group name formats",
                        List.of("/full-path-group", "simple-group", "/nested/path/group")),
                Arguments.of("complex group names",
                        List.of("/realm-management", "/account-console", "/offline_access")),
                Arguments.of("groups with special characters",
                        List.of("/test-group_123", "/admin@domain", "/group.with.dots"))
        );
    }

    private JsonObject createKeycloakTokenWithGroups(List<String> groups) {
        JsonArrayBuilder groupsArrayBuilder = Json.createArrayBuilder();
        groups.forEach(groupsArrayBuilder::add);

        return Json.createObjectBuilder()
                .add("sub", "user123")
                .add("iss", "https://keycloak.example.com")
                .add("groups", groupsArrayBuilder.build())
                .build();
    }
}
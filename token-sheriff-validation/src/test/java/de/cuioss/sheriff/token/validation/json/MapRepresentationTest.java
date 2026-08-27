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
package de.cuioss.sheriff.token.validation.json;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests MapRepresentation functionality")
class MapRepresentationTest {

    @Test
    @DisplayName("Basic string access")
    void shouldAccessBasicStringValues() {
        Map<String, Object> data = Map.of(
                "sub", "user123",
                "iss", "https://example.com",
                "aud", "client-app"
        );
        MapRepresentation map = new MapRepresentation(data);

        assertEquals(Optional.of("user123"), map.getString("sub"));
        assertEquals(Optional.of("https://example.com"), map.getString("iss"));
        assertEquals(Optional.of("client-app"), map.getString("aud"));
        assertEquals(Optional.empty(), map.getString("nonexistent"));
    }

    @Test
    @DisplayName("Basic number access")
    void shouldAccessBasicNumberValues() {
        Map<String, Object> data = Map.of(
                "exp", 1234567890L,
                "iat", 1234567800L,
                "nbf", 1234567700,
                "age", 25
        );
        MapRepresentation map = new MapRepresentation(data);

        assertEquals(Optional.of(1234567890L), map.getNumber("exp"));
        assertEquals(Optional.of(1234567800L), map.getNumber("iat"));
        assertEquals(Optional.of(1234567700), map.getNumber("nbf"));
        assertEquals(Optional.of(25), map.getNumber("age"));
        assertEquals(Optional.empty(), map.getNumber("nonexistent"));
    }

    @Test
    @DisplayName("List access - KeycloakDefaultRolesMapper pattern")
    void shouldAccessKeycloakRolesPattern() {
        // Simulates the Keycloak realm_access.roles structure
        Map<String, Object> realmAccess = Map.of(
                "roles", List.of("user", "admin", "read-only")
        );
        Map<String, Object> data = Map.of(
                "sub", "user123",
                "iss", "https://keycloak.example.com",
                "realm_access", realmAccess
        );
        MapRepresentation map = new MapRepresentation(data);

        // Test nested map access
        Optional<MapRepresentation> nestedMap = map.getNestedMap("realm_access");
        assertTrue(nestedMap.isPresent());

        // Test roles list access
        Optional<List<String>> roles = nestedMap.get().getStringList("roles");
        assertTrue(roles.isPresent());
        assertEquals(List.of("user", "admin", "read-only"), roles.get());
    }

    @Test
    @DisplayName("List access - KeycloakDefaultGroupsMapper pattern")
    void shouldAccessKeycloakGroupsPattern() {
        // Simulates the Keycloak realm_access.groups structure
        Map<String, Object> realmAccess = Map.of(
                "groups", List.of("/administrators", "/users", "/guests")
        );
        Map<String, Object> data = Map.of(
                "sub", "user123",
                "iss", "https://keycloak.example.com",
                "realm_access", realmAccess
        );
        MapRepresentation map = new MapRepresentation(data);

        Optional<MapRepresentation> nestedMap = map.getNestedMap("realm_access");
        assertTrue(nestedMap.isPresent());

        Optional<List<String>> groups = nestedMap.get().getStringList("groups");
        assertTrue(groups.isPresent());
        assertEquals(List.of("/administrators", "/users", "/guests"), groups.get());
    }

    @Test
    @DisplayName("String list access - ScopeMapper pattern")
    void shouldAccessScopeList() {
        Map<String, Object> data = Map.of(
                "scope", List.of("openid", "profile", "email", "read:users")
        );
        MapRepresentation map = new MapRepresentation(data);

        Optional<List<String>> scopes = map.getStringList("scope");
        assertTrue(scopes.isPresent());
        assertEquals(List.of("openid", "profile", "email", "read:users"), scopes.get());
    }

    @Test
    @DisplayName("Direct list access - JsonCollectionMapper pattern")
    void shouldAccessDirectList() {
        Map<String, Object> data = Map.of(
                "aud", List.of("client-1", "client-2", "client-3"),
                "groups", List.of("admin", "user", "guest")
        );
        MapRepresentation map = new MapRepresentation(data);

        Optional<List<String>> audiences = map.getStringList("aud");
        assertTrue(audiences.isPresent());
        assertEquals(List.of("client-1", "client-2", "client-3"), audiences.get());

        Optional<List<String>> groups = map.getStringList("groups");
        assertTrue(groups.isPresent());
        assertEquals(List.of("admin", "user", "guest"), groups.get());
    }

    @Test
    @DisplayName("String splitting pattern - StringSplitterMapper use case")
    void shouldAccessCommaSeparatedString() {
        Map<String, Object> data = Map.of(
                "roles", "admin,user,manager",
                "permissions", "read:write:delete",
                "single_role", "admin"
        );
        MapRepresentation map = new MapRepresentation(data);

        assertEquals(Optional.of("admin,user,manager"), map.getString("roles"));
        assertEquals(Optional.of("read:write:delete"), map.getString("permissions"));
        assertEquals(Optional.of("admin"), map.getString("single_role"));
    }

    @Test
    @DisplayName("DateTime access - OffsetDateTimeMapper pattern")
    void shouldAccessDateTimeValues() {
        Map<String, Object> data = Map.of(
                "exp", 1672531200L, // Unix timestamp
                "iat", 1672444800L,
                "nbf", 1672444700L,
                "auth_time", 1672444750L
        );
        MapRepresentation map = new MapRepresentation(data);

        assertEquals(Optional.of(1672531200L), map.getNumber("exp"));
        assertEquals(Optional.of(1672444800L), map.getNumber("iat"));
        assertEquals(Optional.of(1672444700L), map.getNumber("nbf"));
        assertEquals(Optional.of(1672444750L), map.getNumber("auth_time"));
    }

    @Test
    @DisplayName("Identity mapping - IdentityMapper pattern")
    void shouldAccessIdentityValues() {
        Map<String, Object> data = Map.of(
                "email", "user@example.com",
                "name", "John Doe",
                "preferred_username", "john.doe",
                "sub", "123456789"
        );
        MapRepresentation map = new MapRepresentation(data);

        assertEquals(Optional.of("user@example.com"), map.getString("email"));
        assertEquals(Optional.of("John Doe"), map.getString("name"));
        assertEquals(Optional.of("john.doe"), map.getString("preferred_username"));
        assertEquals(Optional.of("123456789"), map.getString("sub"));
    }

    @Test
    @DisplayName("Complex nested structures")
    void shouldAccessComplexNestedStructures() {
        Map<String, Object> address = Map.of(
                "street", "123 Main St",
                "city", "Anytown",
                "country", "US"
        );
        Map<String, Object> data = Map.of(
                "sub", "user123",
                "address", address,
                "roles", List.of("user", "admin")
        );
        MapRepresentation map = new MapRepresentation(data);

        // Test direct access
        assertEquals(Optional.of("user123"), map.getString("sub"));

        // Test nested map access
        Optional<MapRepresentation> addressMap = map.getNestedMap("address");
        assertTrue(addressMap.isPresent());
        assertEquals(Optional.of("123 Main St"), addressMap.get().getString("street"));
        assertEquals(Optional.of("Anytown"), addressMap.get().getString("city"));
        assertEquals(Optional.of("US"), addressMap.get().getString("country"));

        // Test list access
        Optional<List<String>> roles = map.getStringList("roles");
        assertTrue(roles.isPresent());
        assertEquals(List.of("user", "admin"), roles.get());
    }

    @Test
    @DisplayName("Type safety - wrong type access")
    void shouldHandleWrongTypeAccess() {
        Map<String, Object> data = Map.of(
                "number_as_string", "123",
                "string_as_number", 123,
                "list_as_string", List.of("a", "b", "c"),
                "boolean_as_string", "true"
        );
        MapRepresentation map = new MapRepresentation(data);

        // String value accessed as number should return empty
        assertEquals(Optional.empty(), map.getNumber("number_as_string"));

        // Number value accessed as string should return empty
        assertEquals(Optional.empty(), map.getString("string_as_number"));

        // List value accessed as string should return empty
        assertEquals(Optional.empty(), map.getString("list_as_string"));

        // But correct type access should work
        assertEquals(Optional.of("123"), map.getString("number_as_string"));
        assertEquals(Optional.of(123), map.getNumber("string_as_number"));
        assertEquals(Optional.of(List.of("a", "b", "c")), map.getStringList("list_as_string"));
    }

    @Test
    @DisplayName("Utility methods")
    void shouldProvideUtilityMethods() {
        Map<String, Object> data = Map.of(
                "key1", "value1",
                "key2", "value2",
                "key3", 123
        );
        MapRepresentation map = new MapRepresentation(data);

        assertTrue(map.containsKey("key1"));
        assertTrue(map.containsKey("key2"));
        assertTrue(map.containsKey("key3"));
        assertFalse(map.containsKey("nonexistent"));

        assertEquals(3, map.size());
        assertFalse(map.isEmpty());

        MapRepresentation emptyMap = new MapRepresentation(Map.of());
        assertTrue(emptyMap.isEmpty());
        assertEquals(0, emptyMap.size());
    }

    @Test
    @DisplayName("Raw value access")
    void shouldProvideRawValueAccess() {
        Object customObject = new Object();
        Map<String, Object> data = Map.of(
                "string", "value",
                "number", 123,
                "custom", customObject
        );
        MapRepresentation map = new MapRepresentation(data);

        assertEquals(Optional.of("value"), map.getValue("string"));
        assertEquals(Optional.of(123), map.getValue("number"));
        assertEquals(Optional.of(customObject), map.getValue("custom"));
        assertEquals(Optional.empty(), map.getValue("nonexistent"));
    }


    @Test
    @DisplayName("Null safety")
    void shouldHandleNullValues() {
        Map<String, Object> data = new HashMap<>();
        data.put("null_value", null);
        data.put("non_null", "value");

        MapRepresentation map = new MapRepresentation(data);

        assertEquals(Optional.empty(), map.getString("null_value"));
        assertEquals(Optional.empty(), map.getNumber("null_value"));
        assertEquals(Optional.empty(), map.getList("null_value"));
        assertEquals(Optional.empty(), map.getMap("null_value"));
        assertEquals(Optional.empty(), map.getNestedMap("null_value"));
        assertEquals(Optional.empty(), map.getStringList("null_value"));

        // But getValue should return Optional.empty() for null values (Optional.ofNullable behavior)
        assertEquals(Optional.empty(), map.getValue("null_value"));

        // Non-null values should work normally
        assertEquals(Optional.of("value"), map.getString("non_null"));

        // Key should still be reported as present even with null value
        assertTrue(map.containsKey("null_value"));
        assertTrue(map.containsKey("non_null"));
        assertFalse(map.containsKey("missing"));
    }
}
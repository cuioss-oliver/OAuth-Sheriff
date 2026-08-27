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
package de.cuioss.sheriff.token.validation.domain.claim;

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.valueobjects.junit5.contracts.ShouldHandleObjectContracts;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests ClaimName functionality")
class ClaimNameTest implements ShouldHandleObjectContracts<ClaimName> {

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

    @ParameterizedTest
    @MethodSource("provideClaimNameMapTestData")
    @DisplayName("Map claims from JsonObject")
    void shouldMapClaimsFromJsonObject(ClaimName claimName, JsonObject jsonObject, ClaimValue expectedValue) {
        ClaimValue result = claimName.getClaimMapper().map(convertJsonObjectToMapRepresentation(jsonObject), claimName.getName());

        if (expectedValue == null) {
            assertNull(result, "Result should be null for absent claims");
            return;
        }

        assertNotNull(result, "Result should not be null");
        assertEquals(expectedValue.getType(), result.getType(), "Type should match expected");
        assertEquals(expectedValue.getOriginalString(), result.getOriginalString(), "Original string should match expected");

        if (expectedValue.getType() == ClaimValueType.STRING_LIST) {
            assertEquals(expectedValue.getAsList(), result.getAsList(), "List values should match expected");
        } else if (expectedValue.getType() == ClaimValueType.DATETIME) {
            assertEquals(expectedValue.getDateTime(), result.getDateTime(), "DateTime values should match expected");
        }
    }

    static Stream<Arguments> provideClaimNameMapTestData() {
        return Stream.of(
                Arguments.of(
                        ClaimName.ISSUER,
                        createJsonObjectWithStringClaim("iss", "https://example.com"),
                        ClaimValue.forPlainString("https://example.com")
                ),

                Arguments.of(
                        ClaimName.SUBJECT,
                        createJsonObjectWithStringClaim("sub", "user123"),
                        ClaimValue.forPlainString("user123")
                ),

                Arguments.of(
                        ClaimName.AUDIENCE,
                        createJsonObjectWithArrayClaim("aud", List.of("client1", "client2")),
                        ClaimValue.forList("[client1, client2]", List.of("client1", "client2"))
                ),

                Arguments.of(
                        ClaimName.AUDIENCE,
                        createJsonObjectWithStringClaim("aud", "singleClient"),
                        ClaimValue.forList("singleClient", List.of("singleClient"))
                ),

                Arguments.of(
                        ClaimName.EXPIRATION,
                        createJsonObjectWithNumericClaim("exp", 1609459200),
                        ClaimValue.forDateTime("1609459200", OffsetDateTime.ofInstant(
                                Instant.ofEpochSecond(1609459200),
                                ZoneOffset.systemDefault())
                        )
                ),

                Arguments.of(
                        ClaimName.NOT_BEFORE,
                        createJsonObjectWithNumericClaim("nbf", 1609459200),
                        ClaimValue.forDateTime("1609459200", OffsetDateTime.ofInstant(
                                Instant.ofEpochSecond(1609459200),
                                ZoneOffset.systemDefault())
                        )
                ),

                Arguments.of(
                        ClaimName.ISSUED_AT,
                        createJsonObjectWithNumericClaim("iat", 1609459200),
                        ClaimValue.forDateTime("1609459200", OffsetDateTime.ofInstant(
                                Instant.ofEpochSecond(1609459200),
                                ZoneOffset.systemDefault())
                        )
                ),

                Arguments.of(
                        ClaimName.TOKEN_ID,
                        createJsonObjectWithStringClaim("jti", "token123"),
                        ClaimValue.forPlainString("token123")
                ),

                Arguments.of(
                        ClaimName.NAME,
                        createJsonObjectWithStringClaim("name", "John Doe"),
                        ClaimValue.forPlainString("John Doe")
                ),

                Arguments.of(
                        ClaimName.EMAIL,
                        createJsonObjectWithStringClaim("email", "john@example.com"),
                        ClaimValue.forPlainString("john@example.com")
                ),

                Arguments.of(
                        ClaimName.PREFERRED_USERNAME,
                        createJsonObjectWithStringClaim("preferred_username", "johndoe"),
                        ClaimValue.forPlainString("johndoe")
                ),

                Arguments.of(
                        ClaimName.SCOPE,
                        createJsonObjectWithStringClaim("scope", "email openid profile"),
                        ClaimValue.forList("email openid profile", List.of("email", "openid", "profile"))
                ),

                Arguments.of(
                        ClaimName.TYPE,
                        createJsonObjectWithStringClaim("typ", "JWT"),
                        ClaimValue.forPlainString("JWT")
                ),

                Arguments.of(
                        ClaimName.ROLES,
                        createJsonObjectWithArrayClaim("roles", List.of("admin", "user", "manager")),
                        ClaimValue.forList("[admin, user, manager]", List.of("admin", "user", "manager"))
                ),

                Arguments.of(
                        ClaimName.ROLES,
                        createJsonObjectWithStringClaim("roles", "admin"),
                        ClaimValue.forList("admin", List.of("admin"))
                ),

                Arguments.of(
                        ClaimName.GROUPS,
                        createJsonObjectWithArrayClaim("groups", List.of("group1", "group2", "group3")),
                        ClaimValue.forList("[group1, group2, group3]", List.of("group1", "group2", "group3"))
                ),

                Arguments.of(
                        ClaimName.GROUPS,
                        createJsonObjectWithStringClaim("groups", "group1"),
                        ClaimValue.forList("group1", List.of("group1"))
                ),

                Arguments.of(
                        ClaimName.AUTHORIZED_PARTY,
                        createJsonObjectWithStringClaim("azp", "client123"),
                        ClaimValue.forPlainString("client123")
                ),

                Arguments.of(
                        ClaimName.CLIENT_ID,
                        createJsonObjectWithStringClaim("client_id", "my-client"),
                        ClaimValue.forPlainString("my-client")
                ),

                Arguments.of(
                        ClaimName.UPN,
                        createJsonObjectWithStringClaim("upn", "user@example.com"),
                        ClaimValue.forPlainString("user@example.com")
                ),

                Arguments.of(
                        ClaimName.ISSUER,
                        Json.createObjectBuilder().build(),
                        null
                ),

                Arguments.of(
                        ClaimName.SUBJECT,
                        createJsonObjectWithNullClaim("sub"),
                        null
                )
        );
    }

    private static JsonObject createJsonObjectWithStringClaim(String claimName, String value) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        if (value != null) {
            builder.add(claimName, value);
        } else {
            builder.addNull(claimName);
        }
        return builder.build();
    }

    private static JsonObject createJsonObjectWithNullClaim(String claimName) {
        return Json.createObjectBuilder()
                .addNull(claimName)
                .build();
    }

    private static JsonObject createJsonObjectWithArrayClaim(String claimName, List<String> values) {
        var arrayBuilder = Json.createArrayBuilder();
        for (String value : values) {
            arrayBuilder.add(value);
        }
        return Json.createObjectBuilder()
                .add(claimName, arrayBuilder.build())
                .build();
    }

    private static JsonObject createJsonObjectWithNumericClaim(String claimName, long value) {
        return Json.createObjectBuilder()
                .add(claimName, value)
                .build();
    }

    @Test
    @DisplayName("Should have correct name and value type for each enum value")
    @SuppressWarnings("java:S5961") // owolff: Suppressing this warning as the test is designed to check enum values
    void shouldHaveCorrectNameAndValueType() {
        assertEquals("iss", ClaimName.ISSUER.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.ISSUER.getValueType());

        assertEquals("sub", ClaimName.SUBJECT.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.SUBJECT.getValueType());

        assertEquals("aud", ClaimName.AUDIENCE.getName());
        assertEquals(ClaimValueType.STRING_LIST, ClaimName.AUDIENCE.getValueType());

        assertEquals("exp", ClaimName.EXPIRATION.getName());
        assertEquals(ClaimValueType.DATETIME, ClaimName.EXPIRATION.getValueType());

        assertEquals("nbf", ClaimName.NOT_BEFORE.getName());
        assertEquals(ClaimValueType.DATETIME, ClaimName.NOT_BEFORE.getValueType());

        assertEquals("iat", ClaimName.ISSUED_AT.getName());
        assertEquals(ClaimValueType.DATETIME, ClaimName.ISSUED_AT.getValueType());

        assertEquals("jti", ClaimName.TOKEN_ID.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.TOKEN_ID.getValueType());

        assertEquals("name", ClaimName.NAME.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.NAME.getValueType());

        assertEquals("email", ClaimName.EMAIL.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.EMAIL.getValueType());

        assertEquals("preferred_username", ClaimName.PREFERRED_USERNAME.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.PREFERRED_USERNAME.getValueType());

        assertEquals("scope", ClaimName.SCOPE.getName());
        assertEquals(ClaimValueType.STRING_LIST, ClaimName.SCOPE.getValueType());

        assertEquals("typ", ClaimName.TYPE.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.TYPE.getValueType());

        assertEquals("roles", ClaimName.ROLES.getName());
        assertEquals(ClaimValueType.STRING_LIST, ClaimName.ROLES.getValueType());

        assertEquals("groups", ClaimName.GROUPS.getName());
        assertEquals(ClaimValueType.STRING_LIST, ClaimName.GROUPS.getValueType());

        assertEquals("azp", ClaimName.AUTHORIZED_PARTY.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.AUTHORIZED_PARTY.getValueType());

        assertEquals("client_id", ClaimName.CLIENT_ID.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.CLIENT_ID.getValueType());

        assertEquals("upn", ClaimName.UPN.getName());
        assertEquals(ClaimValueType.STRING, ClaimName.UPN.getValueType());
    }

    @Test
    @DisplayName("Should find ClaimName by string name")
    void shouldFindClaimNameByString() {
        String issuerName = "iss";
        Optional<ClaimName> result = ClaimName.fromString(issuerName);
        assertTrue(result.isPresent(), "Should find ClaimName for valid string");
        assertEquals(ClaimName.ISSUER, result.get(), "Should return correct ClaimName");
    }

    @Test
    @DisplayName("Should find all ClaimName values by their string names")
    void shouldFindAllClaimNamesByString() {
        for (ClaimName claimName : ClaimName.values()) {
            Optional<ClaimName> result = ClaimName.fromString(claimName.getName());
            assertTrue(result.isPresent(), "Should find ClaimName for " + claimName.getName());
            assertEquals(claimName, result.get(), "Should return correct ClaimName for " + claimName.getName());
        }
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"unknown", "invalid", " ", "ISS", "Iss"})
    @DisplayName("Should return empty Optional for null, empty, or unknown claim names")
    void shouldReturnEmptyForUnknownNames(String input) {
        Optional<ClaimName> result = ClaimName.fromString(input);
        assertFalse(result.isPresent(), "Should return empty for unknown input: " + input);
    }

    @Override
    public ClaimName getUnderTest() {
        return ClaimName.ISSUER;
    }
}

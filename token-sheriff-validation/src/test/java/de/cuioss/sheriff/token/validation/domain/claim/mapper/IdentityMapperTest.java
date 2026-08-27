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
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests IdentityMapper functionality")
class IdentityMapperTest {

    private static final String CLAIM_NAME = "testClaim";
    private final IdentityMapper underTest = new IdentityMapper();

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
    @DisplayName("Should correctly map a regular string")
    void shouldMapRegularString() {

        String input = "some-regular-string";
        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, input);
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING, result.getType(), "Type should be STRING");
    }

    @Test
    @DisplayName("Should handle null input - returns null for absent claim")
    void shouldHandleNullInput() {
        JsonObject jsonObject = createJsonObjectWithNullClaim(CLAIM_NAME);
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNull(result, "Should return null for null claim");
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {" ", "\t", "\n"})
    @DisplayName("Should handle empty and whitespace inputs")
    void shouldHandleEmptyAndWhitespaceInputs(String input) {
        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, input);
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING, result.getType(), "Type should be STRING");
    }

    @Test
    @DisplayName("Should handle special characters")
    void shouldHandleSpecialCharacters() {

        String input = "!@#$%^&*()_+{}|:<>?~`-=[]\\;',./";
        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, input);
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING, result.getType(), "Type should be STRING");
    }

    @Test
    @DisplayName("Should handle very long strings")
    void shouldHandleVeryLongStrings() {

        String longString = "a".repeat(1000);
        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, longString);
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNotNull(result, "Result should not be null");
        assertEquals(longString, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING, result.getType(), "Type should be STRING");
    }

    @Test
    @DisplayName("Should handle numeric values")
    void shouldHandleNumericValues() {

        int input = 12345;
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, input)
                .build();
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNotNull(result, "Result should not be null");
        assertEquals(String.valueOf(input), result.getOriginalString(), "Original string should be the string representation of the number");
        assertEquals(ClaimValueType.STRING, result.getType(), "Type should be STRING");
    }

    @Test
    @DisplayName("Should handle boolean values")
    void shouldHandleBooleanValues() {

        boolean input = true;
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, input)
                .build();
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNotNull(result, "Result should not be null");
        assertEquals(String.valueOf(input), result.getOriginalString(), "Original string should be the string representation of the boolean");
        assertEquals(ClaimValueType.STRING, result.getType(), "Type should be STRING");
    }

    @Test
    @DisplayName("Should handle missing claim - returns null")
    void shouldHandleMissingClaim() {
        JsonObject jsonObject = Json.createObjectBuilder().build();
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(jsonObject), CLAIM_NAME);
        assertNull(result, "Should return null for missing claim");
    }

    @Test
    @DisplayName("Should handle empty JsonObject - returns null")
    void shouldHandleEmptyJsonObject() {
        JsonObject emptyJsonObject = Json.createObjectBuilder().build();
        ClaimValue result = underTest.map(convertJsonObjectToMapRepresentation(emptyJsonObject), CLAIM_NAME);
        assertNull(result, "Should return null for empty JsonObject");
    }

    // Helper methods

    private JsonObject createJsonObjectWithStringClaim(String claimName, String value) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        if (value != null) {
            builder.add(claimName, value);
        } else {
            builder.addNull(claimName);
        }
        return builder.build();
    }

    private JsonObject createJsonObjectWithNullClaim(String claimName) {
        return Json.createObjectBuilder()
                .addNull(claimName)
                .build();
    }
}

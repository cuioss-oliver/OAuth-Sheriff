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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests StringSplitterMapper functionality")
class StringSplitterMapperTest {

    private static final String CLAIM_NAME = "roles";
    private final StringSplitterMapper commaMapper = new StringSplitterMapper(',');


    @ParameterizedTest
    @MethodSource("provideSeparatorTestCases")
    @DisplayName("Map values with different separators")
    void shouldMapValuesWithDifferentSeparators(char separator, String input, List<String> expected) throws Exception {
        StringSplitterMapper mapper = new StringSplitterMapper(separator);
        String jsonString = "{\"" + CLAIM_NAME + "\": \"" + input.replace("\"", "\\\"") + "\"}";
        DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
        MapRepresentation mapRepresentation = MapRepresentation.fromJson(dslJson, jsonString);

        ClaimValue result = mapper.map(mapRepresentation, CLAIM_NAME);

        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING_LIST, result.getType(), "Type should be STRING_LIST");
        assertEquals(expected, result.getAsList(), "Values should be correctly parsed");
    }

    static Stream<Arguments> provideSeparatorTestCases() {
        return Stream.of(
                // separator, input string, expected list
                Arguments.of(',', "admin,user,manager", List.of("admin", "user", "manager")),
                Arguments.of(':', "admin:user:manager", List.of("admin", "user", "manager")),
                Arguments.of(';', "admin;user;manager", List.of("admin", "user", "manager")),
                Arguments.of('|', "admin|user|manager", List.of("admin", "user", "manager"))
        );
    }

    @ParameterizedTest
    @MethodSource("provideInputFormatTestCases")
    @DisplayName("Handle different input formats")
    void shouldHandleDifferentInputFormats(String input, List<String> expected, String testDescription) throws Exception {
        String jsonString = "{\"" + CLAIM_NAME + "\": \"" + input.replace("\"", "\\\"") + "\"}";
        DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
        MapRepresentation mapRepresentation = MapRepresentation.fromJson(dslJson, jsonString);

        ClaimValue result = commaMapper.map(mapRepresentation, CLAIM_NAME);

        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING_LIST, result.getType(), "Type should be STRING_LIST");
        assertEquals(expected, result.getAsList(), testDescription);
    }

    static Stream<Arguments> provideInputFormatTestCases() {
        return Stream.of(
                // input string, expected list, test description
                Arguments.of("  admin  ,  user  ,  manager  ",
                        List.of("admin", "user", "manager"),
                        "Values should be correctly parsed with whitespace trimmed"),
                Arguments.of("admin,,user,,manager",
                        List.of("admin", "user", "manager"),
                        "Empty segments should be omitted"),
                Arguments.of("role1,role-with-dash,role_with_underscore,role.with.dots,role@with@at",
                        List.of("role1", "role-with-dash", "role_with_underscore", "role.with.dots", "role@with@at"),
                        "Values with special characters should be correctly parsed")
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t", "\n"})
    @DisplayName("Handle null, empty, and whitespace inputs")
    void shouldHandleSpecialInputs(String input) throws Exception {
        if (input == null) {
            // Null input means absent claim, mapper now returns null
            String jsonString = "{\"" + CLAIM_NAME + "\": null}";
            DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
            MapRepresentation mapRepresentation = MapRepresentation.fromJson(dslJson, jsonString);
            ClaimValue result = commaMapper.map(mapRepresentation, CLAIM_NAME);
            assertNull(result, "Should return null for null claim");
            return;
        }
        String jsonString = "{\"" + CLAIM_NAME + "\": \"" + input.replace("\"", "\\\"").replace("\n", "\\n").replace("\t", "\\t") + "\"}";
        DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
        MapRepresentation mapRepresentation = MapRepresentation.fromJson(dslJson, jsonString);

        ClaimValue result = commaMapper.map(mapRepresentation, CLAIM_NAME);

        assertNotNull(result, "Result should not be null");
        assertEquals(input, result.getOriginalString(), "Original string should be preserved");
        assertEquals(ClaimValueType.STRING_LIST, result.getType(), "Type should be STRING_LIST");
        assertTrue(result.getAsList().isEmpty(), "Value list should be empty");
    }

    @Test
    @DisplayName("Handle missing claim - returns null")
    void shouldHandleMissingClaim() throws Exception {
        String jsonString = "{}";
        DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
        MapRepresentation mapRepresentation = MapRepresentation.fromJson(dslJson, jsonString);

        ClaimValue result = commaMapper.map(mapRepresentation, CLAIM_NAME);

        assertNull(result, "Should return null for missing claim");
    }

    @ParameterizedTest
    @MethodSource("provideUnsupportedValueTypes")
    @DisplayName("Throw exception for unsupported value types")
    void shouldThrowExceptionForUnsupportedValueTypes(String jsonString, String valueTypeName) throws Exception {
        DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
        MapRepresentation mapRepresentation = MapRepresentation.fromJson(dslJson, jsonString);

        assertThrows(IllegalArgumentException.class, () -> commaMapper.map(mapRepresentation, CLAIM_NAME),
                "Should throw IllegalArgumentException for " + valueTypeName + " value type");
    }

    static Stream<Arguments> provideUnsupportedValueTypes() {
        return Stream.of(
                // JSON string, value type name
                Arguments.of(
                        "{\"" + CLAIM_NAME + "\": [\"admin\", \"user\", \"manager\"]}",
                        "array"
                ),
                Arguments.of(
                        "{\"" + CLAIM_NAME + "\": 123}",
                        "number"
                ),
                Arguments.of(
                        "{\"" + CLAIM_NAME + "\": true}",
                        "boolean"
                ),
                Arguments.of(
                        "{\"" + CLAIM_NAME + "\": {\"key\": \"value\"}}",
                        "object"
                )
        );
    }

}

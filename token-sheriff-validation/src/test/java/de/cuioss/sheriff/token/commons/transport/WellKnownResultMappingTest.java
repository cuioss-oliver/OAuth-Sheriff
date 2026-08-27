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
package de.cuioss.sheriff.token.commons.transport;

import com.dslplatform.json.DslJson;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Isolated test to verify DSL-JSON mapping to WellKnownResult.
 *
 * @author Oliver Wolff
 */
@SuppressWarnings("unchecked")
@DisplayName("WellKnownResult DSL-JSON Mapping")
class WellKnownResultMappingTest {

    private static final String VALID_JSON = """
            {
                "issuer": "https://example.com",
                "jwks_uri": "https://example.com/.well-known/jwks.json",
                "authorization_endpoint": "https://example.com/auth",
                "token_endpoint": "https://example.com/token"
            }
            """;

    private static final String MINIMAL_JSON = """
            {
                "issuer": "https://example.com",
                "jwks_uri": "https://example.com/.well-known/jwks.json"
            }
            """;

    private DslJson<Object> dslJson;

    @BeforeEach
    void setUp() {
        ParserConfig config = ParserConfig.builder().build();
        dslJson = config.getDslJson();
    }

    @Test
    @DisplayName("Should map full JSON to WellKnownResult via Map deserialization")
    void shouldMapFullJsonToWellKnownConfigurationViaMap() throws Exception {
        // First: Parse JSON to Map using DSL-JSON
        byte[] bytes = VALID_JSON.getBytes();
        Map<String, Object> jsonMap = dslJson.deserialize(Map.class, bytes, bytes.length);

        assertNotNull(jsonMap);
        assertEquals("https://example.com", jsonMap.get("issuer"));
        assertEquals("https://example.com/.well-known/jwks.json", jsonMap.get("jwks_uri"));
        assertEquals("https://example.com/auth", jsonMap.get("authorization_endpoint"));
        assertEquals("https://example.com/token", jsonMap.get("token_endpoint"));

        // Second: Map to WellKnownResult
        WellKnownResult config = mapToWellKnownConfiguration(jsonMap);

        assertNotNull(config);
        assertEquals("https://example.com", config.issuer);
        assertEquals("https://example.com/.well-known/jwks.json", config.jwksUri);
    }

    @Test
    @DisplayName("Should map minimal JSON to WellKnownResult")
    void shouldMapMinimalJsonToWellKnownConfiguration() throws Exception {
        byte[] bytes = MINIMAL_JSON.getBytes();
        Map<String, Object> jsonMap = dslJson.deserialize(Map.class, bytes, bytes.length);

        assertNotNull(jsonMap);
        assertEquals("https://example.com", jsonMap.get("issuer"));
        assertEquals("https://example.com/.well-known/jwks.json", jsonMap.get("jwks_uri"));
        assertNull(jsonMap.get("authorization_endpoint"));
        assertNull(jsonMap.get("token_endpoint"));

        WellKnownResult config = mapToWellKnownConfiguration(jsonMap);

        assertNotNull(config);
        assertEquals("https://example.com", config.issuer);
        assertEquals("https://example.com/.well-known/jwks.json", config.jwksUri);
    }

    @Test
    @DisplayName("Should handle missing required fields gracefully")
    void shouldHandleMissingRequiredFieldsGracefully() throws Exception {
        String invalidJson = """
                {
                    "issuer": "https://example.com"
                }
                """;

        byte[] bytes = invalidJson.getBytes();
        Map<String, Object> jsonMap = dslJson.deserialize(Map.class, bytes, bytes.length);

        assertNotNull(jsonMap);
        assertEquals("https://example.com", jsonMap.get("issuer"));
        assertNull(jsonMap.get("jwks_uri"));

        // Should fail validation when missing required jwks_uri
        assertThrows(IllegalArgumentException.class, () -> mapToWellKnownConfiguration(jsonMap));
    }

    @Test
    @DisplayName("Should create direct string-to-configuration mapper")
    void shouldCreateDirectStringToConfigurationMapper() {
        Optional<WellKnownResult> result = parseWellKnownConfiguration(VALID_JSON);

        assertTrue(result.isPresent());
        WellKnownResult config = result.get();
        assertEquals("https://example.com", config.issuer);
        assertEquals("https://example.com/.well-known/jwks.json", config.jwksUri);
    }

    /**
     * Direct String → WellKnownResult mapper (what we want to achieve)
     */
    private Optional<WellKnownResult> parseWellKnownConfiguration(String json) {
        try {
            byte[] bytes = json.getBytes();
            Map<String, Object> jsonMap = dslJson.deserialize(Map.class, bytes, bytes.length);

            if (jsonMap == null) {
                return Optional.empty();
            }

            return Optional.of(mapToWellKnownConfiguration(jsonMap));
        } catch (IOException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * Maps a JSON Map to WellKnownResult with validation
     */
    private WellKnownResult mapToWellKnownConfiguration(Map<String, Object> jsonMap) {
        String issuer = (String) jsonMap.get("issuer");
        String jwksUri = (String) jsonMap.get("jwks_uri");

        // Validate required fields
        if (issuer == null || issuer.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing required field: issuer");
        }
        if (jwksUri == null || jwksUri.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing required field: jwks_uri");
        }

        var result = new WellKnownResult();
        result.issuer = issuer;
        result.jwksUri = jwksUri;
        return result;
    }
}
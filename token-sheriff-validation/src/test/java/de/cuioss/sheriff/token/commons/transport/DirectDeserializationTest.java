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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests direct JSON deserialization to WellKnownResult.
 */
@DisplayName("Direct Deserialization Test")
class DirectDeserializationTest {

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
    @DisplayName("Should deserialize directly to WellKnownResult record")
    void shouldDeserializeDirectlyToWellKnownConfigurationRecord() throws Exception {
        byte[] bytes = VALID_JSON.getBytes();

        WellKnownResult config = dslJson.deserialize(WellKnownResult.class, bytes, bytes.length);

        assertNotNull(config);
        assertEquals("https://example.com", config.issuer);
        assertEquals("https://example.com/.well-known/jwks.json", config.jwksUri);
    }

    @Test
    @DisplayName("Should deserialize minimal JSON directly to WellKnownResult record")
    void shouldDeserializeMinimalJsonDirectly() throws Exception {
        byte[] bytes = MINIMAL_JSON.getBytes();

        WellKnownResult config = dslJson.deserialize(WellKnownResult.class, bytes, bytes.length);

        assertNotNull(config);
        assertEquals("https://example.com", config.issuer);
        assertEquals("https://example.com/.well-known/jwks.json", config.jwksUri);
    }

    @Test
    @DisplayName("Should handle direct deserialization errors gracefully")
    void shouldHandleDirectDeserializationErrors() {
        String malformedJson = "{invalid json}";
        byte[] bytes = malformedJson.getBytes();

        assertThrows(IOException.class, () ->
                dslJson.deserialize(WellKnownResult.class, bytes, bytes.length));
    }

}
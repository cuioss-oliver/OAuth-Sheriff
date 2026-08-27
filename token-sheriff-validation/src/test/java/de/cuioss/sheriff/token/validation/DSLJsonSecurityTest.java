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
package de.cuioss.sheriff.token.validation;

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.transport.Jwks;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.commons.transport.WellKnownResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test to verify DSL-JSON behavior with our @CompiledJson mapped classes.
 */
class DSLJsonSecurityTest {

    @Test
    @DisplayName("Should parse valid JWKS JSON successfully")
    void shouldParseValidJwksSuccessfully() {
        ParserConfig config = ParserConfig.builder()
                .maxStringLength(1000)
                .build();

        DslJson<Object> dslJson = config.getDslJson();

        String validJwks = """
                {
                    "keys": [
                        {
                            "kty": "RSA",
                            "kid": "test-key-1",
                            "alg": "RS256",
                            "n": "test-modulus",
                            "e": "AQAB"
                        }
                    ]
                }
                """;

        Jwks result = assertDoesNotThrow(() ->
                dslJson.deserialize(Jwks.class, validJwks.getBytes(), validJwks.getBytes().length)
        );
        assertFalse(result.isEmpty());
        assertEquals(1, result.keys().size());
    }

    @Test
    @DisplayName("Should parse valid WellKnownResult JSON successfully")
    void shouldParseValidWellKnownConfigurationSuccessfully() {
        ParserConfig config = ParserConfig.builder().build();
        DslJson<Object> dslJson = config.getDslJson();

        String validConfig = """
                {
                    "issuer": "https://example.com",
                    "jwks_uri": "https://example.com/.well-known/jwks.json",
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token"
                }
                """;

        WellKnownResult result = assertDoesNotThrow(() ->
                dslJson.deserialize(WellKnownResult.class, validConfig.getBytes(), validConfig.getBytes().length)
        );
        assertNotNull(result.issuer);
        assertEquals("https://example.com", result.issuer);
        assertEquals("https://example.com/.well-known/jwks.json", result.jwksUri);
    }

    @Test
    @DisplayName("Should throw exception for malformed JWKS JSON")
    void shouldThrowExceptionForMalformedJwks() {
        ParserConfig config = ParserConfig.builder().build();
        DslJson<Object> dslJson = config.getDslJson();

        String malformedJwks = "{invalid json}";

        assertThrows(IOException.class, () ->
                dslJson.deserialize(Jwks.class, malformedJwks.getBytes(), malformedJwks.getBytes().length));
    }

    @Test
    @DisplayName("Should reject a JWKS whose string value exceeds the configured maxStringLength")
    void shouldRejectJwksWithOverLimitString() {
        int maxStringLength = 1000;
        ParserConfig config = ParserConfig.builder()
                .maxStringLength(maxStringLength)
                .build();

        DslJson<Object> dslJson = config.getDslJson();

        // The "n" modulus value is one character past the configured limit; DSL-JSON's
        // limitStringBuffer must abort deserialization rather than buffer the oversized string.
        String oversizedModulus = "a".repeat(maxStringLength + 1);
        String overLimitJwks = """
                {
                    "keys": [
                        {
                            "kty": "RSA",
                            "kid": "test-key-1",
                            "alg": "RS256",
                            "n": "%s",
                            "e": "AQAB"
                        }
                    ]
                }
                """.formatted(oversizedModulus);
        byte[] payload = overLimitJwks.getBytes(StandardCharsets.UTF_8);

        assertThrows(IOException.class, () ->
                        dslJson.deserialize(Jwks.class, payload, payload.length),
                "A string longer than maxStringLength must be rejected during deserialization");
    }
}

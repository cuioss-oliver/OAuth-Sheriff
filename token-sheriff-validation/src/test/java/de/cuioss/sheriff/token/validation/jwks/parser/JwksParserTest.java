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
package de.cuioss.sheriff.token.validation.jwks.parser;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.JwkKey;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = JwksParser.class)
@DisplayName("Tests JwksParser functionality")
class JwksParserTest {

    private JwksParser parser;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        parser = new JwksParser(ParserConfig.builder().build(), securityEventCounter);
    }

    @Nested
    @DisplayName("Valid JWKS Parsing")
    class ValidJwksParsingTests {

        @Test
        @DisplayName("Should parse standard JWKS with keys array")
        void shouldParseStandardJwks() {
            // Given a standard JWKS with keys array
            String jwksContent = InMemoryJWKSFactory.createDefaultJwks();

            // When parsing
            List<JwkKey> result = parser.parse(jwksContent);

            // Then parsing should succeed
            assertFalse(result.isEmpty(), "Should parse at least one key");
            assertEquals(1, result.size(), "Should parse exactly one key from default JWKS");

            JwkKey jwk = result.getFirst();
            assertNotNull(jwk.kty(), "Parsed JWK should contain key type");
            assertNotNull(jwk.kid(), "Parsed JWK should contain key ID");
        }

        @Test
        @DisplayName("Should parse single JWK object")
        void shouldParseSingleJwk() {
            // Given a single JWK object (without keys array)
            String singleJwk = """
                    {
                        "kty": "RSA",
                        "kid": "test-key",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus",
                        "e": "AQAB"
                    }
                    """;

            // When parsing
            List<JwkKey> result = parser.parse(singleJwk);

            // Then parsing should succeed
            assertEquals(1, result.size(), "Should parse single JWK");
            JwkKey jwk = result.getFirst();
            assertEquals("RSA", jwk.kty());
            assertEquals("test-key", jwk.kid());
        }

        @Test
        @DisplayName("Should parse JWKS with multiple keys")
        void shouldParseMultipleKeys() {
            // Given a JWKS with multiple keys
            String multiKeyJwks = """
                    {
                        "keys": [
                            {
                                "kty": "RSA",
                                "kid": "key1",
                                "use": "sig",
                                "alg": "RS256",
                                "n": "test-modulus1",
                                "e": "AQAB"
                            },
                            {
                                "kty": "EC",
                                "kid": "key2",
                                "use": "sig",
                                "alg": "ES256",
                                "crv": "P-256",
                                "x": "test-x",
                                "y": "test-y"
                            }
                        ]
                    }
                    """;

            // When parsing
            List<JwkKey> result = parser.parse(multiKeyJwks);

            // Then should parse all keys
            assertEquals(2, result.size(), "Should parse both keys");
            assertTrue(result.stream().anyMatch(jwk -> "key1".equals(jwk.kid())));
            assertTrue(result.stream().anyMatch(jwk -> "key2".equals(jwk.kid())));
        }
    }

    @Nested
    @DisplayName("Invalid JWKS Handling")
    class InvalidJwksHandlingTests {

        @Test
        @DisplayName("Should handle invalid JSON gracefully")
        void shouldHandleInvalidJson() {
            // Given invalid JSON
            String invalidJson = "{ invalid json }";

            // When parsing
            List<JwkKey> result = parser.parse(invalidJson);

            // Then should return empty list and log error
            assertTrue(result.isEmpty(), "Should return empty list for invalid JSON");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                    JWTValidationLogMessages.ERROR.JWKS_INVALID_JSON.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should handle empty JWKS")
        void shouldHandleEmptyJwks() {
            // Given empty JWKS
            String emptyJwks = "{}";

            // When parsing
            List<JwkKey> result = parser.parse(emptyJwks);

            // Then should return empty list and log warning
            assertTrue(result.isEmpty(), "Should return empty list for empty JWKS");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.JWKS_OBJECT_NULL.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should handle JWKS with empty keys array")
        void shouldHandleEmptyKeysArray() {
            // Given JWKS with empty keys array
            String emptyKeysJwks = """
                    {
                        "keys": []
                    }
                    """;

            // When parsing
            List<JwkKey> result = parser.parse(emptyKeysJwks);

            // Then should return empty list and log warning
            assertTrue(result.isEmpty(), "Should return empty list for empty keys array");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.JWKS_KEYS_ARRAY_EMPTY.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Security Features")
    class SecurityFeaturesTests {

        @Test
        @DisplayName("Should reject oversized content")
        void shouldRejectOversizedContent() {
            // Given a parser with small size limit
            ParserConfig config = ParserConfig.builder().maxPayloadSize(100).build();
            JwksParser smallParser = new JwksParser(config, securityEventCounter);

            // Given oversized content
            String largeContent = "{ \"keys\": [" + "x".repeat(200) + "] }";

            // When parsing
            List<JwkKey> result = smallParser.parse(largeContent);

            // Then should reject and return empty list
            assertTrue(result.isEmpty(), "Should return empty list for oversized content");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                    JWTValidationLogMessages.ERROR.JWKS_CONTENT_SIZE_EXCEEDED.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should track security events")
        void shouldTrackSecurityEvents() {
            // Given invalid JSON
            String invalidJson = "{ invalid }";

            // When parsing
            parser.parse(invalidJson);

            // Then should increment security event counter
            assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED) > 0,
                    "Should track JSON parse failures");
        }
    }

    @Nested
    @DisplayName("JWKS with too many keys")
    class JwksTooManyKeysTests {

        @Test
        @DisplayName("Should handle JWKS with too many keys")
        void shouldHandleJwksWithTooManyKeys() {
            // Given a parser with small payload size limit
            ParserConfig config = ParserConfig.builder().maxPayloadSize(50).build();
            JwksParser limitedParser = new JwksParser(config, securityEventCounter);

            // Given JWKS with more keys than can fit in size limit
            String manyKeysJwks = """
                    {
                        "keys": [
                            {"kty": "RSA", "kid": "key1", "n": "mod1", "e": "AQAB"},
                            {"kty": "RSA", "kid": "key2", "n": "mod2", "e": "AQAB"},
                            {"kty": "RSA", "kid": "key3", "n": "mod3", "e": "AQAB"}
                        ]
                    }
                    """;

            // When parsing - will fail due to size limit
            List<JwkKey> result = limitedParser.parse(manyKeysJwks);

            // Then should return empty list and log error
            assertTrue(result.isEmpty(), "Should return empty list when JWKS exceeds size limit");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                    JWTValidationLogMessages.ERROR.JWKS_CONTENT_SIZE_EXCEEDED.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("JWKS with missing KTY")
    class JwksMissingKtyTests {

        @Test
        @DisplayName("Should handle JWK with missing kty field")
        void shouldHandleJwkWithMissingKty() {
            // Given a JWK without kty field
            String missingKtyJwk = """
                    {
                        "keys": [
                            {
                                "kid": "test-key",
                                "use": "sig",
                                "alg": "RS256",
                                "n": "test-modulus",
                                "e": "AQAB"
                            }
                        ]
                    }
                    """;

            // When parsing
            List<JwkKey> result = parser.parse(missingKtyJwk);

            // Then should skip key and log warning
            assertTrue(result.isEmpty(), "Should skip key with missing kty");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.JWK_MISSING_KTY.resolveIdentifierString());
        }
    }
}
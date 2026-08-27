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
package de.cuioss.sheriff.token.validation.pipeline;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link NonValidatingJwtParser}
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests NonValidatingJwtParser functionality")
class NonValidatingJwtParserTest {

    // Sample validation parts
    private static final String SAMPLE_HEADER = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key-id\"}";
    private static final String SAMPLE_PAYLOAD = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iss\":\"https://example.com\",\"exp\":1735689600}";
    private static final String SAMPLE_SIGNATURE = "signature";
    // Encoded validation parts
    private static final String ENCODED_HEADER = Base64.getUrlEncoder().encodeToString(SAMPLE_HEADER.getBytes(StandardCharsets.UTF_8));
    private static final String ENCODED_PAYLOAD = Base64.getUrlEncoder().encodeToString(SAMPLE_PAYLOAD.getBytes(StandardCharsets.UTF_8));
    private static final String ENCODED_SIGNATURE = Base64.getUrlEncoder().encodeToString(SAMPLE_SIGNATURE.getBytes(StandardCharsets.UTF_8));
    // Complete validation
    private static final String VALID_TOKEN = ENCODED_HEADER + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;
    private NonValidatingJwtParser parser;

    @BeforeEach
    void setUp() {
        parser = NonValidatingJwtParser.builder().securityEventCounter(new SecurityEventCounter()).build();
    }

    @Nested
    @DisplayName("Valid Token Tests")
    class ValidTokenTests {

        @Test
        @DisplayName("Should decode valid validation")
        void shouldDecodeValidToken() {
            // When decoding a valid token, it should not throw an exception
            DecodedJwt jwt = parser.decode(VALID_TOKEN);

            // Verify header
            var header = jwt.header();
            assertNotNull(header, "Header should be present");
            assertNotNull(header.alg(), "Algorithm should be present");
            assertEquals("RS256", header.alg(), "Algorithm should be RS256");
            assertEquals("JWT", header.getTyp().orElse(""), "Type should be JWT");
            assertEquals("test-key-id", header.getKid().orElse(""), "Key ID should match expected");

            // Verify body
            var body = jwt.body();
            assertNotNull(body, "Body should be present");
            assertFalse(body.isEmpty(), "Body should not be empty");
            assertEquals("1234567890", body.getString("sub").orElse(""), "Subject should match expected");
            assertEquals("John Doe", body.getString("name").orElse(""), "Name should match expected");
            assertEquals("https://example.com", body.getString("iss").orElse(""), "Issuer should match expected");
            assertEquals(1735689600, body.getNumber("exp").orElse(0).intValue(), "Expiration should match expected");

            // Verify signature
            assertNotNull(jwt.signature(), "Signature should be present");

            // Verify extracted fields
            assertTrue(jwt.getIssuer().isPresent(), "Issuer should be present");
            assertEquals("https://example.com", jwt.getIssuer().get(), "Issuer should match expected");

            assertTrue(jwt.getKid().isPresent(), "Key ID should be present");
            assertEquals("test-key-id", jwt.getKid().get(), "Key ID should match expected");

            // Verify raw token
            assertEquals(VALID_TOKEN, jwt.rawToken(), "Raw token should match original");
        }
    }

    @Nested
    @DisplayName("Invalid Token Tests")
    class InvalidTokenTests {

        static Stream<Arguments> invalidTokenProvider() {
            return Stream.of(
                    Arguments.of("invalid.validation", "Should not decode a validation with invalid format"),
                    Arguments.of("invalid.base64.encoding", "Should not decode a validation with invalid Base64 encoding")
            );
        }

        // Note: Empty/null token validation is now handled by TokenStringValidator (precondition)

        @ParameterizedTest
        @MethodSource("invalidTokenProvider")
        @DisplayName("Should handle invalid validation format")
        void shouldHandleInvalidTokenFormat(String invalidToken, String message) {
            // When decoding an invalid token, it should throw a TokenValidationException
            TokenValidationException exception = assertThrows(TokenValidationException.class, () -> parser.decode(invalidToken),
                    message);

            // Verify the exception has a valid event type
            assertNotNull(exception.getEventType(), "Exception should have an event type");
            // The tokens provided don't have valid JWT structure (missing periods), so they fail during decode
            assertTrue(
                    exception.getEventType() == EventType.INVALID_JWT_FORMAT ||
                            exception.getEventType() == EventType.FAILED_TO_DECODE_JWT,
                    "Exception should have INVALID_JWT_FORMAT or FAILED_TO_DECODE_JWT event type");

            // Verify log message - could be either depending on the failure mode
            // Try to assert either message might be present, catch the assertion error
            try {
                LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                        JWTValidationLogMessages.WARN.INVALID_JWT_FORMAT.resolveIdentifierString());
            } catch (AssertionError e) {
                // If first assertion fails, the second must pass
                LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                        JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT.resolveIdentifierString());
            }
        }

        @Test
        @DisplayName("Should handle invalid JSON")
        void shouldHandleInvalidJson() {
            String invalidHeader = Base64.getUrlEncoder().encodeToString("not json".getBytes(StandardCharsets.UTF_8));
            String invalidToken = invalidHeader + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            // When decoding a token with invalid JSON, it should throw a TokenValidationException
            TokenValidationException exception = assertThrows(TokenValidationException.class, () -> parser.decode(invalidToken),
                    "Should throw TokenValidationException for token with invalid JSON");

            // Verify the exception has a valid event type
            assertNotNull(exception.getEventType(), "Exception should have an event type");
        }
    }

    @Nested
    @DisplayName("Missing Field Tests")
    class MissingFieldTests {

        @Test
        @DisplayName("Should handle missing issuer")
        void shouldHandleMissingIssuer() {
            String payloadWithoutIssuer = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"exp\":1735689600}";
            String encodedPayloadWithoutIssuer = Base64.getUrlEncoder().encodeToString(payloadWithoutIssuer.getBytes(StandardCharsets.UTF_8));
            String tokenWithoutIssuer = ENCODED_HEADER + "." + encodedPayloadWithoutIssuer + "." + ENCODED_SIGNATURE;

            // When decoding a token without issuer, it should not throw an exception
            DecodedJwt jwt = parser.decode(tokenWithoutIssuer);

            // Verify issuer is not present
            assertFalse(jwt.getIssuer().isPresent(), "Issuer should not be present");
            assertEquals(tokenWithoutIssuer, jwt.rawToken(), "Raw validation should match the original validation");
        }

        @Test
        @DisplayName("Should handle missing kid")
        void shouldHandleMissingKid() {
            String headerWithoutKid = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
            String encodedHeaderWithoutKid = Base64.getUrlEncoder().encodeToString(headerWithoutKid.getBytes(StandardCharsets.UTF_8));
            String tokenWithoutKid = encodedHeaderWithoutKid + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            // When decoding a token without kid, it should not throw an exception
            DecodedJwt jwt = parser.decode(tokenWithoutKid);

            // Verify kid is not present
            assertFalse(jwt.getKid().isPresent(), "Key ID should not be present");
            assertEquals(tokenWithoutKid, jwt.rawToken(), "Raw validation should match the original validation");
        }
    }

    @Nested
    @DisplayName("Token Size Tests")
    class TokenSizeTests {

        // Note: Token size validation is now handled by TokenStringValidator (precondition).
        // Max token size tests have been moved to TokenStringValidatorTest.

        @Test
        @DisplayName("Should count DECODED_PART_SIZE_EXCEEDED event")
        void shouldCountDecodedPartSizeExceededEvent() {
            // Create a validation with a very large decoded part (header)
            // Make sure it's larger than the max payload size
            String largeJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key-id\",\"data\":\""
                    + "a".repeat(ParserConfig.DEFAULT_MAX_PAYLOAD_SIZE + 1000) + "\"}";

            byte[] decodedBytes = largeJson.getBytes(StandardCharsets.UTF_8);

            String encodedLargeHeader = Base64.getUrlEncoder().encodeToString(decodedBytes);
            String tokenWithLargeHeader = encodedLargeHeader + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            // Create a parser with a security event counter we can check and a custom config with a small max payload size
            // but a large max validation size to ensure the validation passes the validation size check
            SecurityEventCounter counter = new SecurityEventCounter();
            ParserConfig config = ParserConfig.builder()
                    .maxPayloadSize(1024) // Use a small max payload size to ensure our test data exceeds it
                    .maxTokenSize(100000) // Use a large max validation size to ensure the validation passes the validation size check
                    .build();
            NonValidatingJwtParser testParser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .config(config)
                    .build();

            // When decoding a token with a large decoded part, it should throw a TokenValidationException
            TokenValidationException exception = assertThrows(TokenValidationException.class, () -> testParser.decode(tokenWithLargeHeader),
                    "Should throw TokenValidationException for token with large decoded part");

            // Verify the exception has the correct event type
            assertEquals(EventType.DECODED_PART_SIZE_EXCEEDED, exception.getEventType(),
                    "Exception should have DECODED_PART_SIZE_EXCEEDED event type");

            // Check the event count
            assertEquals(1, counter.getCount(SecurityEventCounter.EventType.DECODED_PART_SIZE_EXCEEDED),
                    "Should count DECODED_PART_SIZE_EXCEEDED event");

            // Verify log message
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.DECODED_PART_SIZE_EXCEEDED.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should throw NullPointerException when securityEventCounter is not set")
        void shouldThrowWhenSecurityEventCounterNotSet() {
            var builder = NonValidatingJwtParser.builder();
            assertThrows(NullPointerException.class, builder::build);
        }

        @Test
        @DisplayName("Should create builder with defaults")
        void shouldCreateBuilderWithDefaults() {
            NonValidatingJwtParser defaultParser = NonValidatingJwtParser.builder().securityEventCounter(new SecurityEventCounter()).build();
            assertNotNull(defaultParser, "Should create a parser with default settings");

            // Verify it works with a valid validation
            DecodedJwt result = defaultParser.decode(VALID_TOKEN);
            assertNotNull(result, "Default parser should decode a valid validation");
            assertEquals(VALID_TOKEN, result.rawToken(), "Raw validation should match the original validation");
        }
    }

    @Nested
    @DisplayName("Security Event Tests")
    class SecurityEventTests {

        @Test
        @DisplayName("Should count FAILED_TO_DECODE_JWT event")
        void shouldCountFailedToDecodeJwtEvent() {
            // Create a parser with a security event counter we can check
            SecurityEventCounter counter = new SecurityEventCounter();
            NonValidatingJwtParser testParser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .build();

            // When - try to decode an invalid validation that will cause a general decoding failure
            // Create a validation with 3 parts but invalid Base64 in the middle part to trigger a JSON parsing exception
            String invalidToken = "eyJhbGciOiJIUzI1NiJ9.invalid_base64_payload.signature";

            // When decoding an invalid token, it should throw a TokenValidationException
            TokenValidationException exception = assertThrows(TokenValidationException.class, () -> testParser.decode(invalidToken),
                    "Should throw TokenValidationException for token with invalid Base64 encoding");

            // Verify the exception has the correct event type
            assertEquals(EventType.FAILED_TO_DECODE_JWT, exception.getEventType(),
                    "Exception should have FAILED_TO_DECODE_JWT event type");

            // Verify the counter was incremented
            assertEquals(1, counter.getCount(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT),
                    "Should count FAILED_TO_DECODE_JWT event");
        }

        // Note: TOKEN_SIZE_EXCEEDED is now handled by TokenStringValidator (precondition)
    }

    @Nested
    @DisplayName("Security Measures Tests")
    class SecurityMeasuresTest {

        @Test
        @DisplayName("Should respect JSON depth limits")
        void shouldRespectJsonDepthLimits() {
            // Create a deeply nested JSON structure that exceeds the max depth
            StringBuilder nestedJson = new StringBuilder("{");
            for (int i = 0; i < 20; i++) { // Create deep nesting
                nestedJson.append("\"level").append(i).append("\":{");
            }
            // Close all the nested objects
            nestedJson.append("}".repeat(20));

            String encodedNestedJson = Base64.getUrlEncoder().encodeToString(nestedJson.toString().getBytes(StandardCharsets.UTF_8));
            String tokenWithDeepJson = encodedNestedJson + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            // When decoding a token with JSON exceeding max depth, it should throw a TokenValidationException
            TokenValidationException exception = assertThrows(TokenValidationException.class, () -> parser.decode(tokenWithDeepJson),
                    "Should throw TokenValidationException for token with JSON exceeding max depth");

            // Verify the exception has a valid event type
            assertNotNull(exception.getEventType(), "Exception should have an event type");
        }

        @Test
        @DisplayName("Should handle large JSON arrays")
        void shouldHandleLargeJsonArrays() {
            // Create a JSON with a large array and required alg field
            StringBuilder largeArrayJson = new StringBuilder("{\"alg\":\"RS256\",\"array\":[");
            for (int i = 0; i < 99; i++) { // Create reasonably sized array
                if (i > 0) {
                    largeArrayJson.append(",");
                }
                largeArrayJson.append("\"item").append(i).append("\"");
            }
            largeArrayJson.append("]}");

            String encodedLargeArrayJson = Base64.getUrlEncoder().encodeToString(largeArrayJson.toString().getBytes(StandardCharsets.UTF_8));
            String tokenWithLargeArray = encodedLargeArrayJson + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            // When decoding a token with large JSON array within limits, it should not throw an exception
            DecodedJwt result = parser.decode(tokenWithLargeArray);

            // Verify the array was parsed correctly
            var header = result.header();
            assertNotNull(header, "Header should be present");
            assertNotNull(header.alg(), "Algorithm should be present");
            // Note: With new header structure, the array would be in the body, not header
        }

        @Test
        @DisplayName("Should handle large JSON strings")
        void shouldHandleLargeJsonStrings() {
            // Create a JSON with a large string and required alg field
            String largeStringJson = "{\"alg\":\"RS256\",\"largeString\":\"" + "a".repeat(ParserConfig.DEFAULT_MAX_STRING_LENGTH - 100) + "\"}";

            String encodedLargeStringJson = Base64.getUrlEncoder().encodeToString(largeStringJson.getBytes(StandardCharsets.UTF_8));
            String tokenWithLargeString = encodedLargeStringJson + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            // When decoding a token with large JSON string within limits, it should not throw an exception
            DecodedJwt result = parser.decode(tokenWithLargeString);

            // Verify the string was parsed correctly
            var header = result.header();
            assertNotNull(header, "Header should be present");
            assertNotNull(header.alg(), "Algorithm should be present");
            // Note: With new header structure, the large string would be in the body, not header
        }

        @Test
        @DisplayName("Should reject a mapped JSON string value longer than maxStringLength")
        void shouldRejectOverLimitJsonString() {
            // A mapped string value (kid) one byte past the DSL-JSON maxStringLength (4 KB) must be
            // rejected. The value goes in a mapped field so DSL-JSON reads it into the string buffer
            // (unmapped fields are skipped without buffering); maxPayloadSize is raised well above the
            // string so the string-length limit — not the payload-size limit — is the check that fires.
            SecurityEventCounter counter = new SecurityEventCounter();
            ParserConfig config = ParserConfig.builder()
                    .maxStringLength(ParserConfig.DEFAULT_MAX_STRING_LENGTH)
                    .maxPayloadSize(ParserConfig.DEFAULT_MAX_STRING_LENGTH * 4)
                    .maxTokenSize(ParserConfig.DEFAULT_MAX_STRING_LENGTH * 8)
                    .build();
            NonValidatingJwtParser overLimitParser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .config(config)
                    .build();

            String overLimitKid = "a".repeat(ParserConfig.DEFAULT_MAX_STRING_LENGTH + 1);
            String overLimitJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + overLimitKid + "\"}";
            String encodedOverLimit = Base64.getUrlEncoder().encodeToString(overLimitJson.getBytes(StandardCharsets.UTF_8));
            String tokenWithOverLimitString = encodedOverLimit + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> overLimitParser.decode(tokenWithOverLimitString),
                    "A JSON string exceeding maxStringLength must be rejected");
            assertEquals(EventType.FAILED_TO_DECODE_JWT, exception.getEventType(),
                    "An over-limit string must be rejected as a decode failure");
            assertEquals(1, counter.getCount(EventType.FAILED_TO_DECODE_JWT),
                    "Should count the FAILED_TO_DECODE_JWT event exactly once");
        }

        @Test
        @DisplayName("Should reject a payload whose nesting depth exceeds maxNestingDepth")
        void shouldRejectJsonExceedingMaxNestingDepth() {
            SecurityEventCounter counter = new SecurityEventCounter();
            ParserConfig config = ParserConfig.builder().maxNestingDepth(3).build();
            NonValidatingJwtParser boundedParser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .config(config)
                    .build();

            // Five levels of object nesting — two past the configured max of 3.
            String deepJson = "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":1}}}}}";
            String encodedDeep = Base64.getUrlEncoder().encodeToString(deepJson.getBytes(StandardCharsets.UTF_8));
            String tokenWithDeepHeader = encodedDeep + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> boundedParser.decode(tokenWithDeepHeader),
                    "A payload nested deeper than maxNestingDepth must be rejected");
            assertEquals(EventType.JSON_STRUCTURE_BOUNDS_EXCEEDED, exception.getEventType(),
                    "Over-depth nesting must fail closed with a typed structural-bounds rejection");
            assertEquals(1, counter.getCount(EventType.JSON_STRUCTURE_BOUNDS_EXCEEDED),
                    "Should count the structural-bounds rejection exactly once");
        }

        @Test
        @DisplayName("Should reject a payload whose array size exceeds maxArraySize")
        void shouldRejectJsonArrayExceedingMaxArraySize() {
            SecurityEventCounter counter = new SecurityEventCounter();
            ParserConfig config = ParserConfig.builder().maxArraySize(5).build();
            NonValidatingJwtParser boundedParser = NonValidatingJwtParser.builder()
                    .securityEventCounter(counter)
                    .config(config)
                    .build();

            // A ten-element array — twice the configured max of 5.
            String arrayJson = "{\"arr\":[1,2,3,4,5,6,7,8,9,10]}";
            String encodedArray = Base64.getUrlEncoder().encodeToString(arrayJson.getBytes(StandardCharsets.UTF_8));
            String tokenWithLargeArrayHeader = encodedArray + "." + ENCODED_PAYLOAD + "." + ENCODED_SIGNATURE;

            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> boundedParser.decode(tokenWithLargeArrayHeader),
                    "A payload with an array larger than maxArraySize must be rejected");
            assertEquals(EventType.JSON_STRUCTURE_BOUNDS_EXCEEDED, exception.getEventType(),
                    "Over-size arrays must fail closed with a typed structural-bounds rejection");
            assertEquals(1, counter.getCount(EventType.JSON_STRUCTURE_BOUNDS_EXCEEDED),
                    "Should count the structural-bounds rejection exactly once");
        }

        @Test
        @DisplayName("Should use cached JsonReaderFactory")
        void shouldUseCachedJsonReaderFactory() {
            // This test verifies that the JsonReaderFactory is cached and reused
            // We can't directly test the caching behavior, but we can verify that
            // the parser works correctly after the JsonReaderFactory is created

            // First decode should create and cache the JsonReaderFactory
            DecodedJwt result1 = parser.decode(VALID_TOKEN);

            // Second decode should use the cached JsonReaderFactory
            DecodedJwt result2 = parser.decode(VALID_TOKEN);

            // Both results should be equal
            assertEquals(result1.rawToken(), result2.rawToken(),
                    "Both decodes should produce the same result");
        }
    }
}

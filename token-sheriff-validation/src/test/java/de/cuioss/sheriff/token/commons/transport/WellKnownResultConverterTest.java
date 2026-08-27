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

import de.cuioss.http.client.ContentType;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for direct String → WellKnownResult converter.
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@DisplayName("WellKnownConfigurationConverter")
class WellKnownResultConverterTest {

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

    /** The knob a well-known bounded-read failure must name as the origin of its ceiling. */
    private static final String BOUND_ORIGIN_KNOB = "WellKnownConfig.parserConfig.maxPayloadSize";

    private WellKnownConfigurationConverter converter;

    @BeforeEach
    void setUp() {
        ParserConfig config = ParserConfig.builder().build();
        converter = new WellKnownConfigurationConverter(config.getDslJson(), new SecurityEventCounter(), 8 * 1024);
    }

    @Test
    @DisplayName("Should convert valid JSON string to WellKnownResult")
    void shouldConvertValidJsonStringToWellKnownConfiguration() {
        Optional<WellKnownResult> result = converter.convert(VALID_JSON);

        assertTrue(result.isPresent());
        WellKnownResult config = result.get();
        assertEquals("https://example.com", config.issuer);
        assertEquals("https://example.com/.well-known/jwks.json", config.jwksUri);
    }

    @Test
    @DisplayName("Should convert minimal JSON to WellKnownResult")
    void shouldConvertMinimalJsonToWellKnownConfiguration() {
        Optional<WellKnownResult> result = converter.convert(MINIMAL_JSON);

        assertTrue(result.isPresent());
        WellKnownResult config = result.get();
        assertEquals("https://example.com", config.issuer);
        assertEquals("https://example.com/.well-known/jwks.json", config.jwksUri);
    }

    @Test
    @DisplayName("Should handle empty JSON response")
    void shouldHandleEmptyJsonResponse() {
        Optional<WellKnownResult> result = converter.convert("");

        assertFalse(result.isPresent());
    }

    @Test
    @DisplayName("Should handle null input")
    void shouldHandleNullInput() {
        Optional<WellKnownResult> result = converter.convert(null);

        assertFalse(result.isPresent());
    }

    @Test
    @DisplayName("Should handle non-String input")
    void shouldHandleNonStringInput() {
        Optional<WellKnownResult> result = converter.convert(12345);

        assertFalse(result.isPresent());
    }

    @Test
    @DisplayName("Should handle malformed JSON")
    void shouldHandleMalformedJson() {
        String malformedJson = "{invalid json}";

        Optional<WellKnownResult> result = converter.convert(malformedJson);

        assertFalse(result.isPresent());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                TransportLogMessages.ERROR.JSON_PARSE_FAILED.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should log JSON_PARSING_FAILED for oversized content")
    void shouldLogJsonParsingFailedForOversizedContent() {
        // Create a large JSON that exceeds the max allowed size
        ParserConfig restrictedConfig = ParserConfig.builder()
                .maxPayloadSize(50) // Very small size to trigger the error
                .build();
        WellKnownConfigurationConverter restrictedConverter = new WellKnownConfigurationConverter(restrictedConfig.getDslJson(), new SecurityEventCounter(), 8 * 1024);

        String largeJson = "{\"issuer\": \"" + "x".repeat(100) + "\"}";
        Optional<WellKnownResult> result = restrictedConverter.convert(largeJson);

        assertFalse(result.isPresent());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                TransportLogMessages.ERROR.JSON_PARSE_FAILED.resolveIdentifierString());
    }

    @Test
    @DisplayName("Should handle missing required issuer field")
    void shouldHandleMissingRequiredIssuerField() {
        String invalidJson = """
                {
                    "jwks_uri": "https://example.com/.well-known/jwks.json"
                }
                """;

        Optional<WellKnownResult> result = converter.convert(invalidJson);

        assertFalse(result.isPresent());
    }

    @Test
    @DisplayName("Should handle missing required jwks_uri field")
    void shouldHandleMissingRequiredJwksUriField() {
        String invalidJson = """
                {
                    "issuer": "https://example.com"
                }
                """;

        Optional<WellKnownResult> result = converter.convert(invalidJson);

        assertFalse(result.isPresent());
    }

    @Test
    @DisplayName("Should throw TransportException for content size violations")
    void shouldThrowTransportExceptionForContentSizeViolations() {
        ParserConfig config = ParserConfig.builder().build();
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();
        int maxContentSize = 10; // Very small limit
        WellKnownConfigurationConverter restrictiveConverter =
                new WellKnownConfigurationConverter(config.getDslJson(), securityEventCounter, maxContentSize);

        String largeJson = """
                {
                    "issuer": "https://example.com/with/very/long/path/that/exceeds/limit",
                    "jwks_uri": "https://example.com/.well-known/jwks.json"
                }
                """;

        TransportException thrown = assertThrows(TransportException.class, () ->
                restrictiveConverter.convert(largeJson));

        assertTrue(thrown.getMessage().contains(BOUND_ORIGIN_KNOB),
                "Rejection must name the knob that set the ceiling, but was: " + thrown.getMessage());
        assertTrue(thrown.getMessage().contains(String.valueOf(maxContentSize)),
                "Rejection must report the enforced ceiling, but was: " + thrown.getMessage());
        assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED) > 0);

        // Verify the log message was written, and that it carries the same origin as the exception
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.JWKS_JSON_PARSE_FAILED.resolveIdentifierString());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, BOUND_ORIGIN_KNOB);
    }

    @Test
    @DisplayName("Should name the bound origin when rejecting an over-limit body during streaming")
    void shouldNameBoundOriginWhenRejectingOverLimitBodyDuringStreaming() {
        ParserConfig config = ParserConfig.builder().build();
        int maxContentSize = 64;
        WellKnownConfigurationConverter restrictiveConverter =
                new WellKnownConfigurationConverter(config.getDslJson(), new SecurityEventCounter(), maxContentSize);
        byte[] overLimit = "x".repeat(maxContentSize + 40).getBytes(StandardCharsets.UTF_8);

        var result = BoundedBodyHandlerTestSupport.drive(restrictiveConverter.getBodyHandler(), overLimit, null);

        assertFalse(result.succeeded(), "Over-limit well-known body must fail closed during streaming");
        assertNotNull(result.failure());
        assertTrue(result.failure().getMessage().contains(BOUND_ORIGIN_KNOB),
                "Streaming rejection must name the same knob as the post-materialization rejection, but was: "
                        + result.failure().getMessage());
        assertTrue(result.failure().getMessage().contains(String.valueOf(maxContentSize)),
                "Streaming rejection must report the enforced ceiling, but was: " + result.failure().getMessage());
    }

    @Test
    @DisplayName("Should provide a bounded String BodyHandler")
    void shouldProvideAppropriateBodyHandler() {
        var bodyHandler = converter.getBodyHandler();

        assertNotNull(bodyHandler, "getBodyHandler must return a non-null body handler");

        // H2 (a0e4f81e) wraps the discovery body in a BoundedBodyHandlers streaming size ceiling, so
        // the handler is deliberately no longer the plain HttpResponse.BodyHandlers.ofString. Assert
        // it still functions as a String body handler (produces a subscriber for a 200 response)
        // rather than pinning its now-bounded implementation class.
        HttpResponse.ResponseInfo responseInfo = BoundedBodyHandlerTestSupport.responseInfo(null);
        assertNotNull(bodyHandler.apply(responseInfo),
                "The bounded body handler must produce a subscriber for a successful response");
    }

    @Test
    @DisplayName("Should return APPLICATION_JSON content type")
    void shouldReturnApplicationJsonContentType() {
        var contentType = converter.contentType();

        assertNotNull(contentType);
        assertEquals(ContentType.APPLICATION_JSON, contentType);
    }
}

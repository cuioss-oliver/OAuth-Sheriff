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
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for DoS protection against oversized JWKS arrays.
 * This is a critical security test to prevent memory exhaustion attacks.
 */
@EnableTestLogger
@DisplayName("Tests JwksParser protection against oversized arrays (DoS protection)")
class JwksParserLargeArrayTest {

    private JwksParser parser;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        parser = new JwksParser(ParserConfig.builder().build(), securityEventCounter);
    }

    @Test
    @DisplayName("Should reject JWKS with more than 50 keys (DoS protection)")
    void shouldRejectOversizedJwksArray() {
        // Create a JWKS with 51 keys (exceeds limit of 50)
        StringBuilder jwksBuilder = new StringBuilder("{\"keys\":[");
        for (int i = 0; i < 51; i++) {
            if (i > 0) jwksBuilder.append(",");
            jwksBuilder.append("""
                    {
                        "kty": "RSA",
                        "kid": "key-%d",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus-%d",
                        "e": "AQAB"
                    }""".formatted(i, i));
        }
        jwksBuilder.append("]}");

        String oversizedJwks = jwksBuilder.toString();

        // Parse the oversized JWKS
        List<JwkKey> result = parser.parse(oversizedJwks);

        // Should reject the entire JWKS for security
        assertTrue(result.isEmpty(), "Should reject oversized JWKS for DoS protection");

        // Verify the warning was logged
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.WARN.JWKS_KEYS_ARRAY_TOO_LARGE.resolveIdentifierString());

        // Verify the security event was counted
        assertEquals(1, securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED),
                "Should count as security event");
    }

    @Test
    @DisplayName("Should accept JWKS with exactly 50 keys (at limit)")
    void shouldAcceptMaxSizeJwksArray() {
        // Create a JWKS with exactly 50 keys (at the limit)
        StringBuilder jwksBuilder = new StringBuilder("{\"keys\":[");
        for (int i = 0; i < 50; i++) {
            if (i > 0) jwksBuilder.append(",");
            jwksBuilder.append("""
                    {
                        "kty": "RSA",
                        "kid": "key-%d",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "test-modulus-%d",
                        "e": "AQAB"
                    }""".formatted(i, i));
        }
        jwksBuilder.append("]}");

        String maxSizeJwks = jwksBuilder.toString();

        // Parse the max-size JWKS
        List<JwkKey> result = parser.parse(maxSizeJwks);

        // Should accept exactly 50 keys
        assertEquals(50, result.size(), "Should accept all 50 keys (at limit)");

        // No security event should be counted
        assertEquals(0, securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED),
                "Should not count as error for exactly 50 keys");
    }
}
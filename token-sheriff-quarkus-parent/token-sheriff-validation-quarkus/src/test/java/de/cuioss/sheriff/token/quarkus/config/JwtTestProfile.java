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
package de.cuioss.sheriff.token.quarkus.config;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.HashMap;
import java.util.Map;

/**
 * Test profile for JWT tests, providing test configuration values.
 * <p>
 * This profile can be used with the {@link io.quarkus.test.junit.TestProfile} annotation
 * to override configuration for tests.
 * <p>
 * Example usage:
 * <pre>
 * {@code
 * @QuarkusTest
 * @TestProfile(JwtTestProfile.class)
 * public class MyTest {
 *     // test methods
 * }
 * }
 * </pre>
 */
public class JwtTestProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> config = new HashMap<>();

        // Override default issuer configuration from application.properties
        config.put(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("default"), "https://example.com/auth");
        config.put(JwtPropertyKeys.ISSUERS.ENABLED.formatted("default"), "true");
        config.put(JwtPropertyKeys.ISSUERS.JWKS_FILE_PATH.formatted("default"), ""); // Clear file path
        // A valid 2048-bit RSA public key (RFC 7638 example). The previous test key was 1904-bit,
        // which the module now rejects (weak-RSA hardening: minimum 2048 bits). The health check only
        // needs a parseable key for loader status — no test signs tokens against this JWKS.
        config.put(JwtPropertyKeys.ISSUERS.JWKS_CONTENT.formatted("default"),
                "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"default-key-1\",\"alg\":\"RS256\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\"}]}");

        // Disable audience validation for test (no real audience in tests)
        config.put(JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("default"), "true");

        // Disable test-issuer from application.properties
        config.put(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test-issuer"), "false");

        // Global parser configuration
        config.put(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, "8192");
        config.put(JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE, "8192");
        config.put(JwtPropertyKeys.PARSER.MAX_STRING_LENGTH, "4096");
        // Health check configuration
        config.put(JwtPropertyKeys.HEALTH.JWKS.CACHE_SECONDS, "30");

        return config;
    }
}

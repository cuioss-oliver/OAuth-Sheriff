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

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.commons.transport.JwkKey;
import de.cuioss.sheriff.token.commons.transport.Jwks;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses and validates JWKS content using DSL-JSON for high-performance parsing.
 * This class is responsible for:
 * <ul>
 *   <li>Parsing JSON content with security limits using DSL-JSON</li>
 *   <li>Validating JWKS structure and constraints</li>
 *   <li>Extracting keys from JWKS structure</li>
 *   <li>Handling both standard JWKS format and single key format</li>
 *   <li>Security event tracking for parsing failures</li>
 * </ul>
 * @since 1.0
 */
public class JwksParser {

    private static final CuiLogger LOGGER = new CuiLogger(JwksParser.class);

    /**
     * Maximum number of keys accepted in a JWKS keys array (denial-of-service protection).
     */
    private static final int MAX_KEYS_COUNT = 50;


    private final DslJson<Object> dslJson;


    private final SecurityEventCounter securityEventCounter;


    private final ParserConfig parserConfig;

    /**
     * Create JwksParser with ParserConfig and SecurityEventCounter.
     */
    public JwksParser(ParserConfig parserConfig, SecurityEventCounter securityEventCounter) {
        this.dslJson = parserConfig.getDslJson();
        this.securityEventCounter = securityEventCounter;
        this.parserConfig = parserConfig;
    }

    /**
     * Parse JWKS content and extract individual JWK objects.
     *
     * @param jwksContent the JWKS content as a string
     * @return a list of parsed JWK objects, empty if parsing fails
     */
    public List<JwkKey> parse(String jwksContent) {
        List<JwkKey> result = new ArrayList<>();

        // Encode once and reuse the byte array for both size validation and parsing
        byte[] bytes = jwksContent.getBytes(StandardCharsets.UTF_8);

        // Check content size
        if (!validateContentSize(bytes)) {
            return result;
        }

        // First, try to parse as standard JWKS with "keys" array
        boolean jwksParsed = false;
        try {
            Jwks jwks = dslJson.deserialize(Jwks.class, bytes, bytes.length);
            if (jwks != null && jwks.keys() != null) {
                // We have a valid JWKS with keys field, let parseJwks handle validation and logging
                return parseJwks(jwks);
            }
            jwksParsed = jwks != null;  // Remember if we parsed a JWKS structure
        } catch (IOException e) {
            // JSON syntax error - continue to try single JWK parsing
        }

        // Design Decision: bare JWK fallback retained for real-world interoperability.
        // Some endpoints serve a single JWK directly rather than wrapping it in a JWKS structure.
        // The parsed key validates kty field, so accepting broader input does not weaken
        // cryptographic validation.
        // If standard JWKS parsing failed or had no keys, try parsing as single JWK
        try {
            JwkKey singleKey = dslJson.deserialize(JwkKey.class, bytes, bytes.length);
            if (singleKey != null && singleKey.kty() != null) {
                result.add(singleKey);
                return result;
            }
        } catch (IOException e) {
            // If both parsers threw IOException, it's invalid JSON
            LOGGER.error(JWTValidationLogMessages.ERROR.JWKS_INVALID_JSON, e.getMessage());
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return result;
        }

        // If we successfully parsed a JWKS but it had no keys field
        if (jwksParsed) {
            LOGGER.warn(JWTValidationLogMessages.WARN.JWKS_OBJECT_NULL);
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
        } else {
            // If both parsing attempts failed with no IOException, it's likely a structure issue
            LOGGER.warn(JWTValidationLogMessages.WARN.JWKS_KEYS_ARRAY_EMPTY);
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
        }
        return result;
    }

    /**
     * Internal method to parse a Jwks object into individual JWK objects.
     * <p>
     * The caller guarantees a non-null JWKS with a non-null keys array. This is the single
     * validation path for the keys array: emptiness, size limits, and per-key structure are
     * each checked (and logged) in exactly one place.
     *
     * @param jwks the JWKS object to parse
     * @return a list of parsed JWK objects, empty if validation fails
     */
    private List<JwkKey> parseJwks(Jwks jwks) {
        List<JwkKey> result = new ArrayList<>();
        List<JwkKey> keysArray = jwks.keys();

        if (keysArray.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.JWKS_KEYS_ARRAY_EMPTY);
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return result;
        }

        if (keysArray.size() > MAX_KEYS_COUNT) {
            LOGGER.warn(JWTValidationLogMessages.WARN.JWKS_KEYS_ARRAY_TOO_LARGE, keysArray.size());
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return result;
        }

        for (JwkKey key : keysArray) {
            if (key != null && key.kty() != null) {
                result.add(key);
            } else if (key != null) {
                // Key exists but missing kty field
                LOGGER.warn(JWTValidationLogMessages.WARN.JWK_MISSING_KTY);
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            }
        }
        return result;
    }

    /**
     * Validate JWKS content size to prevent memory exhaustion attacks.
     *
     * @param contentBytes the JWKS content as UTF-8 bytes
     * @return true if content size is within limits, false otherwise
     */
    private boolean validateContentSize(byte[] contentBytes) {
        int actualSize = contentBytes.length;
        int upperLimit = parserConfig.getMaxPayloadSize();

        if (actualSize > upperLimit) {
            LOGGER.error(JWTValidationLogMessages.ERROR.JWKS_CONTENT_SIZE_EXCEEDED, upperLimit, actualSize);
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }

        return true;
    }

}
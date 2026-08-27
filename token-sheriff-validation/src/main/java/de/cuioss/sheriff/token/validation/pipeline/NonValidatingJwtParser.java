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

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptor;
import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * This class provides a unified way to parse JWT tokens and extract common information
 * such as the header, body, signature, issuer, and kid-header.
 * <p>
 * Security features:
 * <ul>
 *   <li>Token size validation to prevent memory exhaustion</li>
 *   <li>Payload size validation for JSON parsing</li>
 *   <li>Standard Base64 decoding for JWT parts</li>
 *   <li>Proper character encoding handling</li>
 *   <li>JSON depth limits to prevent stack overflow attacks</li>
 *   <li>JSON array size limits to prevent denial-of-service attacks</li>
 *   <li>JSON string size limits to prevent memory exhaustion</li>
 * </ul>
 * <p>
 * Basic usage example:
 * <pre>
 * // Create a parser with default settings
 * NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
 *     .securityEventCounter(securityEventCounter)
 *     .build();
 *
 * // Decode a JWT token
 * Optional&lt;DecodedJwt&gt; decodedJwt = parser.decode(tokenString);
 *
 * // Access decoded JWT information using convenience methods
 * decodedJwt.ifPresent(jwt -> {
 *     // Access common JWT fields with convenience methods
 *     jwt.getAlg().ifPresent(alg -> LOGGER.debug("Algorithm: %s", alg));
 *     jwt.getIssuer().ifPresent(issuer -> LOGGER.debug("Issuer: %s", issuer));
 *     jwt.getKid().ifPresent(kid -> LOGGER.debug("Key ID: %s", kid));
 *
 *     // Access the raw token
 *     String rawToken = jwt.getRawToken();
 *
 *     // For more complex operations, access the header and body via record accessors
 *     var header = jwt.header();
 *     if (header != null) {
 *         // Process header fields not covered by convenience methods
 *     }
 *
 *     var body = jwt.body();
 *     if (!body.isEmpty()) {
 *         // Process custom claims in the body
 *         body.getString("custom_claim").ifPresent(customValue -> {});
 *     }
 * });
 * </pre>
 * <p>
 * Example with custom security settings:
 * <pre>
 * // Create a parser with custom security settings using ParserConfig
 * ParserConfig config = ParserConfig.builder()
 *     .maxTokenSize(1024)      // 1KB max token size
 *     .maxPayloadSize(512)     // 512 bytes max payload size
 *     .maxStringLength(256)    // 256 bytes max string size
 *     .maxArraySize(10)        // 10 elements max array size
 *     .maxNestingDepth(5)      // 5 levels max JSON nesting depth
 *     .build();
 *
 * NonValidatingJwtParser customParser = NonValidatingJwtParser.builder()
 *     .config(config)
 *     .securityEventCounter(securityEventCounter)
 *     .build();
 *
 * // Decode a token with the custom parser
 * Optional&lt;DecodedJwt&gt; result = customParser.decode(tokenString);
 * </pre>
 * <p>
 * Example handling empty or invalid tokens:
 * <pre>
 * // Handle empty or null tokens
 * Optional&lt;DecodedJwt&gt; emptyResult = parser.decode("");
 * assertFalse(emptyResult.isPresent());
 *
 * // Handle invalid token format
 * Optional&lt;DecodedJwt&gt; invalidResult = parser.decode("invalid.token.format");
 * assertFalse(invalidResult.isPresent());
 * </pre>
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc">Security Specification</a>
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class NonValidatingJwtParser {

    private static final CuiLogger LOGGER = new CuiLogger(NonValidatingJwtParser.class);

    /**
     * Configuration for the parser, containing all security settings.
     */
    private final ParserConfig config;

    /**
     * Counter for security events that occur during token processing.
     */
    private final SecurityEventCounter securityEventCounter;

    /**
     * Optional JWE decryption configuration. When present, 5-part JWE tokens
     * will be decrypted and the inner JWS will be parsed.
     */
    @Nullable
    private final JweDecryptionConfig jweDecryptionConfig;

    private final JweDecryptor jweDecryptor;

    private NonValidatingJwtParser(ParserConfig config, SecurityEventCounter securityEventCounter,
            @Nullable JweDecryptionConfig jweDecryptionConfig) {
        this.config = Objects.requireNonNull(config, "ParserConfig must not be null");
        this.securityEventCounter = securityEventCounter;
        this.jweDecryptionConfig = jweDecryptionConfig;
        this.jweDecryptor = jweDecryptionConfig != null ? new JweDecryptor() : null;
    }

    public static NonValidatingJwtParserBuilder builder() {
        return new NonValidatingJwtParserBuilder();
    }

    public static class NonValidatingJwtParserBuilder {
        private ParserConfig config = ParserConfig.builder().build();
        private SecurityEventCounter securityEventCounter;
        private JweDecryptionConfig jweDecryptionConfig;

        public NonValidatingJwtParserBuilder config(ParserConfig config) {
            this.config = config;
            return this;
        }

        public NonValidatingJwtParserBuilder securityEventCounter(SecurityEventCounter securityEventCounter) {
            this.securityEventCounter = securityEventCounter;
            return this;
        }

        public NonValidatingJwtParserBuilder jweDecryptionConfig(JweDecryptionConfig jweDecryptionConfig) {
            this.jweDecryptionConfig = jweDecryptionConfig;
            return this;
        }

        public NonValidatingJwtParser build() {
            Objects.requireNonNull(securityEventCounter, "SecurityEventCounter must not be null");
            return new NonValidatingJwtParser(config, securityEventCounter, jweDecryptionConfig);
        }
    }

    /**
     * Decodes a JWT token and returns a DecodedJwt object containing the decoded parts.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     * </ul>
     * <p>
     * This method logs warnings when decoding fails. Use {@link #decodeQuietly(String)}
     * to suppress warning logging.
     *
     * @param token the JWT token string to parse
     * @return the DecodedJwt if parsing is successful
     * @throws TokenValidationException if the token is invalid or cannot be parsed
     */
    public DecodedJwt decode(String token) {
        return decodeInternal(token, DecodeMode.NORMAL);
    }

    /**
     * Decodes a JWT token without logging warnings or tracking security events.
     * <p>
     * This method is specifically designed for opaque tokens (like refresh tokens) where
     * parsing failures are expected and should not be logged or tracked as security events.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     *   <li>No logging or security event tracking on failures</li>
     * </ul>
     *
     * @param token the JWT token string to parse (may be opaque)
     * @return the DecodedJwt if parsing is successful
     * @throws TokenValidationException if the token is invalid or cannot be parsed
     */
    public DecodedJwt decodeOpaqueToken(String token) {
        return decodeInternal(token, DecodeMode.OPAQUE);
    }

    /**
     * Decodes a JWT token without logging warnings, but still tracking security events.
     * <p>
     * This method is useful when re-parsing a previously validated token (e.g., for
     * DPoP validation of cached tokens) where decoding warnings are not desired.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     * </ul>
     *
     * @param token the JWT token string to parse
     * @return the DecodedJwt if parsing is successful
     * @throws TokenValidationException if the token is invalid or cannot be parsed
     */
    DecodedJwt decodeQuietly(String token) {
        return decodeInternal(token, DecodeMode.QUIET);
    }

    /**
     * Decode mode controlling logging and security event tracking behavior.
     * <ul>
     *   <li>{@code NORMAL} — log warnings and track security events (standard validation path)</li>
     *   <li>{@code QUIET} — no logging, but track security events (re-parsing cached tokens)</li>
     *   <li>{@code OPAQUE} — no logging, no tracking (opaque/refresh tokens where failures are expected)</li>
     * </ul>
     */
    private enum DecodeMode {
        NORMAL(true, true),
        QUIET(false, true),
        OPAQUE(false, false);

        private final boolean logWarnings;
        private final boolean trackSecurityEvents;

        DecodeMode(boolean logWarnings, boolean trackSecurityEvents) {
            this.logWarnings = logWarnings;
            this.trackSecurityEvents = trackSecurityEvents;
        }
    }

    /**
     * Internal method that handles token decoding with configurable logging and security tracking.
     *
     * @param token the JWT token string to parse
     * @param mode the decode mode controlling logging and security event tracking
     * @return the DecodedJwt if parsing is successful
     * @throws TokenValidationException if the token is invalid or cannot be parsed
     */
    @SuppressWarnings("java:S3776") // owolff: Justified - complexity due to logging and security event tracking
    private DecodedJwt decodeInternal(String token, DecodeMode mode) {
        // Precondition: TokenStringValidator has already validated null, blank, and size limits
        Preconditions.checkArgument(token != null && !token.isEmpty(),
                "TokenStringValidator precondition: token must not be null/empty");
        Preconditions.checkArgument(token.getBytes(StandardCharsets.UTF_8).length <= config.getMaxTokenSize(),
                "TokenStringValidator precondition: token size within limits (max: %s)", config.getMaxTokenSize());

        // Split token and validate format
        String[] parts = token.split("\\.");

        if (parts.length == 5) {
            // JWE token (5 parts: header.encryptedKey.iv.ciphertext.authTag)
            return handleJweToken(parts, token, mode.logWarnings, mode.trackSecurityEvents);
        }

        if (parts.length != 3) {
            if (mode.logWarnings) {
                LOGGER.warn(JWTValidationLogMessages.WARN.INVALID_JWT_FORMAT, parts.length);
            }
            if (mode.trackSecurityEvents) {
                securityEventCounter.increment(SecurityEventCounter.EventType.INVALID_JWT_FORMAT);
            }
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.INVALID_JWT_FORMAT,
                    JWTValidationLogMessages.WARN.INVALID_JWT_FORMAT.format(parts.length)
            );
        }

        try {
            // Decode token parts
            return decodeTokenParts(parts, token, mode.logWarnings, mode.trackSecurityEvents);
        } catch (IllegalArgumentException e) {
            if (mode.logWarnings) {
                LOGGER.warn(e, JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT);
            }
            if (mode.trackSecurityEvents) {
                securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT);
            }
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT,
                    "Failed to decode JWT: %s".formatted(e.getMessage()),
                    e
            );
        }
    }

    /**
     * Handles a 5-part JWE token by decrypting it and parsing the inner JWS.
     */
    private DecodedJwt handleJweToken(String[] parts, String originalToken,
            boolean logWarnings, boolean trackSecurityEvents) {
        validateJweConfigured(logWarnings, trackSecurityEvents);

        try {
            // Decode JWE header only (first part)
            JwtHeader jweHeader = decodeJwtHeader(parts[0]);

            // Verify this is actually a JWE (has 'enc' field)
            if (!jweHeader.isJwe()) {
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                        "5-part token does not have 'enc' header field — not a valid JWE");
            }

            // Decrypt to get inner JWS string
            String innerJws = jweDecryptor.decrypt(parts, jweHeader, jweDecryptionConfig, securityEventCounter, config.getDslJson());

            // Check inner JWS size
            if (innerJws.getBytes(StandardCharsets.UTF_8).length > config.getMaxTokenSize()) {
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED,
                        "Inner JWS from JWE exceeds maximum token size");
            }

            // Parse the inner JWS and return DecodedJwt with original JWE as rawToken
            String[] innerParts = validateInnerJwsParts(innerJws, logWarnings);
            DecodedJwt innerDecoded = decodeTokenParts(innerParts, innerJws, logWarnings, trackSecurityEvents);
            // Return with original JWE token as rawToken (for caching/logging)
            return new DecodedJwt(innerDecoded.header(), innerDecoded.body(),
                    innerDecoded.signature(), innerDecoded.parts(), originalToken);

        } catch (TokenValidationException e) {
            throw e;
        } catch (IOException e) {
            if (logWarnings) {
                LOGGER.warn(e, JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT);
            }
            if (trackSecurityEvents) {
                securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT);
            }
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT,
                    "Failed to decode JWE header: " + e.getMessage(), e);
        }
    }

    /**
     * Validates that JWE decryption is configured, throwing if it is not.
     */
    private void validateJweConfigured(boolean logWarnings, boolean trackSecurityEvents) {
        if (jweDecryptionConfig == null || jweDecryptor == null) {
            if (logWarnings) {
                LOGGER.warn(JWTValidationLogMessages.WARN.JWE_DECRYPTION_NOT_CONFIGURED);
            }
            if (trackSecurityEvents) {
                securityEventCounter.increment(SecurityEventCounter.EventType.JWE_DECRYPTION_NOT_CONFIGURED);
            }
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_NOT_CONFIGURED,
                    "Received JWE token but no decryption configuration is available");
        }
    }

    /**
     * Splits the inner JWS string and validates the part count.
     * Returns the 3 parts on success, throws {@link TokenValidationException} otherwise.
     */
    private String[] validateInnerJwsParts(String innerJws, boolean logWarnings) {
        String[] innerParts = innerJws.split("\\.");
        if (innerParts.length == 5) {
            if (logWarnings) {
                LOGGER.warn(JWTValidationLogMessages.WARN.JWE_NESTED_NOT_ALLOWED);
            }
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED,
                    "Nested JWE tokens are not allowed");
        }
        if (innerParts.length != 3) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.INVALID_JWT_FORMAT,
                    "Inner JWS from JWE has invalid format: expected 3 parts but got %d".formatted(innerParts.length));
        }
        return innerParts;
    }


    /**
     * Decodes the token parts and creates a DecodedJwt object using DSL-JSON.
     *
     * @param parts                the token parts
     * @param token                the original token
     * @param logWarnings          whether to log warnings
     * @param trackSecurityEvents  whether to track security events
     * @return the DecodedJwt if decoding is successful
     * @throws TokenValidationException if decoding fails
     */
    private DecodedJwt decodeTokenParts(String[] parts, String token, boolean logWarnings, boolean trackSecurityEvents) {
        try {
            // Decode the header (first part) to JwtHeader using DSL-JSON
            JwtHeader header = decodeJwtHeader(parts[0]);

            // Decode the payload (second part) to MapRepresentation using DSL-JSON
            MapRepresentation body = decodePayload(parts[1]);

            // The signature part (third part) is kept as is
            String signature = parts[2];

            return new DecodedJwt(header, body, signature, parts, token);
        } catch (IOException e) {
            // IOException from DSL-JSON deserialization
            if (logWarnings) {
                LOGGER.warn(e, JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT);
            }
            if (trackSecurityEvents) {
                securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT);
            }
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT,
                    "Failed to decode JWT parts: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Decodes a Base64Url encoded JWT header using DSL-JSON.
     *
     * @param encodedHeader the Base64Url encoded header part
     * @return the decoded JwtHeader
     * @throws IOException if decoding fails
     */
    private JwtHeader decodeJwtHeader(String encodedHeader) throws IOException {
        byte[] jsonBytes = decodeBase64UrlPart(encodedHeader);
        DslJson<Object> dslJson = config.getDslJson();

        JwtHeader header = dslJson.deserialize(JwtHeader.class, jsonBytes, jsonBytes.length);

        if (header == null) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT,
                    "Failed to deserialize JWT header: null result"
            );
        }

        return header;
    }

    /**
     * Decodes a Base64Url encoded JWT payload using DSL-JSON.
     *
     * @param encodedPayload the Base64Url encoded payload part
     * @return the decoded MapRepresentation
     * @throws IOException if decoding fails
     */
    private MapRepresentation decodePayload(String encodedPayload) throws IOException {
        byte[] jsonBytes = decodeBase64UrlPart(encodedPayload);
        DslJson<Object> dslJson = config.getDslJson();

        return MapRepresentation.fromJson(dslJson, jsonBytes);
    }

    /**
     * Decodes a Base64Url encoded part to its raw (UTF-8 encoded JSON) bytes.
     * <p>
     * Returning the raw bytes avoids a lossy byte-to-String-to-byte round trip and
     * guarantees that no platform-default charset is involved (JWT JSON is always UTF-8
     * per RFC 7515).
     *
     * @param encodedPart the Base64Url encoded part
     * @return the decoded JSON bytes
     */
    private byte[] decodeBase64UrlPart(String encodedPart) {
        try {
            byte[] decodedBytes = Base64.getUrlDecoder().decode(encodedPart);

            // Check payload size limit to prevent memory exhaustion attacks
            if (decodedBytes.length > config.getMaxPayloadSize()) {
                LOGGER.warn(JWTValidationLogMessages.WARN.DECODED_PART_SIZE_EXCEEDED, config.getMaxPayloadSize());
                securityEventCounter.increment(SecurityEventCounter.EventType.DECODED_PART_SIZE_EXCEEDED);
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.DECODED_PART_SIZE_EXCEEDED,
                        JWTValidationLogMessages.WARN.DECODED_PART_SIZE_EXCEEDED.format(config.getMaxPayloadSize())
                );
            }

            // Enforce structural bounds (nesting depth / array size) before handing the bytes to
            // DSL-JSON, so a deeply-nested or oversized-array payload fails closed with a typed
            // exception rather than risking a StackOverflowError during recursive parsing.
            enforceStructuralBounds(decodedBytes);

            return decodedBytes;
        } catch (IllegalArgumentException e) {
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.FAILED_TO_DECODE_JWT,
                    "Failed to decode Base64Url part: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Scans decoded JSON bytes and enforces the configured nesting-depth and array-size bounds.
     * <p>
     * The scan is a single linear pass that tracks string state (so braces/brackets inside string
     * literals are ignored) and, for every object/array frame, its depth and — for arrays — its
     * element count. Exceeding {@link ParserConfig#getMaxNestingDepth()} or
     * {@link ParserConfig#getMaxArraySize()} fails closed with a typed
     * {@link TokenValidationException}.
     *
     * @param jsonBytes the decoded (UTF-8) JSON bytes of a single JWT part
     */
    @SuppressWarnings({"java:S3776", "java:S6916"}) // single-pass state-tracking scan is a deliberate security-critical
    // DoS bound check; splitting the switch cases or the method risks introducing a subtle parsing bug
    private void enforceStructuralBounds(byte[] jsonBytes) {
        final int maxDepth = config.getMaxNestingDepth();
        final int maxArraySize = config.getMaxArraySize();
        final boolean[] frameIsArray = new boolean[maxDepth + 1];
        final int[] frameElementCount = new int[maxDepth + 1];
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;

        for (byte rawByte : jsonBytes) {
            char c = (char) rawByte;
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            switch (c) {
                case '"' -> inString = true;
                case '{', '[' -> {
                    depth++;
                    if (depth > maxDepth) {
                        rejectStructuralBounds("nesting depth exceeds the configured maximum of " + maxDepth);
                    }
                    frameIsArray[depth] = c == '[';
                    frameElementCount[depth] = 0;
                }
                case '}', ']' -> {
                    if (depth > 0) {
                        depth--;
                    }
                }
                case ',' -> {
                    if (depth > 0 && frameIsArray[depth]) {
                        frameElementCount[depth]++;
                        if (frameElementCount[depth] >= maxArraySize) {
                            rejectStructuralBounds("array size exceeds the configured maximum of " + maxArraySize);
                        }
                    }
                }
                default -> {
                    // structural scan ignores all other characters
                }
            }
        }
    }

    /**
     * Rejects a JWT part that violates the configured JSON structural bounds.
     *
     * @param reason a human-readable description of the violated bound
     */
    private void rejectStructuralBounds(String reason) {
        LOGGER.warn(JWTValidationLogMessages.WARN.JSON_STRUCTURE_BOUNDS_EXCEEDED, reason);
        securityEventCounter.increment(SecurityEventCounter.EventType.JSON_STRUCTURE_BOUNDS_EXCEEDED);
        throw new TokenValidationException(
                SecurityEventCounter.EventType.JSON_STRUCTURE_BOUNDS_EXCEEDED,
                "JSON structure bounds exceeded: " + reason
        );
    }

}

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
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;


/**
 * Configuration class for the TokenValidator using DSL-JSON.
 * <p>
 * This class provides configuration options for the TokenValidator, such as
 * maximum token size and maximum payload size.
 * It uses DSL-JSON for secure, high-performance JSON parsing with configurable limits.
 * <p>
 * <strong>Security Layers:</strong>
 * The configuration provides multiple layers of protection against various attack vectors:
 * <ul>
 *   <li><strong>maxTokenSize</strong>: Limits the entire JWT token string before any processing.
 *       This prevents oversized tokens from consuming memory or processing time.</li>
 *   <li><strong>maxPayloadSize</strong>: Limits each decoded JWT part (header, payload) after Base64 decoding.
 *       Since Base64 encoding increases size by ~33%, decoded parts are smaller than the original token.</li>
 *   <li><strong>maxStringLength</strong>: DSL-JSON enforced limit on maximum string buffer size.</li>
 * </ul>
 * <p>
 * <strong>DSL-JSON Advantages:</strong>
 * <ul>
 *   <li>Compile-time code generation - no reflection needed</li>
 *   <li>GraalVM Native Image compatible</li>
 *   <li>Configurable security limits that are actually enforced</li>
 *   <li>Superior performance compared to reflection-based JSON libraries</li>
 * </ul>
 * <p>
 * This class is immutable and thread-safe.
 * <p>
 * Usage example:
 * <pre>
 * ParserConfig config = ParserConfig.builder()
 *     .maxTokenSize(16 * 1024)
 *     .maxPayloadSize(4 * 1024)
 *     .maxStringLength(2 * 1024)
 *     .build();
 * </pre>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.1">VALIDATION-8.1: Token Size Limits</a></li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.2">VALIDATION-8.2: Safe Parsing</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc">Token Size Validation Specification</a>
 *
 * @since 1.0
 */
@Getter
@EqualsAndHashCode
@ToString
public final class ParserConfig {

    /**
     * Default maximum JWT token size (8KB).
     * Based on OAuth 2.0 BCP recommendations for token size limits.
     */
    public static final int DEFAULT_MAX_TOKEN_SIZE = 8 * 1024;

    /**
     * Default maximum payload size for decoded JWT parts (8KB).
     */
    public static final int DEFAULT_MAX_PAYLOAD_SIZE = 8 * 1024;

    /**
     * Default maximum string length for DSL-JSON parsing (4KB).
     */
    public static final int DEFAULT_MAX_STRING_LENGTH = 4 * 1024;

    /**
     * Default maximum JSON nesting depth. A JWT header/payload is shallow in practice
     * (typically 2-4 levels); this bound rejects maliciously deep structures that would
     * otherwise risk a {@link StackOverflowError} during parsing.
     */
    public static final int DEFAULT_MAX_NESTING_DEPTH = 10;

    /**
     * Default maximum number of elements in any single JSON array. Bounds the work a
     * single oversized array can force during parsing (denial-of-service protection).
     */
    public static final int DEFAULT_MAX_ARRAY_SIZE = 1000;

    /**
     * Maximum size of a JWT token in bytes to prevent overflow attacks.
     * This limit is applied to the entire token string before any processing begins.
     * Protects against denial-of-service attacks via extremely large token strings.
     */
    int maxTokenSize = DEFAULT_MAX_TOKEN_SIZE;

    /**
     * Maximum size of decoded JSON payload in bytes.
     * This limit is applied to each Base64-decoded JWT part (header, payload).
     * Since Base64 encoding increases size by ~33%, decoded parts are smaller than the original token.
     */
    int maxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE;

    /**
     * The maximum length for the string buffer in DSL-JSON.
     * <p>
     * This limit is enforced by DSL-JSON during parsing and prevents
     * attacks where extremely large strings could consume excessive memory.
     * <p>
     * Default: 4KB (4,096 bytes) - allows for reasonably large claim values while
     * preventing individual strings from consuming excessive memory.
     *
     * @return the maximum string length in bytes
     */
    int maxStringLength = DEFAULT_MAX_STRING_LENGTH;

    /**
     * Maximum JSON nesting depth honored during parsing.
     * <p>
     * Enforced by {@code NonValidatingJwtParser} on each decoded JWT part before it is
     * handed to DSL-JSON: a part whose object/array nesting exceeds this bound is rejected
     * with a typed {@code TokenValidationException} rather than risking a stack overflow.
     *
     * @return the maximum JSON nesting depth
     */
    int maxNestingDepth = DEFAULT_MAX_NESTING_DEPTH;

    /**
     * Maximum number of elements permitted in any single JSON array during parsing.
     * <p>
     * Enforced by {@code NonValidatingJwtParser} on each decoded JWT part before it is
     * handed to DSL-JSON: a part containing an array larger than this bound is rejected
     * with a typed {@code TokenValidationException}.
     *
     * @return the maximum JSON array size
     */
    int maxArraySize = DEFAULT_MAX_ARRAY_SIZE;

    /**
     * Lazy-initialized DSL-JSON instance with security settings.
     * <p>
     * This DSL-JSON instance is created only when first accessed and then cached.
     * It includes actual enforceable security settings based on the configured limits.
     * <p>
     * Unlike Jakarta JSON API, DSL-JSON actually enforces the configured limits
     * and provides compile-time code generation for better performance and security.
     * <p>
     * This DSL-JSON instance provides compile-time code generation for better performance and security.
     *
     * @return a DslJson instance configured with security settings
     */
    @Getter(lazy = true)
    private final DslJson<Object> dslJson = createDslJson();

    /**
     * Private constructor for ParserConfig.
     *
     * @param maxTokenSize the maximum token size
     * @param maxPayloadSize the maximum payload size
     * @param maxStringLength the maximum string length
     * @param maxNestingDepth the maximum JSON nesting depth
     * @param maxArraySize the maximum JSON array size
     */
    private ParserConfig(int maxTokenSize, int maxPayloadSize, int maxStringLength,
            int maxNestingDepth, int maxArraySize) {
        this.maxTokenSize = maxTokenSize;
        this.maxPayloadSize = maxPayloadSize;
        this.maxStringLength = maxStringLength;
        this.maxNestingDepth = maxNestingDepth;
        this.maxArraySize = maxArraySize;
    }

    /**
     * Creates a DSL-JSON instance with the configured security settings.
     * <p>
     * This method is used by the lazy getter for dslJson.
     * The configuration includes:
     * <ul>
     *   <li>Service loader for compile-time generated converters</li>
     *   <li>Security limits for string and digits buffers</li>
     *   <li>Support for our domain-specific record types (JWKS, WellKnownResult)</li>
     * </ul>
     *
     * @return a DslJson instance configured with security settings and compile-time mapping
     */
    private DslJson<Object> createDslJson() {
        return new DslJson<>(new DslJson.Settings<>()
                .includeServiceLoader() // Enable compile-time generated converters
                .limitStringBuffer(maxStringLength)
                .limitDigitsBuffer(16) // Reasonable limit for number parsing
                .allowArrayFormat(true) // Enable proper JSON array handling
                .skipDefaultValues(false) // Include null values in output for completeness
        );
    }

    /**
     * Creates a new builder for ParserConfig.
     *
     * @return a new ParserConfigBuilder
     */
    public static ParserConfigBuilder builder() {
        return new ParserConfigBuilder();
    }

    /**
     * Builder for ParserConfig.
     */
    public static class ParserConfigBuilder {
        private int maxTokenSize = DEFAULT_MAX_TOKEN_SIZE;
        private int maxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE;
        private int maxStringLength = DEFAULT_MAX_STRING_LENGTH;
        private int maxNestingDepth = DEFAULT_MAX_NESTING_DEPTH;
        private int maxArraySize = DEFAULT_MAX_ARRAY_SIZE;

        public ParserConfigBuilder maxTokenSize(int maxTokenSize) {
            this.maxTokenSize = maxTokenSize;
            return this;
        }

        public ParserConfigBuilder maxPayloadSize(int maxPayloadSize) {
            this.maxPayloadSize = maxPayloadSize;
            return this;
        }

        public ParserConfigBuilder maxStringLength(int maxStringLength) {
            this.maxStringLength = maxStringLength;
            return this;
        }

        public ParserConfigBuilder maxNestingDepth(int maxNestingDepth) {
            this.maxNestingDepth = maxNestingDepth;
            return this;
        }

        public ParserConfigBuilder maxArraySize(int maxArraySize) {
            this.maxArraySize = maxArraySize;
            return this;
        }

        public ParserConfig build() {
            if (maxTokenSize <= 0) {
                throw new IllegalArgumentException("maxTokenSize must be positive, but was: " + maxTokenSize);
            }
            if (maxPayloadSize <= 0) {
                throw new IllegalArgumentException("maxPayloadSize must be positive, but was: " + maxPayloadSize);
            }
            if (maxStringLength <= 0) {
                throw new IllegalArgumentException("maxStringLength must be positive, but was: " + maxStringLength);
            }
            if (maxNestingDepth <= 0) {
                throw new IllegalArgumentException("maxNestingDepth must be positive, but was: " + maxNestingDepth);
            }
            if (maxArraySize <= 0) {
                throw new IllegalArgumentException("maxArraySize must be positive, but was: " + maxArraySize);
            }
            return new ParserConfig(maxTokenSize, maxPayloadSize, maxStringLength, maxNestingDepth, maxArraySize);
        }
    }

}
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
package de.cuioss.sheriff.token.validation.metrics;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Enum defining all measurement types for JWT validation pipeline steps.
 * <p>
 * Each measurement type represents a specific phase of the JWT validation process
 * that can be independently monitored and analyzed for performance optimization.
 * <p>
 * The enum constants are ordered by their execution sequence in the validation pipeline (ordinals 0-9).
 * This natural ordering makes it easy to identify pipeline flow and bottlenecks by ordinal value.
 * <p>
 * <strong>Pipeline Execution Order (Access Token):</strong>
 * <ol>
 *   <li>COMPLETE_VALIDATION (0) - Wraps entire validation</li>
 *   <li>TOKEN_PARSING (1) - Decode Base64URL and parse JSON</li>
 *   <li>ISSUER_EXTRACTION (2) - Extract issuer claim</li>
 *   <li>CACHE_LOOKUP (3) - Check cache before expensive operations</li>
 *   <li>ISSUER_CONFIG_RESOLUTION (4) - Resolve issuer configuration</li>
 *   <li>HEADER_VALIDATION (5) - Validate JWT header</li>
 *   <li>SIGNATURE_VALIDATION (6) - Cryptographic verification (most expensive)</li>
 *   <li>TOKEN_BUILDING (7) - Build typed token object</li>
 *   <li>CLAIMS_VALIDATION (8) - Validate token claims</li>
 *   <li>CACHE_STORE (9) - Store validated token in cache</li>
 * </ol>
 * <p>
 * <strong>Pipeline Usage:</strong>
 * <ul>
 *   <li><strong>AccessTokenValidationPipeline</strong>: Uses ordinals 0-9 for complete instrumentation</li>
 *   <li><strong>IdTokenValidationPipeline</strong>: No metrics (uses NoOpMetricsTicker)</li>
 *   <li><strong>RefreshTokenValidationPipeline</strong>: No metrics (uses NoOpMetricsTicker)</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
@Getter
public enum MeasurementType {
    /**
     * 0. Complete token validation from start to finish.
     * <p>
     * Includes all pipeline steps, error handling, and represents the total
     * time taken for a JWT validation request from the perspective of the caller.
     * This is the most important metric for end-to-end performance analysis.
     */
    COMPLETE_VALIDATION("0. Complete JWT validation"),

    /**
     * 1. JWT token parsing and structure validation.
     * <p>
     * Measures time to decode Base64URL segments, parse JSON structures,
     * and validate basic JWT format. This step typically has minimal overhead
     * but can indicate issues with malformed tokens or JSON parsing performance.
     */
    TOKEN_PARSING("1. JWT token parsing"),

    /**
     * 2. Issuer extraction from decoded JWT.
     * <p>
     * Measures time to extract and validate the presence of the issuer (iss) claim
     * from the decoded JWT. This includes claim lookup and validation that the
     * issuer is present.
     */
    ISSUER_EXTRACTION("2. Issuer extraction"),

    /**
     * 3. Cache lookup operation (access tokens only).
     * <p>
     * Measures time to look up a token in the cache, including key generation
     * and hash computation. This happens BEFORE expensive signature validation
     * to maximize cache performance (addresses issue #131).
     * Only used by AccessTokenValidationPipeline.
     */
    CACHE_LOOKUP("3. Cache lookup operation"),

    /**
     * 4. Issuer configuration resolution.
     * <p>
     * Measures time to look up the appropriate issuer configuration based on the
     * issuer claim. This includes configuration cache lookups and health checks.
     * High values may indicate configuration lookup inefficiencies or cache misses.
     */
    ISSUER_CONFIG_RESOLUTION("4. Issuer config resolution"),

    /**
     * 5. JWT header validation.
     * <p>
     * Measures time to validate header claims and structure, including
     * algorithm verification, key ID extraction, and header claim validation.
     * Performance issues here may indicate problems with header processing logic.
     */
    HEADER_VALIDATION("5. JWT header validation"),

    /**
     * 6. JWT signature verification (most expensive).
     * <p>
     * Measures time for cryptographic signature validation using RSA/ECDSA algorithms.
     * This is typically the most expensive operation in JWT validation, often consuming
     * 90%+ of total validation time. Performance optimization efforts should focus here.
     * <p>
     * This is why cache lookup happens at ordinal 3 (before this step) rather than after.
     */
    SIGNATURE_VALIDATION("6. JWT signature validation"),

    /**
     * 7. Token object building.
     * <p>
     * Measures time to construct the typed token objects (AccessTokenContent,
     * IdTokenContent) from the validated JWT claims. This includes claim extraction,
     * type conversion, and object instantiation.
     */
    TOKEN_BUILDING("7. Token building"),

    /**
     * 8. JWT claims validation.
     * <p>
     * Measures time to validate token claims including expiration (exp),
     * not-before (nbf), audience (aud), issuer (iss), and other standard/custom claims.
     * This step is typically fast but can indicate issues with claim processing logic.
     */
    CLAIMS_VALIDATION("8. JWT claims validation"),

    /**
     * 9. Cache store operation (access tokens only).
     * <p>
     * Measures time to store a validated token in the cache, including
     * serialization and LRU management. This metric helps identify caching overhead.
     * Only used by AccessTokenValidationPipeline.
     */
    CACHE_STORE("9. Cache store operation");

    /**
     * Human-readable description of this measurement type for logging and monitoring.
     * Includes ordinal number prefix to indicate pipeline execution order.
     */
    private final String description;
}

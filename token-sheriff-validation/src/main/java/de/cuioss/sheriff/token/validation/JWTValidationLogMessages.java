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

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * Provides logging messages for the Token-Sheriff library module.
 * All messages follow the format: TokenSheriff-[identifier]: [message]
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-7">VALIDATION-7: Logging</a></li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-7.1">VALIDATION-7.1: Log Levels</a></li>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-7.2">VALIDATION-7.2: Log Content</a></li>
 * </ul>
 * <p>
 * For more detailed information about log messages, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/LogMessages.adoc">Log Messages Documentation</a>
 *
 * @since 1.0
 */
@UtilityClass
public final class JWTValidationLogMessages {

    private static final String PREFIX = "TokenSheriff";

    /**
     * Contains error-level log messages for significant problems that require attention.
     * These messages indicate failures that impact functionality but don't necessarily
     * prevent the application from continuing to run.
     */
    @UtilityClass
    public static final class ERROR {
        public static final LogRecord SIGNATURE_VALIDATION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(200)
                .template("Failed to validate validation signature: %s")
                .build();

        public static final LogRecord JWKS_CONTENT_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(201)
                .template("JWKS content size exceeds maximum allowed size (upperLimit=%s, actual=%s)")
                .build();

        public static final LogRecord JWKS_INVALID_JSON = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(202)
                .template("Failed to parse JWKS JSON: %s")
                .build();

        public static final LogRecord JWKS_LOAD_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(203)
                .template("Failed to load JWKS")
                .build();

        public static final LogRecord JWKS_INITIALIZATION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(205)
                .template("JWKS initialization failed: %s for issuer: %s")
                .build();

        public static final LogRecord JWKS_LOAD_EXECUTION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(206)
                .template("JWKS load execution failed: %s for issuer: %s")
                .build();
    }

    /**
     * Contains info-level log messages for general operational information.
     * These messages provide high-level information about the normal operation
     * of the application that is useful for monitoring.
     */
    @UtilityClass
    public static final class INFO {
        public static final LogRecord TOKEN_FACTORY_INITIALIZED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("TokenValidator initialized with %s")
                .build();

        public static final LogRecord JWKS_KEYS_UPDATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(2)
                .template("Keys updated due to data change - load state: %s")
                .build();

        public static final LogRecord JWKS_BACKGROUND_REFRESH_STARTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(3)
                .template("Background JWKS refresh started with interval: %s seconds")
                .build();

        public static final LogRecord ISSUER_CONFIG_SKIPPED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(4)
                .template("Skipping disabled issuer configuration %s")
                .build();

        public static final LogRecord JWKS_LOADED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(7)
                .template("JWKS loaded successfully for issuer: %s")
                .build();

        public static final LogRecord ISSUER_CONFIG_LOADED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(8)
                .template("Issuer configuration loaded successfully: %s")
                .build();

        public static final LogRecord JWE_DECRYPTION_ENABLED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(9)
                .template("JWE decryption enabled with %s decryption key(s)")
                .build();
    }

    /**
     * Contains warning-level log messages for potential issues that don't prevent
     * normal operation but may indicate problems. These messages highlight situations
     * that should be monitored or addressed to prevent future errors.
     */
    @UtilityClass
    public static final class WARN {
        public static final LogRecord TOKEN_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(100)
                .template("Token exceeds maximum size limit of %s bytes, validation will be rejected")
                .build();

        public static final LogRecord TOKEN_IS_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(101)
                .template("The given validation was empty, request will be rejected")
                .build();

        public static final LogRecord KEY_NOT_FOUND = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(102)
                .template("No key found with ID: %s")
                .build();

        public static final LogRecord FAILED_TO_DECODE_JWT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(103)
                .template("Failed to decode JWT Token")
                .build();

        public static final LogRecord INVALID_JWT_FORMAT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(104)
                .template("Invalid JWT Token format: expected 3 parts (JWS) or 5 parts (JWE) but got %s")
                .build();

        public static final LogRecord DECODED_PART_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(105)
                .template("Decoded part exceeds maximum size limit of %s bytes")
                .build();

        public static final LogRecord JSON_STRUCTURE_BOUNDS_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(108)
                .template("JSON structure bounds exceeded: %s")
                .build();

        public static final LogRecord UNSUPPORTED_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(106)
                .template("Unsupported algorithm: %s")
                .build();

        public static final LogRecord TOKEN_NBF_FUTURE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(107)
                .template("Token has a 'not before' claim that is more than %s seconds in the future")
                .build();

        public static final LogRecord MISSING_CLAIM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(109)
                .template("Token is missing required claim: %s")
                .build();

        public static final LogRecord TOKEN_EXPIRED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(110)
                .template("Token has expired")
                .build();

        public static final LogRecord AZP_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(111)
                .template("Token authorized party '%s' does not match expected client ID '%s'")
                .build();

        public static final LogRecord MISSING_RECOMMENDED_ELEMENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(112)
                .template("Missing recommended element: %s")
                .build();

        public static final LogRecord AUDIENCE_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(113)
                .template("Token audience %s does not match any of the expected audiences %s")
                .build();

        public static final LogRecord NO_ISSUER_CONFIG = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(114)
                .template("No configuration found for issuer: %s")
                .build();

        public static final LogRecord ALGORITHM_REJECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(115)
                .template("Algorithm %s is explicitly rejected for security reasons")
                .build();


        public static final LogRecord JWK_MISSING_KTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(117)
                .template("JWK is missing required field 'kty'")
                .build();

        public static final LogRecord JWK_UNSUPPORTED_KEY_TYPE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(118)
                .template("Unsupported key type: %s")
                .build();

        public static final LogRecord JWK_KEY_ID_TOO_LONG = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(119)
                .template("Key ID exceeds maximum length: %s")
                .build();

        public static final LogRecord JWK_INVALID_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(120)
                .template("Invalid or unsupported algorithm: %s")
                .build();

        public static final LogRecord BACKGROUND_REFRESH_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(122)
                .template("Background JWKS refresh failed: %s")
                .build();

        public static final LogRecord JWKS_URI_RESOLUTION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(123)
                .template("Failed to resolve JWKS URI from well-known resolver")
                .build();

        public static final LogRecord JWKS_OBJECT_NULL = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(124)
                .template("JWKS object is null")
                .build();

        public static final LogRecord JWKS_KEYS_ARRAY_TOO_LARGE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(125)
                .template("JWKS keys array exceeds maximum size: %s")
                .build();

        public static final LogRecord JWKS_KEYS_ARRAY_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(126)
                .template("JWKS keys array is empty")
                .build();

        public static final LogRecord RSA_KEY_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(127)
                .template("Failed to parse RSA key with ID %s: %s")
                .build();

        public static final LogRecord EC_KEY_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(128)
                .template("Failed to parse EC key with ID %s: %s")
                .build();

        public static final LogRecord CLAIM_SUB_OPTIONAL_WARNING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(131)
                .template("IssuerConfig for issuer '%s' has claimSubOptional=true. This is not conform to RFC 7519 which requires the 'sub' claim for ACCESS_TOKEN and ID_TOKEN types. Use this setting only when necessary and ensure appropriate alternative validation mechanisms.")
                .build();

        public static final LogRecord BACKGROUND_REFRESH_NO_HANDLER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(133)
                .template("Background refresh skipped - no HTTP handler available")
                .build();

        public static final LogRecord BACKGROUND_REFRESH_PARSE_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(134)
                .template("Background refresh parse error: %s for issuer: %s")
                .build();

        public static final LogRecord ISSUER_CONFIG_LOAD_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(135)
                .template("Failed to load issuer configuration for %s, status: %s")
                .build();

        public static final LogRecord JWKS_LOAD_TIMEOUT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(136)
                .template("Timeout waiting for JWKS to load for issuer: %s")
                .build();

        public static final LogRecord JWKS_LOAD_INTERRUPTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(137)
                .template("Interrupted while waiting for JWKS to load for issuer: %s")
                .build();

        public static final LogRecord ISSUER_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(138)
                .template("Configured issuer '%s' does not match discovered issuer '%s' from well-known document")
                .build();

        public static final LogRecord OKP_KEY_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(142)
                .template("Failed to parse OKP key with ID %s: %s")
                .build();

        public static final LogRecord TOKEN_TYPE_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(143)
                .template("Token type '%s' does not match expected type '%s'")
                .build();

        // DPoP validation issues (RFC 9449)
        public static final LogRecord DPOP_PROOF_MISSING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(144)
                .template("DPoP proof is required but the DPoP HTTP header is missing")
                .build();

        public static final LogRecord DPOP_PROOF_INVALID = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(145)
                .template("DPoP proof has invalid format: %s")
                .build();

        public static final LogRecord DPOP_PROOF_EXPIRED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(146)
                .template("DPoP proof iat claim is outside acceptable freshness window")
                .build();

        public static final LogRecord DPOP_THUMBPRINT_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(147)
                .template("DPoP proof JWK thumbprint '%s' does not match token cnf.jkt '%s'")
                .build();

        public static final LogRecord DPOP_REPLAY_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(148)
                .template("DPoP proof replay detected for jti: %s")
                .build();

        public static final LogRecord DPOP_PROOF_MISSING_CLAIM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(149)
                .template("DPoP proof is missing required claim: %s")
                .build();

        public static final LogRecord DPOP_ATH_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(150)
                .template("DPoP proof ath claim does not match access token hash")
                .build();

        public static final LogRecord DPOP_CNF_MISSING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(151)
                .template("DPoP is required but access token does not contain cnf.jkt claim")
                .build();

        // JWE decryption issues (RFC 7516)
        public static final LogRecord JWE_DECRYPTION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(152)
                .template("Failed to decrypt JWE token: %s")
                .build();

        public static final LogRecord JWE_UNSUPPORTED_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(153)
                .template("Unsupported JWE algorithm: alg=%s, enc=%s")
                .build();

        public static final LogRecord JWE_DECRYPTION_NOT_CONFIGURED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(154)
                .template("Received JWE token but no decryption configuration is available")
                .build();

        public static final LogRecord JWE_DECRYPTION_KEY_NOT_FOUND = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(155)
                .template("No decryption key found for key ID: %s")
                .build();

        public static final LogRecord JWE_COMPRESSION_NOT_SUPPORTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(156)
                .template("Unsupported JWE compression algorithm: %s")
                .build();

        public static final LogRecord JWE_NESTED_NOT_ALLOWED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(157)
                .template("Nested JWE tokens are not allowed")
                .build();

        public static final LogRecord TOKEN_AGE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(158)
                .template("Token age exceeds maximum allowed age")
                .build();

        public static final LogRecord CUSTOM_RULE_REJECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(159)
                .template("Custom validation rule rejected token: %s")
                .build();

        public static final LogRecord JWK_MISSING_KID = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(160)
                .template("JWK entry without 'kid' field skipped — kid is required for key identification")
                .build();

        public static final LogRecord JWK_RSA_DEFAULTING_TO_RS256 = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(161)
                .template("RSA JWK without 'alg' field — defaulting to RS256 for key ID: %s")
                .build();

        public static final LogRecord ACCESS_TOKEN_AUDIENCE_MISSING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(162)
                .template("Access token is missing required audience claim. Expected audience: %s")
                .build();

        public static final LogRecord DPOP_HTU_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(163)
                .template("DPoP proof htu claim '%s' does not match request URI '%s'")
                .build();

        public static final LogRecord DPOP_HTM_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(164)
                .template("DPoP proof htm claim '%s' does not match request method '%s'")
                .build();

        public static final LogRecord AUDIENCE_AZP_FALLBACK = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(165)
                .template("Audience claim missing but azp claim '%s' matches expected audience — using azp as fallback")
                .build();

        public static final LogRecord ACCESS_TOKEN_AUDIENCE_OPTIONAL_SKIPPED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(166)
                .template("Access token audience validation skipped (accessTokenAudienceOptional=true). Expected audience: %s")
                .build();

        public static final LogRecord AZP_CLIENT_ID_FALLBACK = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(167)
                .template("azp claim missing, using client_id claim '%s' for authorized party validation (RFC 9068)")
                .build();

        public static final LogRecord DUPLICATE_JWKS_KID = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(168)
                .template("Duplicate kid '%s' in JWKS: a later key overwrote an earlier one — the JWKS should carry a unique kid per key")
                .build();

        public static final LogRecord JWKS_REFRESH_RETURNED_NO_KEYS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(169)
                .template("JWKS refresh for issuer '%s' produced no usable keys — retaining the current key set instead of retiring it")
                .build();

    }

}

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
package de.cuioss.sheriff.token.quarkus;

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * Log messages for the Token-Sheriff Quarkus runtime module.
 * <p>
 * This class provides structured logging constants for runtime JWT validation functionality,
 * following the CUI logging standards with unique identifiers for each message.
 * </p>
 * <p>
 * Message ID ranges:
 * <ul>
 *   <li>001-099: INFO level messages</li>
 *   <li>100-199: WARN level messages</li>
 *   <li>200-299: ERROR level messages</li>
 * </ul>
 *
 * @since 1.0
 * @see de.cuioss.tools.logging.LogRecord
 */
@UtilityClass
public final class TokenSheriffQuarkusLogMessages {

    /**
     * The prefix for all log messages in this module.
     */
    public static final String PREFIX = "TokenSheriff_Q";

    /**
     * INFO level log messages (001-025; identifiers 017 and 018 are retired and must not be reused).
     */
    @UtilityClass
    public static final class INFO {

        public static final LogRecord RESOLVING_ISSUER_CONFIGURATIONS = LogRecordModel.builder()
                .template("Resolving issuer configurations from properties")
                .prefix(PREFIX)
                .identifier(1)
                .build();

        public static final LogRecord RESOLVED_ISSUER_CONFIGURATION = LogRecordModel.builder()
                .template("Resolved issuer configuration: %s")
                .prefix(PREFIX)
                .identifier(2)
                .build();

        public static final LogRecord RESOLVED_ENABLED_ISSUER_CONFIGURATIONS = LogRecordModel.builder()
                .template("Resolved %s enabled issuer configurations")
                .prefix(PREFIX)
                .identifier(3)
                .build();

        public static final LogRecord RESOLVED_PARSER_CONFIG = LogRecordModel.builder()
                .template("Resolved ParserConfig: maxTokenSize=%s bytes, maxPayloadSize=%s bytes, maxStringLength=%s")
                .prefix(PREFIX)
                .identifier(4)
                .build();

        public static final LogRecord INITIALIZING_JWT_VALIDATION_COMPONENTS = LogRecordModel.builder()
                .template("Initializing JWT validation components from configuration")
                .prefix(PREFIX)
                .identifier(5)
                .build();

        public static final LogRecord JWT_VALIDATION_COMPONENTS_INITIALIZED = LogRecordModel.builder()
                .template("JWT validation components initialized successfully with %s issuers")
                .prefix(PREFIX)
                .identifier(6)
                .build();

        public static final LogRecord RESOLVING_ACCESS_LOG_FILTER_CONFIG = LogRecordModel.builder()
                .template("Resolving access log filter configuration from properties")
                .prefix(PREFIX)
                .identifier(7)
                .build();

        public static final LogRecord CLAIM_MAPPER_REGISTRY_INITIALIZED = LogRecordModel.builder()
                .template("Claim mapper registry initialized with %s custom mapper(s): %s")
                .prefix(PREFIX)
                .identifier(8)
                .build();

        public static final LogRecord NO_CUSTOM_CLAIM_MAPPERS_DISCOVERED = LogRecordModel.builder()
                .template("No custom claim mappers discovered")
                .prefix(PREFIX)
                .identifier(9)
                .build();

        public static final LogRecord VALIDATION_RULE_REGISTRY_INITIALIZED = LogRecordModel.builder()
                .template("Token validation rule registry initialized with %s custom rule(s)")
                .prefix(PREFIX)
                .identifier(10)
                .build();

        public static final LogRecord NO_CUSTOM_VALIDATION_RULES_DISCOVERED = LogRecordModel.builder()
                .template("No custom token validation rules discovered")
                .prefix(PREFIX)
                .identifier(11)
                .build();

        public static final LogRecord INITIALIZING_JWT_METRICS_COLLECTOR = LogRecordModel.builder()
                .template("Initializing JwtMetricsCollector")
                .prefix(PREFIX)
                .identifier(12)
                .build();

        public static final LogRecord JWT_METRICS_COLLECTOR_INITIALIZED = LogRecordModel.builder()
                .template("JwtMetricsCollector initialized with %s event types")
                .prefix(PREFIX)
                .identifier(13)
                .build();

        public static final LogRecord RESOLVING_ACCESS_TOKEN_CACHE_CONFIG = LogRecordModel.builder()
                .template("Resolving access token cache configuration from properties")
                .prefix(PREFIX)
                .identifier(14)
                .build();

        public static final LogRecord ACCESS_TOKEN_CACHE_DISABLED = LogRecordModel.builder()
                .template("Access token cache disabled (maxSize=0)")
                .prefix(PREFIX)
                .identifier(15)
                .build();

        public static final LogRecord ACCESS_TOKEN_CACHE_CONFIGURED = LogRecordModel.builder()
                .template("Access token cache configured: maxSize=%s, evictionIntervalSeconds=%s")
                .prefix(PREFIX)
                .identifier(16)
                .build();

        public static final LogRecord JWE_DECRYPTION_CONFIG_RESOLVING = LogRecordModel.builder()
                .template("Resolving JWE decryption configuration from properties")
                .prefix(PREFIX)
                .identifier(19)
                .build();

        public static final LogRecord JWE_DECRYPTION_CONFIG_RESOLVED = LogRecordModel.builder()
                .template("JWE decryption configuration resolved with %s key(s)")
                .prefix(PREFIX)
                .identifier(20)
                .build();

        public static final LogRecord JWE_CONFIG_CHECK = LogRecordModel.builder()
                .template("JWE config check: singleKeyPath=%s, keystorePath=%s, multiKeys=%s")
                .prefix(PREFIX)
                .identifier(21)
                .build();

        public static final LogRecord JWE_DECRYPTION_NOT_CONFIGURED = LogRecordModel.builder()
                .template("No JWE decryption configuration found - JWE support disabled")
                .prefix(PREFIX)
                .identifier(22)
                .build();

        public static final LogRecord CUSTOM_ACCESS_LOG_FILTER_INITIALIZED = LogRecordModel.builder()
                .template("CustomAccessLogFilter initialized: %s")
                .prefix(PREFIX)
                .identifier(23)
                .build();

        public static final LogRecord ACCESS_LOG_ENTRY = LogRecordModel.builder()
                .template("%s")
                .prefix(PREFIX)
                .identifier(24)
                .build();

        public static final LogRecord OBSERVED_VALIDATOR_RESOLUTION = LogRecordModel.builder()
                .template("Observed TokenValidator resolution: %s")
                .prefix(PREFIX)
                .identifier(25)
                .build();
    }

    /**
     * WARN level log messages (100-104).
     */
    @UtilityClass
    public static final class WARN {

        public static final LogRecord ERROR_CHECKING_JWKS_LOADER = LogRecordModel.builder()
                .template("Error checking JWKS loader for issuer %s: %s")
                .prefix(PREFIX)
                .identifier(100)
                .build();

        public static final LogRecord BEARER_TOKEN_REQUIREMENTS_NOT_MET_DETAILED = LogRecordModel.builder()
                .template("Bearer token does not meet requirements. Missing scopes: %s, Missing roles: %s, Missing groups: %s")
                .prefix(PREFIX)
                .identifier(101)
                .build();

        public static final LogRecord BEARER_TOKEN_VALIDATION_FAILED = LogRecordModel.builder()
                .template("Bearer token validation failed: %s (eventType=%s)")
                .prefix(PREFIX)
                .identifier(102)
                .build();

        public static final LogRecord NO_MICROMETER_COUNTER_FOUND = LogRecordModel.builder()
                .template("No Micrometer counter found for event type %s, delta %s lost")
                .prefix(PREFIX)
                .identifier(103)
                .build();

        public static final LogRecord AMBIGUOUS_EXTERNAL_VALIDATORS = LogRecordModel.builder()
                .template("Multiple external TokenValidator beans found (%s) - unable to select one, reporting NOT_CONFIGURED")
                .prefix(PREFIX)
                .identifier(104)
                .build();

    }

    /**
     * ERROR level log messages (200).
     */
    @UtilityClass
    public static final class ERROR {

        public static final LogRecord VERTX_REQUEST_CONTEXT_UNAVAILABLE = LogRecordModel.builder()
                .template("Vertx HttpServerRequest context is unavailable - no active request context found")
                .prefix(PREFIX)
                .identifier(200)
                .build();
    }
}
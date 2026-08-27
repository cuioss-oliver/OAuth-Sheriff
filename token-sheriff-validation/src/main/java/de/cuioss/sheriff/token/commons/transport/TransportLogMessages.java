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

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * Log messages emitted by the {@code commons} transport layer (OIDC discovery and JWKS
 * retrieval / parsing).
 * <p>
 * These records were split out of {@code JWTValidationLogMessages} when the transport cluster
 * moved into {@code commons.transport} (Plan 05). They keep the global {@code TokenSheriff-}
 * prefix and their original identifiers so the {@code doc/LogMessages.adoc} registry and any
 * log-identifier assertions remain unchanged — only the owning Java class differs.
 * <p>
 * As part of the {@code commons} base layer, this class must not depend on the
 * {@code de.cuioss.sheriff.token.validation} packages (the ArchUnit boundary).
 *
 * @since 1.0
 */
@UtilityClass
public final class TransportLogMessages {

    private static final String PREFIX = "TokenSheriff";

    /**
     * Warn-level transport messages (WARN range 100-199).
     */
    @UtilityClass
    public static final class WARN {
        public static final LogRecord INVALID_JWKS_URI = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(116)
                .template("Creating HttpJwksLoaderConfig with invalid JWKS URI. The loader will return empty results.")
                .build();

        public static final LogRecord JWKS_JSON_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(130)
                .template("Failed to parse JWKS JSON: %s")
                .build();

        public static final LogRecord INVALID_BASE64_URL_ENCODING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(132)
                .template("Invalid Base64 URL encoding detected for JWK field: %s")
                .build();

        public static final LogRecord INSECURE_HTTP_WELLKNOWN = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(129)
                .template("Using insecure HTTP protocol for well-known discovery endpoint: %s - HTTPS should be used in production")
                .build();

        public static final LogRecord INSECURE_HTTP_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(139)
                .template("Using insecure HTTP protocol for JWKS endpoint: %s - HTTPS should be used in production")
                .build();

        public static final LogRecord JWKS_PARSE_NULL_RESULT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(140)
                .template("DSL-JSON returned null for JWKS parsing")
                .build();

        public static final LogRecord JWKS_PARSE_IO_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(141)
                .template("Failed to parse JWKS content: %s")
                .build();

        public static final LogRecord SSRF_EGRESS_BLOCKED_DISCOVERY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(168)
                .template("SSRF egress guard blocked well-known discovery fetch: %s")
                .build();
    }

    /**
     * Error-level transport messages (ERROR range 200-299).
     */
    @UtilityClass
    public static final class ERROR {
        public static final LogRecord JSON_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(204)
                .template("Failed to parse JSON from %s: %s")
                .build();
    }
}

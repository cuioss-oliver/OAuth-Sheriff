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
package de.cuioss.sheriff.token.commons.metrics;

import lombok.experimental.UtilityClass;

/**
 * Constants for Micrometer metric identifiers used in the Token-Sheriff Quarkus module.
 * <p>
 * This class follows the DSL-style nested constants pattern to organize
 * metric identifiers in a hierarchical, discoverable manner.
 * </p>
 * <p>
 * All metrics are prefixed with "sheriff.token".
 * </p>
 *
 * @since 1.0
 */
@UtilityClass
public final class MetricIdentifier {

    /**
     * The common prefix for all JWT metrics.
     */
    public static final String PREFIX = "sheriff.token";

    /**
     * Metrics related to bearer token operations.
     */
    @UtilityClass
    public static final class BEARERTOKEN {
        /**
         * Base path for bearer token metrics.
         */
        public static final String BASE = PREFIX + ".bearer.token";

        /**
         * Metric identifier for bearer token validation duration.
         * <p>
         * This metric tracks the time taken to validate a bearer token,
         * including token extraction, parsing, signature validation,
         * and authorization checks.
         * </p>
         */
        public static final String VALIDATION = BASE + ".validation";
    }

    /**
     * Metrics related to JWT validation pipeline.
     */
    @UtilityClass
    public static final class VALIDATION {
        /**
         * Base path for validation metrics.
         */
        public static final String BASE = PREFIX + ".validation";

        /**
         * Counter for validation errors by type.
         */
        public static final String ERRORS = BASE + ".errors";

        /**
         * Counter for successful validation operations by type.
         */
        public static final String SUCCESS = BASE + ".success";
    }
}
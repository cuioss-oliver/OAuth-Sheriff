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

import java.util.Map;

/**
 * Utility for looking up pre-created validators from immutable maps keyed by issuer identifier.
 * Throws {@link IllegalStateException} if the validator is not found, indicating a programming
 * error in the pipeline setup (all validators are pre-created during {@code TokenValidator} construction).
 *
 * @since 1.0
 */
final class ValidatorLookup {

    private ValidatorLookup() {
        // utility class
    }

    /**
     * Retrieves a validator from the map or throws if not found.
     *
     * @param <T>              the validator type
     * @param validators       the immutable map of validators keyed by issuer identifier
     * @param issuerIdentifier the issuer identifier to look up
     * @param validatorType    a human-readable name for error messages (e.g., "header validator")
     * @return the validator instance, never null
     * @throws IllegalStateException if no validator is found for the given issuer
     */
    static <T> T getOrThrow(Map<String, T> validators, String issuerIdentifier, String validatorType) {
        T validator = validators.get(issuerIdentifier);
        if (validator == null) {
            throw new IllegalStateException("No %s found for issuer: %s".formatted(validatorType, issuerIdentifier));
        }
        return validator;
    }
}

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
package de.cuioss.sheriff.token.validation.domain.claim.mapper;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.tools.string.Splitter;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A {@link ClaimMapper} implementation for splitting string claims by a specified character.
 * <p>
 * This mapper only works with string values and splits the string
 * using the provided split character. It trims the results and omits empty strings.
 * <p>
 * This is particularly useful for claims that contain multiple values in a single string
 * separated by a specific character (e.g., comma-separated roles, colon-separated groups).
 * <p>
 * Example usage:
 * <pre>
 * // Create a mapper that splits by comma
 * StringSplitterMapper commaMapper = new StringSplitterMapper(',');
 * 
 * // Use with a claim that contains comma-separated values
 * // e.g., "roles": "admin,user,manager"
 * ClaimValue roles = commaMapper.map(jsonObject, "roles");
 * </pre>
 *
 * @apiNote This mapper is part of the public SPI for library consumers building custom claim
 * configurations. It is not used by any built-in {@link de.cuioss.sheriff.token.validation.domain.claim.ClaimName}
 * but is available for custom claim mapping setups via {@link de.cuioss.sheriff.token.validation.IssuerConfig}.
 * @since 1.0
 */
public class StringSplitterMapper implements ClaimMapper {

    /**
     * The character to split the string by.
     */
   
    private final Character splitChar;

    /**
     * Creates a new mapper splitting on the given character.
     *
     * @param splitChar the character to split by, must not be {@code null}
     * @throws NullPointerException if splitChar is {@code null}
     */
    public StringSplitterMapper(Character splitChar) {
        this.splitChar = Objects.requireNonNull(splitChar, "splitChar must not be null");
    }

    @Override
    public ClaimValue map(MapRepresentation mapRepresentation, String claimName) {
        Optional<Object> claimValue = mapRepresentation.getValue(claimName);

        // If claim doesn't exist, return null (absent)
        if (claimValue.isEmpty()) {
            return null;
        }

        // Check if the claim value is a string
        Optional<String> optionalStringValue = mapRepresentation.getString(claimName);
        if (optionalStringValue.isEmpty()) {
            throw new IllegalArgumentException("Claim '" + claimName + "' exists but is not a string value");
        }

        String originalValue = optionalStringValue.get();
        List<String> values = Splitter.on(splitChar).trimResults().omitEmptyStrings().splitToList(originalValue);
        return ClaimValue.forList(originalValue, Collections.unmodifiableList(values));
    }
}
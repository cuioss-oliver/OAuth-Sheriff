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
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValueType;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;

import java.util.*;

/**
 * A {@link ClaimMapper} implementation for mapping JSON values to collections.
 * This mapper handles the following cases:
 * <ul>
 *   <li>JSON arrays: Converts each element to a string and adds it to the list</li>
 *   <li>JSON strings: Wraps the string in a single-element list</li>
 *   <li>Other JSON types: Converts to string and wraps in a single-element list</li>
 * </ul>
 * This is particularly useful for {@link ClaimValueType#STRING_LIST} claims.
 *
 * @since 1.0
 */
public class JsonCollectionMapper implements ClaimMapper {
    @Override
    public ClaimValue map(MapRepresentation mapRepresentation, String claimName) {
        Optional<Object> optionalValue = mapRepresentation.getValue(claimName);
        if (optionalValue.isEmpty()) {
            return null;
        }
        Object value = optionalValue.get();

        String originalValue;
        List<String> values;

        if (value instanceof List<?> list) {
            // Handle List (array): convert elements once, use the list's toString() as
            // original value (consistent with the Keycloak mappers). No attempt is made to
            // reconstruct the exact JSON source representation.
            values = list.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .toList();
            originalValue = values.toString();
        } else {
            // Handle all other types by wrapping them in a single-element list
            originalValue = value.toString();

            // Add the single value to the list
            values = new ArrayList<>();
            values.add(originalValue);
        }

        return ClaimValue.forList(originalValue, Collections.unmodifiableList(values));
    }
}

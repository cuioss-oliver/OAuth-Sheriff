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

import com.dslplatform.json.CompiledJson;

import java.util.List;
import java.util.Optional;

/**
 * Represents a JSON Web Key Set (JWKS) structure for DSL-JSON mapping.
 * <p>
 * This class uses DSL-JSON's compile-time code generation for high-performance
 * JSON parsing without reflection. It replaces manual JSON parsing with direct
 * object mapping.
 * <p>
 * The keys field is nullable to support permissive JSON parsing - business rule
 * validation should happen later in the validation chain.
 * 
 * @since 1.0
 * @author Generated
 */
@CompiledJson
public record Jwks(List<JwkKey> keys) {

    /**
     * Gets the keys list as Optional.
     * 
     * @return Optional containing the keys list, empty if null
     */
    public Optional<List<JwkKey>> getKeys() {
        return Optional.ofNullable(keys);
    }

    /**
     * Checks if this JWKS contains any keys.
     *
     * @return true if keys list is null or empty, false otherwise
     */
    public boolean isEmpty() {
        return keys == null || keys.isEmpty();
    }
}
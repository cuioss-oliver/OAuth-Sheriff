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
import org.jspecify.annotations.Nullable;

/***
 * A functional interface for mapping a claim from a {@link MapRepresentation} to a {@link ClaimValue}.
 * <p>
 * This interface is responsible for extracting and converting JWT claim values from their
 * map representation into strongly-typed {@link ClaimValue} objects. It provides the
 * foundational mapping capability for claim extraction in the JWT validation process.
 * <p>
 * The interface supports various claim types:
 * <ul>
 *   <li>Simple string claims</li>
 *   <li>Date/time claims (numeric timestamps)</li>
 *   <li>Array claims (e.g., audiences, roles, scopes)</li>
 * </ul>
 * <p>
 * Implementations handle type conversion, format validation, and null safety.
 * <p>
 * Since this is a functional interface, it can be implemented using lambda expressions
 * for custom claim mapping logic, making it flexible and extensible.
 * <p>
 * For more details on claim handling, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-structure">Token Structure</a>
 * specification.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see ClaimValue
 */
@FunctionalInterface
public interface ClaimMapper {

    /**
     * Maps a claim from a {@link MapRepresentation} to a {@link ClaimValue}.
     * <p>
     * Returns {@code null} when the claim is absent from the map representation,
     * indicating that the claim should not be stored in the token's claims map.
     *
     * @param mapRepresentation the map representation containing the claim
     * @param claimName the name of the claim in the map
     * @return the mapped claim as a ClaimValue, or {@code null} if the claim is absent
     */
    @Nullable
    ClaimValue map(MapRepresentation mapRepresentation, String claimName);
}

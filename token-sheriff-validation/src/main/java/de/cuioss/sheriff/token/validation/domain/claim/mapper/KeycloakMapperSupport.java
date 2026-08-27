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
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Collections;
import java.util.List;

/**
 * Package-private support methods shared by the Keycloak default mappers
 * ({@link KeycloakDefaultRolesMapper}, {@link KeycloakDefaultGroupsMapper}).
 *
 * @since 1.0
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class KeycloakMapperSupport {

    /**
     * Converts an extracted string list into a list-typed {@link ClaimValue}.
     * <p>
     * The list's {@code toString()} representation is used as the original string and the
     * list itself is wrapped unmodifiable.
     *
     * @param values the extracted string values, must not be {@code null}
     * @return a list-typed claim value wrapping the given values
     */
    static ClaimValue toListClaimValue(List<String> values) {
        return ClaimValue.forList(values.toString(), Collections.unmodifiableList(values));
    }
}

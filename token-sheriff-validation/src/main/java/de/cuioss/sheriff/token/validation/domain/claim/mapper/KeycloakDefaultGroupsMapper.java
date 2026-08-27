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
import de.cuioss.tools.logging.CuiLogger;

import java.util.List;
import java.util.Optional;

/**
 * A fixed-source {@link ClaimMapper} that always reads from the {@code "groups"} claim
 * in the token payload, regardless of the {@code claimName} parameter passed to
 * {@link #map(MapRepresentation, String)}.
 * <p>
 * This is intentional: Keycloak's group membership mapper always writes to the
 * {@code "groups"} claim, so the source claim is fixed by the identity provider's
 * convention. The {@code claimName} parameter identifies the <em>target</em> claim
 * in Token-Sheriff's model (e.g., {@code GROUPS}), not the source claim in the token.
 * <p>
 * Keycloak typically includes groups in the token as:
 * <pre>
 * {
 *   "groups": ["/test-group", "/admin-group"]
 * }
 * </pre>
 * <p>
 * This mapper processes the groups array and optionally removes leading path separators
 * if configured with full path set to false in Keycloak's group membership mapper.
 * <p>
 * The mapper handles:
 * <ul>
 *   <li>Missing {@code groups} claim - returns {@code null} (claim treated as absent)</li>
 *   <li>Non-array {@code groups} value - returns {@code null} (claim treated as absent)</li>
 *   <li>Empty groups array - returns claim value with empty list</li>
 *   <li>Group names with or without path prefixes</li>
 * </ul>
 *
 * @since 1.0
 * @see <a href="https://www.keycloak.org/docs/latest/server_admin/index.html#_group-mappers">Keycloak Group Mappers</a>
 */
public class KeycloakDefaultGroupsMapper implements ClaimMapper {

    private static final CuiLogger LOGGER = new CuiLogger(KeycloakDefaultGroupsMapper.class);
    private static final String GROUPS_CLAIM = "groups";

    @Override
    public ClaimValue map(MapRepresentation mapRepresentation, String claimName) {
        LOGGER.debug("KeycloakDefaultGroupsMapper.map called for claim: %s", claimName);
        LOGGER.debug("Input MapRepresentation: %s", mapRepresentation);

        Optional<List<String>> groupsValue = mapRepresentation.getStringList(GROUPS_CLAIM);
        if (groupsValue.isEmpty()) {
            LOGGER.debug("No groups claim found in token");
            return null;
        }

        List<String> groupsList = groupsValue.get();

        LOGGER.debug("Successfully mapped groups: %s", groupsList);
        return KeycloakMapperSupport.toListClaimValue(groupsList);
    }
}
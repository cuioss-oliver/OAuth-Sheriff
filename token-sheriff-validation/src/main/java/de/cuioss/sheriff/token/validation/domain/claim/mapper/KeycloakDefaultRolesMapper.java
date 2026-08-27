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
 * A fixed-source {@link ClaimMapper} that always reads from the {@code "realm_access.roles"}
 * path in the token payload, regardless of the {@code claimName} parameter passed to
 * {@link #map(MapRepresentation, String)}.
 * <p>
 * This is intentional: Keycloak always stores realm roles in the nested
 * {@code realm_access.roles} structure, so the source path is fixed by the identity
 * provider's convention. The {@code claimName} parameter identifies the <em>target</em>
 * claim in Token-Sheriff's model (e.g., {@code ROLES}), not the source claim in the token.
 * <p>
 * Keycloak by default stores realm roles in a nested structure:
 * <pre>
 * {
 *   "realm_access": {
 *     "roles": ["user", "admin"]
 *   }
 * }
 * </pre>
 * <p>
 * This mapper extracts the roles array and maps it to a standard {@code roles} claim,
 * making it compatible with Token-Sheriff library's authorization mechanisms.
 * <p>
 * The mapper handles:
 * <ul>
 *   <li>Missing {@code realm_access} object - returns {@code null} (claim treated as absent)</li>
 *   <li>Missing {@code roles} array within {@code realm_access} - returns {@code null} (claim treated as absent)</li>
 *   <li>Non-array {@code roles} value - returns {@code null} (claim treated as absent)</li>
 *   <li>Empty roles array - returns claim value with empty list</li>
 * </ul>
 *
 * @since 1.0
 * @see <a href="https://www.keycloak.org/docs/latest/server_admin/index.html#_protocol-mappers">Keycloak Protocol Mappers</a>
 */
public class KeycloakDefaultRolesMapper implements ClaimMapper {

    private static final CuiLogger LOGGER = new CuiLogger(KeycloakDefaultRolesMapper.class);
    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String ROLES_CLAIM = "roles";

    @Override
    public ClaimValue map(MapRepresentation mapRepresentation, String claimName) {
        LOGGER.debug("KeycloakDefaultRolesMapper.map called for claim: %s", claimName);
        LOGGER.debug("Input MapRepresentation: %s", mapRepresentation);

        Optional<MapRepresentation> realmAccessValue = mapRepresentation.getNestedMap(REALM_ACCESS_CLAIM);
        if (realmAccessValue.isEmpty()) {
            LOGGER.debug("No realm_access claim found in token");
            return null;
        }

        MapRepresentation realmAccessObject = realmAccessValue.get();
        LOGGER.debug("realm_access object: %s", realmAccessObject);

        Optional<List<String>> rolesValue = realmAccessObject.getStringList(ROLES_CLAIM);
        if (rolesValue.isEmpty()) {
            LOGGER.debug("No roles claim found in realm_access");
            return null;
        }

        List<String> rolesList = rolesValue.get();

        LOGGER.debug("Successfully mapped roles: %s", rolesList);
        return KeycloakMapperSupport.toListClaimValue(rolesList);
    }
}
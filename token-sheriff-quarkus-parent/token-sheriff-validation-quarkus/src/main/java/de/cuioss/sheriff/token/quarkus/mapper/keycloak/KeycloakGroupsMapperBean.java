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
package de.cuioss.sheriff.token.quarkus.mapper.keycloak;

import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.mapper.DiscoverableClaimMapper;
import de.cuioss.sheriff.token.validation.domain.claim.mapper.ClaimMapper;
import de.cuioss.sheriff.token.validation.domain.claim.mapper.KeycloakDefaultGroupsMapper;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.Config;

/**
 * CDI bean that provides the Keycloak default groups mapper as a discoverable claim mapper.
 * <p>
 * This bean delegates to {@link KeycloakDefaultGroupsMapper} for the actual mapping logic.
 * It is enabled or disabled via the configuration property
 * {@code sheriff.token.keycloak.default-groups-mapper.enabled} (default: {@code false}).
 * </p>
 * <p>
 * When enabled, this mapper processes Keycloak's standard {@code groups} claim and
 * ensures they are properly formatted for the Token-Sheriff library's authorization mechanisms.
 * The mapper is applied globally to all configured issuers.
 * </p>
 *
 * @since 1.0
 * @see KeycloakDefaultGroupsMapper
 * @see DiscoverableClaimMapper
 */
@ApplicationScoped
public class KeycloakGroupsMapperBean implements DiscoverableClaimMapper {

    private static final String CLAIM_NAME = "groups";

    private final boolean enabled;

    /**
     * Creates a new KeycloakGroupsMapperBean with the specified configuration.
     *
     * @param config the MicroProfile configuration instance
     */
    public KeycloakGroupsMapperBean(Config config) {
        this.enabled = config.getOptionalValue(
                JwtPropertyKeys.KEYCLOAK.DEFAULT_GROUPS_MAPPER_ENABLED, Boolean.class
        ).orElse(false);
    }

    @Override
    public String getClaimName() {
        return CLAIM_NAME;
    }

    @Override
    public ClaimMapper getMapper() {
        return new KeycloakDefaultGroupsMapper();
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}

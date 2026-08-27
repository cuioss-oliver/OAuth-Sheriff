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
package de.cuioss.sheriff.token.quarkus.mapper;

import de.cuioss.sheriff.token.validation.domain.claim.mapper.ClaimMapper;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;

import java.util.*;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;

/**
 * CDI registry for {@link DiscoverableClaimMapper} beans.
 * <p>
 * This registry collects all CDI-discovered {@link DiscoverableClaimMapper} beans,
 * validates that no duplicate claim names exist, and provides access to the registered
 * mappers. Mappers are applied globally to all configured issuers.
 * </p>
 * <p>
 * The registry performs the following during initialization:
 * <ul>
 *   <li>Iterates over all discovered {@link DiscoverableClaimMapper} beans</li>
 *   <li>Filters out disabled mappers (where {@link DiscoverableClaimMapper#isEnabled()} returns {@code false})</li>
 *   <li>Validates that no two enabled mappers share the same claim name (fail-fast)</li>
 *   <li>Logs the number of registered mappers</li>
 * </ul>
 *
 * @since 1.0
 * @see DiscoverableClaimMapper
 */
@ApplicationScoped
public class ClaimMapperRegistry {

    private static final CuiLogger LOGGER = new CuiLogger(ClaimMapperRegistry.class);

    private final Instance<DiscoverableClaimMapper> discoveredMappers;
    private final Map<String, ClaimMapper> registeredMappers = new LinkedHashMap<>();

    /**
     * Creates a new ClaimMapperRegistry with CDI-discovered mappers.
     *
     * @param discoveredMappers the CDI-managed instances of {@link DiscoverableClaimMapper}
     */
    public ClaimMapperRegistry(Instance<DiscoverableClaimMapper> discoveredMappers) {
        this.discoveredMappers = discoveredMappers;
    }

    /**
     * Initializes the registry by collecting all enabled mappers and validating uniqueness.
     *
     * @throws IllegalStateException if duplicate claim names are detected among enabled mappers
     */
    @PostConstruct
    void init() {
        for (DiscoverableClaimMapper mapper : discoveredMappers) {
            if (!mapper.isEnabled()) {
                LOGGER.debug("Skipping disabled claim mapper for claim: %s", mapper.getClaimName());
                continue;
            }

            String claimName = mapper.getClaimName();
            if (registeredMappers.containsKey(claimName)) {
                throw new IllegalStateException(
                        "Duplicate claim mapper registration for claim name '%s'. "
                                .formatted(claimName)
                                + "Each claim name must have at most one enabled DiscoverableClaimMapper.");
            }

            registeredMappers.put(claimName, mapper.getMapper());
            LOGGER.debug("Registered claim mapper for claim: %s", claimName);
        }

        if (registeredMappers.isEmpty()) {
            LOGGER.info(INFO.NO_CUSTOM_CLAIM_MAPPERS_DISCOVERED);
        } else {
            LOGGER.info(INFO.CLAIM_MAPPER_REGISTRY_INITIALIZED,
                    registeredMappers.size(),
                    String.join(", ", registeredMappers.keySet()));
        }
    }

    /**
     * Returns the mapper for the specified claim name.
     *
     * @param claimName the claim name to look up
     * @return an {@link Optional} containing the mapper if registered, or empty if not
     */
    public Optional<ClaimMapper> getMapper(String claimName) {
        return Optional.ofNullable(registeredMappers.get(claimName));
    }

    /**
     * Returns the set of all registered claim names.
     *
     * @return an unmodifiable set of registered claim names
     */
    public Set<String> getRegisteredClaimNames() {
        return Collections.unmodifiableSet(registeredMappers.keySet());
    }
}

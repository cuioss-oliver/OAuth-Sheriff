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

/**
 * CDI-discoverable interface for custom claim mappers.
 * <p>
 * Implementations of this interface are automatically discovered by the CDI container
 * and registered in the {@link ClaimMapperRegistry}. Discovered mappers are applied
 * globally to all configured issuers, replacing the previous per-issuer mapper configuration.
 * </p>
 * <p>
 * To create a custom claim mapper, implement this interface as an {@code @ApplicationScoped}
 * CDI bean:
 * </p>
 * <pre>
 * &#64;ApplicationScoped
 * public class MyCustomMapper implements DiscoverableClaimMapper {
 *
 *     &#64;Override
 *     public String getClaimName() {
 *         return "my-claim";
 *     }
 *
 *     &#64;Override
 *     public ClaimMapper getMapper() {
 *         return new MyClaimMapperImpl();
 *     }
 * }
 * </pre>
 * <p>
 * Each claim name must have at most one mapper. If multiple mappers are registered
 * for the same claim name, the {@link ClaimMapperRegistry} will fail fast with an
 * {@link IllegalStateException}.
 * </p>
 *
 * @since 1.0
 * @see ClaimMapperRegistry
 * @see ClaimMapper
 */
public interface DiscoverableClaimMapper {

    /**
     * Returns the claim name that this mapper handles.
     * <p>
     * The claim name identifies which JWT claim this mapper processes.
     * Each claim name must be unique across all registered mappers.
     * </p>
     *
     * @return the claim name, never {@code null}
     */
    String getClaimName();

    /**
     * Returns the {@link ClaimMapper} implementation that handles the claim mapping.
     *
     * @return the claim mapper instance, never {@code null}
     */
    ClaimMapper getMapper();

    /**
     * Returns whether this mapper is enabled.
     * <p>
     * Disabled mappers are not registered in the {@link ClaimMapperRegistry}.
     * This allows mappers to be conditionally activated via configuration properties.
     * </p>
     *
     * @return {@code true} if this mapper is enabled, {@code false} otherwise
     */
    default boolean isEnabled() {
        return true;
    }
}

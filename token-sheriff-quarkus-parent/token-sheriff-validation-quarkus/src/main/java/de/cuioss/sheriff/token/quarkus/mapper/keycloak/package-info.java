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
/**
 * <h2>Keycloak Claim Mapper CDI Beans</h2>
 * <p>
 * This package provides CDI bean implementations of
 * {@link de.cuioss.sheriff.token.quarkus.mapper.DiscoverableClaimMapper} for
 * Keycloak's default claim structures.
 * </p>
 * <p>
 * Available mappers:
 * <ul>
 *   <li>{@link de.cuioss.sheriff.token.quarkus.mapper.keycloak.KeycloakRolesMapperBean} -
 *       Maps Keycloak's {@code realm_access.roles} to {@code roles}</li>
 *   <li>{@link de.cuioss.sheriff.token.quarkus.mapper.keycloak.KeycloakGroupsMapperBean} -
 *       Maps Keycloak's {@code groups} claim</li>
 * </ul>
 *
 */
package de.cuioss.sheriff.token.quarkus.mapper.keycloak;

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
 * <h2>CDI-based Claim Mapper Discovery</h2>
 * <p>
 * This package provides the CDI-based claim mapper registration mechanism for the
 * Token-Sheriff Quarkus extension. Custom claim mappers are discovered automatically
 * as CDI beans and applied globally to all configured issuers.
 * </p>
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.sheriff.token.quarkus.mapper.DiscoverableClaimMapper} -
 *       Interface for CDI-discoverable claim mappers</li>
 *   <li>{@link de.cuioss.sheriff.token.quarkus.mapper.ClaimMapperRegistry} -
 *       Registry that collects and manages discovered mappers</li>
 * </ul>
 *
 */
package de.cuioss.sheriff.token.quarkus.mapper;

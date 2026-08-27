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
 * Provides context objects for JWT validation operations.
 * <p>
 * This package contains domain objects that carry state and context
 * throughout the JWT validation pipeline, enabling efficient caching
 * and optimization of validation operations.
 * <p>
 * Key classes:
 * <ul>
 *   <li>{@link de.cuioss.sheriff.token.validation.domain.context.ValidationContext} -
 *       Carries cached current time and configuration through the validation pipeline</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.domain.context.TokenValidationRequest} -
 *       Sealed interface for token validation requests carrying token string and HTTP headers</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest} -
 *       Request object for access token validation</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.domain.context.IdTokenRequest} -
 *       Request object for ID token validation</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.domain.context.RefreshTokenRequest} -
 *       Request object for refresh token validation</li>
 * </ul>
 *
 */
package de.cuioss.sheriff.token.validation.domain.context;
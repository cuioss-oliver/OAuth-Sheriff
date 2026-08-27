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
 * <h2>Token-Sheriff Quarkus Extension</h2>
 * <p>
 * This package provides Quarkus integration for the Token-Sheriff validation library.
 * It enables Quarkus applications to easily configure and use JWT validation
 * with proper CDI integration, metrics, and health checks.
 * </p>
 * <p>
 * The extension provides:
 * </p>
 * <ul>
 * <li>Configuration properties for JWT validation</li>
 * <li>CDI producers for token validators</li>
 * <li>Integration with Quarkus security</li>
 * <li>Metrics for token validation events</li>
 * <li>Health checks for JWT validation</li>
 * </ul>
 * <p>
 * This extension follows the Quarkus extension architecture with separate
 * runtime and deployment modules.
 * </p>
 * 
 */
@NullMarked
package de.cuioss.sheriff.token.quarkus;

import org.jspecify.annotations.NullMarked;
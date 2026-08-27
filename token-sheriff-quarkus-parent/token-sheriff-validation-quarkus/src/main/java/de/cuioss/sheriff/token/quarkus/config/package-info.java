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
 * <h2>Configuration for Token-Sheriff Quarkus Extension</h2>
 * <p>
 * This package contains the configuration classes for the Token-Sheriff Quarkus extension.
 * Configuration is accessed directly through MicroProfile Config to ensure compatibility
 * with native images and avoid ConfigMapping fragility issues.
 * </p>
 * <p>
 * The configuration supports the multi-issuer approach of the library,
 * allowing different validation settings for different token issuers.
 * </p>
 * <p>
 * All properties are prefixed with "sheriff.token".
 * </p>
 * 
 */
package de.cuioss.sheriff.token.quarkus.config;
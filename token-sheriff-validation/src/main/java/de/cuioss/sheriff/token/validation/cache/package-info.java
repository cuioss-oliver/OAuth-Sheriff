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
 * Token caching infrastructure for JWT validation performance optimization.
 * <p>
 * This package provides caching functionality to avoid redundant validation of
 * the same access tokens. The cache implementation is thread-safe, uses SHA-256
 * hashing for keys, and includes automatic expiration handling.
 * <p>
 * Key features:
 * <ul>
 *   <li>Thread-safe caching with configurable size limits</li>
 *   <li>Size-based eviction (arbitrary iteration order) for size management</li>
 *   <li>Automatic expiration checking and background cleanup</li>
 *   <li>Security event tracking for cache effectiveness monitoring</li>
 *   <li>No external dependencies (Quarkus compatible)</li>
 * </ul>
 *
 */
package de.cuioss.sheriff.token.validation.cache;
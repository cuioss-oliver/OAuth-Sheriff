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
 * <h2>HTTP-based JWKS Loading and Caching</h2>
 * 
 * <p>This package provides components for loading JSON Web Key Sets (JWKS) from HTTP endpoints
 * with advanced caching, reliability, and performance features.</p>
 * 
 * <h3>Key Components</h3>
 * <ul>
 *   <li>{@link de.cuioss.sheriff.token.validation.jwks.http.HttpJwksLoader} - Main component that implements
 *       {@link de.cuioss.sheriff.token.validation.jwks.JwksLoader} for HTTP-based JWKS sources</li>
 *   <li>{@link de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig} - Configuration parameters
 *       for the HTTP JWKS loader</li>
 *   <li>JwksHttpClient - Client for making HTTP requests
 *       to JWKS endpoints</li>
 *   <li>JwksCacheManager - Manages caching of JWKS keys</li>
 *   <li>BackgroundRefreshManager - Manages background
 *       refresh of JWKS content</li>
 * </ul>
 * 
 * <h3>Component Interactions</h3>
 * <p>The components in this package work together to provide a robust solution for loading and 
 * caching JWKS from HTTP endpoints:</p>
 * 
 * <ol>
 *   <li><strong>Configuration and Initialization:</strong> 
 *     <ul>
 *       <li>{@code HttpJwksLoaderConfig} is created with parameters like JWKS URI, refresh interval, 
 *           SSL context, etc.</li>
 *       <li>{@code HttpJwksLoader} is initialized with this configuration</li>
 *       <li>During initialization, {@code HttpJwksLoader} creates instances of {@code JwksHttpClient}, 
 *           {@code JwksCacheManager}, and {@code BackgroundRefreshManager}</li>
 *     </ul>
 *   </li>
 *   
 *   <li><strong>Key Retrieval Flow:</strong>
 *     <ul>
 *       <li>When a key is requested, {@code HttpJwksLoader} first tries to get it from the cache 
 *           via {@code JwksCacheManager}</li>
 *       <li>If the key is not in the cache or the cache is expired, {@code JwksCacheManager} calls 
 *           back to {@code HttpJwksLoader} to load fresh JWKS content</li>
 *       <li>{@code HttpJwksLoader} uses {@code JwksHttpClient} to fetch the content from the 
 *           JWKS endpoint</li>
 *       <li>{@code JwksHttpClient} includes the ETag in the request if available, enabling 
 *           HTTP 304 "Not Modified" handling</li>
 *       <li>The response is processed and either the existing keys are reused (for 304 responses) 
 *           or new keys are created from the fresh content</li>
 *     </ul>
 *   </li>
 *   
 *   <li><strong>Background Refresh:</strong>
 *     <ul>
 *       <li>{@code BackgroundRefreshManager} schedules periodic refresh tasks</li>
 *       <li>These tasks preemptively refresh the cache before keys expire</li>
 *       <li>The refresh percentage is configurable (e.g., refresh at 80% of the expiration time)</li>
 *     </ul>
 *   </li>
 *   
 *   <li><strong>Fallback Mechanisms:</strong>
 *     <ul>
 *       <li>If a refresh attempt fails, {@code JwksCacheManager} provides the last valid result</li>
 *       <li>This ensures that temporary network issues don't cause authentication failures</li>
 *     </ul>
 *   </li>
 * </ol>
 * 
 * <h3>Performance and Reliability Features</h3>
 * <ul>
 *   <li><strong>HTTP 304 "Not Modified" handling:</strong> Uses the ETag header to avoid unnecessary downloads</li>
 *   <li><strong>Content-based caching:</strong> Only creates new key loaders when content actually changes</li>
 *   <li><strong>Fallback mechanism:</strong> Uses the last valid result if a new request fails</li>
 *   <li><strong>Multi-issuer support:</strong> Efficiently caches keys for multiple issuers</li>
 *   <li><strong>Adaptive caching:</strong> Adjusts cache behavior based on usage patterns</li>
 *   <li><strong>Background refresh:</strong> Preemptively refreshes keys before they expire</li>
 *   <li><strong>Cache size limits:</strong> Prevents memory issues in multi-issuer environments</li>
 * </ul>
 * 
 * <h3>Usage Example</h3>
 * <pre>
 * // Create configuration
 * HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
 *     .jwksUrl("https://auth.example.com/.well-known/jwks.json")
 *     .refreshIntervalSeconds(60)
 *     .build();
 *     
 * // Create loader
 * JwksLoader loader = JwksLoaderFactory.createHttpLoader(config);
 * 
 * // Get key by ID
 * Optional&lt;KeyInfo&gt; keyInfo = loader.getKeyInfo("kid123");
 * </pre>
 * 
 * <p>Implements requirements:</p>
 * <ul>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4.1">VALIDATION-4.1: JWKS Endpoint Support</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.3">VALIDATION-8.3: Secure Communication</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.5">VALIDATION-8.5: Cryptographic Agility</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#_jwksloader">Technical Components Specification - JwksLoader</a>
 * 
 * @author Oliver Wolff
 */
package de.cuioss.sheriff.token.validation.jwks.http;
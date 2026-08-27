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
 * Provides classes for loading and managing JSON Web Key Sets (JWKS).
 * <p>
 * JWKS are used to validate JWT Token signatures by providing the public keys
 * needed for signature verification. This package supports loading JWKS from
 * HTTP endpoints and other sources, with automatic refresh capabilities.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.sheriff.token.validation.jwks.JwksLoader} - Interface for loading JSON Web Keys from a JWKS source</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.jwks.http.HttpJwksLoader} - Implementation that loads JWKS from an HTTP endpoint</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.jwks.JwksLoaderFactory} - Factory for creating JwksLoader instances</li>
 * </ul>
 * <p>
 * The {@link de.cuioss.sheriff.token.validation.jwks.key} subpackage contains classes for handling individual
 * keys within a JWKS.
 * <p>
 * This package implements security best practices for JWKS handling, including:
 * <ul>
 *   <li>Cryptographic agility - supporting multiple key types and algorithms</li>
 *   <li>Automatic key rotation - refreshing keys periodically</li>
 *   <li>Fallback mechanisms - using cached keys when refresh fails</li>
 *   <li>Secure HTTP connections - using TLS for JWKS endpoints</li>
 * </ul>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4">VALIDATION-4: Key Management</a></li>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.5">VALIDATION-8.5: Cryptographic Agility</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#jwks-integration">Technical Components Specification - JwksLoader</a>
 * 
 * @see de.cuioss.sheriff.token.validation.pipeline.validator.TokenSignatureValidator
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517 - JSON Web Key (JWK)</a>
 */
package de.cuioss.sheriff.token.validation.jwks;

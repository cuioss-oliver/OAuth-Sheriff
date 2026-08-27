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
 * Provides classes for handling individual keys within a JSON Web Key Set (JWKS).
 * <p>
 * This package contains classes for parsing, storing, and managing cryptographic keys
 * used for JWT Token signature verification.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.sheriff.token.validation.jwks.key.KeyInfo} - Holds information about a key, including the key itself and its algorithm</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.jwks.key.JwkKeyHandler} - Handles parsing and conversion of JWK keys</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.jwks.key.JWKSKeyLoader} - Loads and manages keys from a JWKS</li>
 * </ul>
 * <p>
 * This package supports cryptographic agility by handling different key types and algorithms,
 * which is essential for secure JWT Token validation. It provides the foundation for
 * signature verification in the token validation pipeline.
 * <p>
 * The classes in this package implement security best practices for key handling, including:
 * <ul>
 *   <li>Support for multiple key types (RSA, EC, etc.)</li>
 *   <li>Support for multiple algorithms (RS256, ES256, etc.)</li>
 *   <li>Proper key identification using key IDs</li>
 *   <li>Safe parsing of key material</li>
 * </ul>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4">VALIDATION-4: Key Management</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.5">VALIDATION-8.5: Cryptographic Agility</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#jwks-integration">Technical Components Specification - JwksLoader</a>
 * 
 * @see de.cuioss.sheriff.token.validation.jwks.JwksLoader
 * @see de.cuioss.sheriff.token.validation.pipeline.validator.TokenSignatureValidator
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517 - JSON Web Key (JWK)</a>
 */
package de.cuioss.sheriff.token.validation.jwks.key;
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
 * Provides classes for processing JWT tokens through a pipeline of operations.
 * <p>
 * <strong>This package is internal to Token-Sheriff and not part of the public API.</strong>
 * Use {@link de.cuioss.sheriff.token.validation.TokenValidator} as the public entry point.
 * <p>
 * This package implements the token processing pipeline, including parsing, validation, and building tokens.
 * The classes in this package work together to form a complete token processing pipeline.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.sheriff.token.validation.pipeline.NonValidatingJwtParser} - Parses JWT tokens without validating signatures</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.pipeline.DecodedJwt} - Represents a decoded JWT token with header, body, and signature</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.pipeline.TokenBuilder} - Creates typed token instances from decoded JWTs</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.pipeline.validator.TokenClaimValidator} - Validates token claims against issuer configuration</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.pipeline.validator.TokenHeaderValidator} - Validates token headers against issuer configuration</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.pipeline.validator.TokenSignatureValidator} - Validates token signatures using JWKS</li>
 *   <li>{@link de.cuioss.sheriff.token.validation.IssuerConfig} - Configuration for a token issuer</li>
 *   <li>{@link de.cuioss.sheriff.token.commons.transport.ParserConfig} - Configuration for token parsing</li>
 * </ul>
 * <p>
 * The typical token processing pipeline is:
 * <ol>
 *   <li>Parse the token using {@link de.cuioss.sheriff.token.validation.pipeline.NonValidatingJwtParser}</li>
 *   <li>Validate the token header using {@link de.cuioss.sheriff.token.validation.pipeline.validator.TokenHeaderValidator}</li>
 *   <li>Validate the token signature using {@link de.cuioss.sheriff.token.validation.pipeline.validator.TokenSignatureValidator}</li>
 *   <li>Build a typed token using {@link de.cuioss.sheriff.token.validation.pipeline.TokenBuilder}</li>
 *   <li>Validate the token claims using {@link de.cuioss.sheriff.token.validation.pipeline.validator.TokenClaimValidator}</li>
 * </ol>
 * <p>
 * This package implements security best practices for JWT token processing, including
 * token size validation, proper signature verification, and claim validation.
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1">VALIDATION-1: Token Parsing and Validation</a></li>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1.3">VALIDATION-1.3: Signature Validation</a></li>
 *   <li><a href="../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-8.4">VALIDATION-8.4: Claims Validation</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc">Technical Components Specification</a>
 * 
 * @author Oliver Wolff
 * @see de.cuioss.sheriff.token.validation.TokenValidator
 * @see de.cuioss.sheriff.token.validation.domain.token.TokenContent
 */
package de.cuioss.sheriff.token.validation.pipeline;

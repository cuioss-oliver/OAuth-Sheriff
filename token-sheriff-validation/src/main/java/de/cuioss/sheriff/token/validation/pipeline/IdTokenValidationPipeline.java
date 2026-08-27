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
package de.cuioss.sheriff.token.validation.pipeline;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.IssuerConfigCache;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.domain.context.IdTokenRequest;
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenClaimValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenHeaderValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenSignatureValidator;
import de.cuioss.tools.logging.CuiLogger;

import java.util.Map;

/**
 * Pipeline for validating ID tokens.
 * <p>
 * ID tokens require full validation but are typically validated only once during
 * login flows, so they are not cached. This pipeline performs complete cryptographic
 * validation and claims checking.
 * <p>
 * <strong>Validation Steps:</strong>
 * <ol>
 *   <li>Parse token into header and payload</li>
 *   <li>Extract and validate issuer claim</li>
 *   <li>Resolve issuer configuration</li>
 *   <li>Validate JWT header</li>
 *   <li>Validate JWT signature (cryptographic verification)</li>
 *   <li>Build typed IdTokenContent object</li>
 *   <li>Validate token claims (expiration, audience, etc.)</li>
 * </ol>
 * <p>
 * <strong>Note:</strong> TokenStringValidator has already validated that the token
 * is non-null, non-blank, and within size limits before this pipeline is called.
 * <p>
 * <strong>No Metrics Instrumentation:</strong> ID token validation uses
 * {@code NoOpMetricsTicker} and does not record performance metrics.
 * <p>
 * <strong>No Caching:</strong> ID tokens are not cached.
 * <p>
 * This class is thread-safe after construction. All validators are pre-created
 * and cached in immutable maps for optimal performance.
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
public class IdTokenValidationPipeline {

    private static final CuiLogger LOGGER = new CuiLogger(IdTokenValidationPipeline.class);

    private final NonValidatingJwtParser jwtParser;
    private final IssuerConfigCache issuerConfigCache;
    private final Map<String, TokenSignatureValidator> signatureValidators;
    private final Map<String, TokenBuilder> tokenBuilders;
    private final Map<String, TokenClaimValidator> claimValidators;
    private final Map<String, TokenHeaderValidator> headerValidators;
    private final SecurityEventCounter securityEventCounter;

    /**
     * Creates a new IdTokenValidationPipeline.
     *
     * @param jwtParser the JWT parser for decoding tokens
     * @param issuerConfigCache the resolver for issuer configurations
     * @param signatureValidators pre-created signature validators keyed by issuer
     * @param tokenBuilders pre-created token builders keyed by issuer
     * @param claimValidators pre-created claim validators keyed by issuer
     * @param headerValidators pre-created header validators keyed by issuer
     * @param securityEventCounter the security event counter for tracking operations
     */
    public IdTokenValidationPipeline(NonValidatingJwtParser jwtParser,
            IssuerConfigCache issuerConfigCache,
            Map<String, TokenSignatureValidator> signatureValidators,
            Map<String, TokenBuilder> tokenBuilders,
            Map<String, TokenClaimValidator> claimValidators,
            Map<String, TokenHeaderValidator> headerValidators,
            SecurityEventCounter securityEventCounter) {
        this.jwtParser = jwtParser;
        this.issuerConfigCache = issuerConfigCache;
        this.signatureValidators = signatureValidators;
        this.tokenBuilders = tokenBuilders;
        this.claimValidators = claimValidators;
        this.headerValidators = headerValidators;
        this.securityEventCounter = securityEventCounter;
    }

    /**
     * Validates and returns an ID token.
     * <p>
     * Performs complete validation including parsing, signature verification,
     * and claims validation. All validation steps must succeed for the token
     * to be considered valid.
     *
     * @param request the ID token validation request (token string guaranteed non-null, non-blank, within size limits)
     * @return the validated ID token content
     * @throws TokenValidationException if any validation step fails
     */
    public IdTokenContent validate(IdTokenRequest request) {
        LOGGER.debug("Validating ID token");
        String tokenString = request.tokenString();

        // TokenStringValidator has already checked: null, blank, size

        // 1. Parse token
        DecodedJwt decodedJwt = jwtParser.decode(tokenString);

        // 2. Extract issuer
        String issuerString = decodedJwt.getIssuer().orElseThrow(() -> {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, "iss");
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            return new TokenValidationException(
                    SecurityEventCounter.EventType.MISSING_CLAIM,
                    "Missing required issuer (iss) claim in token"
            );
        });

        // 3. Resolve issuer config
        IssuerConfig issuerConfig = issuerConfigCache.resolveConfig(issuerString);

        // 4. Validate header
        ValidatorLookup.getOrThrow(headerValidators, issuerConfig.getIssuerIdentifier(), "header validator")
                .validate(decodedJwt, request);

        // 5. Validate signature
        ValidatorLookup.getOrThrow(signatureValidators, issuerConfig.getIssuerIdentifier(), "signature validator")
                .validateSignature(decodedJwt);

        // 6. Build token
        TokenBuilder tokenBuilder = ValidatorLookup.getOrThrow(tokenBuilders, issuerConfig.getIssuerIdentifier(), "token builder");
        IdTokenContent token = tokenBuilder.createIdToken(decodedJwt)
                .orElseThrow(() -> {
                    LOGGER.debug("ID token building failed");
                    return new TokenValidationException(
                            SecurityEventCounter.EventType.MISSING_CLAIM,
                            "Failed to build ID token from decoded JWT"
                    );
                });

        // 7. Validate claims
        // Create ValidationContext with cached current time to eliminate synchronous OffsetDateTime.now() calls
        // Use per-issuer clock skew and max token age from IssuerConfig
        ValidationContext context = new ValidationContext(
                issuerConfig.getClockSkewSeconds(),
                issuerConfig.getMaxTokenAgeSeconds());
        IdTokenContent validatedToken = (IdTokenContent) ValidatorLookup.getOrThrow(claimValidators, issuerConfig.getIssuerIdentifier(), "claim validator")
                .validate(token, context);

        LOGGER.debug("Successfully validated ID token");

        return validatedToken;
    }
}

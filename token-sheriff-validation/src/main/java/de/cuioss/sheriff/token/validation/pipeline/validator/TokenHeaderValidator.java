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
package de.cuioss.sheriff.token.validation.pipeline.validator;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.domain.context.TokenValidationRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.tools.logging.CuiLogger;

/**
 * Validator for JWT Token headers.
 * <p>
 * This class validates the following header elements:
 * <ul>
 *   <li>Algorithm (alg) - against configured SignatureAlgorithmPreferences</li>
 *   <li>Issuer (iss) - against configured expected issuer</li>
 *   <li>Absence of embedded JWK - to prevent CVE-2018-0114 attacks</li>
 *   <li>Token type (typ) - optional per-issuer validation per RFC 9068</li>
 * </ul>
 * <p>
 * The validator logs appropriate warning messages for validation failures.
 * <p>
 * For more details on the validation process, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-validation-pipeline">Token Validation Pipeline</a>
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
public class TokenHeaderValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenHeaderValidator.class);

    private final IssuerConfig issuerConfig;
    /**
     * The counter for security events.
     */
   
    private final SecurityEventCounter securityEventCounter;

    /**
     * Constructs a TokenHeaderValidator with the specified IssuerConfig.
     *
     * @param issuerConfig         the issuer configuration
     * @param securityEventCounter the counter for security events
     */
    public TokenHeaderValidator(IssuerConfig issuerConfig, SecurityEventCounter securityEventCounter) {
        this.issuerConfig = issuerConfig;
        this.securityEventCounter = securityEventCounter;
    }


    /**
     * Validates a decoded JWT Token's header with access to the full validation request context.
     * <p>
     * This validator checks:
     * <ul>
     *   <li>Algorithm (alg) claim presence and support</li>
     *   <li>Key ID (kid) claim presence for signature validation</li>
     *   <li>Absence of embedded JWK to prevent CVE-2018-0114 attacks</li>
     * </ul>
     * <p>
     * The request parameter provides access to HTTP headers, enabling future features such as
     * RFC 9068 {@code typ} header validation and RFC 9449 DPoP support.
     * <p>
     * Note: Issuer validation is now performed at the TokenValidator level during
     * issuer configuration resolution, not here.
     * </p>
     *
     * @param decodedJwt the decoded JWT Token to validate
     * @param request the token validation request providing HTTP context
     * @throws TokenValidationException if the token header is invalid
     */
    public void validate(DecodedJwt decodedJwt, TokenValidationRequest request) {
        LOGGER.trace("Validating token header");

        validateAlgorithm(decodedJwt);
        validateKeyId(decodedJwt);
        // Issuer validation removed - now handled in TokenValidator.resolveIssuerConfig()
        validateNoEmbeddedJwk(decodedJwt);
        validateTokenType(decodedJwt);

        LOGGER.debug("Token header is valid");
    }

    /**
     * Validates that the token does not contain an embedded JWK in the header.
     * This is protection against the embedded JWK attack (CVE-2018-0114).
     *
     * @param decodedJwt the decoded JWT Token
     * @throws TokenValidationException if the token contains an embedded JWK
     */
    @SuppressWarnings("java:S3655") // owolff: False Positive: isPresent is checked before calling get()
    private void validateNoEmbeddedJwk(DecodedJwt decodedJwt) {
        JwtHeader header = decodedJwt.header();
        if (header.getJwk().isPresent()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.UNSUPPORTED_ALGORITHM, "Embedded JWK");
            securityEventCounter.increment(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM,
                    "Embedded JWK in token header is not allowed"
            );
        }
    }

    /**
     * Validates the validation's algorithm against the configured algorithm preferences.
     *
     * @param decodedJwt the decoded JWT Token
     * @throws TokenValidationException if the algorithm is invalid
     */
    private void validateAlgorithm(DecodedJwt decodedJwt) {
        var algorithm = decodedJwt.getAlg();

        if (algorithm.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, "alg");
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.MISSING_CLAIM,
                    "Missing required algorithm (alg) claim in token header"
            );
        }

        if (!issuerConfig.getAlgorithmPreferences().isSupported(algorithm.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.UNSUPPORTED_ALGORITHM, algorithm.get());
            securityEventCounter.increment(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM,
                    "Unsupported algorithm: %s".formatted(algorithm.get())
            );
        }

        LOGGER.debug("Algorithm is valid: %s", algorithm.get());
    }

    /**
     * Validates that the token contains a key ID (kid) claim in the header.
     * The kid is required for signature validation to identify the correct key.
     *
     * @param decodedJwt the decoded JWT Token
     * @throws TokenValidationException if the kid claim is missing
     */
    private void validateKeyId(DecodedJwt decodedJwt) {
        var kid = decodedJwt.getKid();
        if (kid.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, "kid");
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            JwtHeader header = decodedJwt.header();
            StringBuilder headerInfo = new StringBuilder("Available header claims:");
            boolean hasAny = false;

            if (header.getAlg().isPresent()) {
                headerInfo.append(" alg=").append(header.alg());
                hasAny = true;
            }

            var typOpt = header.getTyp();
            if (typOpt.isPresent()) {
                headerInfo.append(hasAny ? "," : "").append(" typ=").append(typOpt.orElse(""));
                hasAny = true;
            }

            if (!hasAny) {
                headerInfo.append(" none");
            }

            throw new TokenValidationException(
                    SecurityEventCounter.EventType.MISSING_CLAIM,
                    "Missing required key ID (kid) claim in token header. " + headerInfo
            );
        }
        LOGGER.debug("Key ID is valid: %s", kid.get());
    }

    /**
     * Validates the token's "typ" header against the expected token type configured in the issuer.
     * <p>
     * This validation is optional and only performed when {@code expectedTokenType} is configured
     * in the {@link IssuerConfig}. When not configured, this method is a no-op.
     * </p>
     * <p>
     * The comparison is case-insensitive per RFC convention.
     * </p>
     *
     * @param decodedJwt the decoded JWT Token
     * @throws TokenValidationException if the token type does not match the expected type
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9068">RFC 9068</a>
     */
    private void validateTokenType(DecodedJwt decodedJwt) {
        var expectedType = issuerConfig.getExpectedTokenType();
        if (expectedType == null || expectedType.isBlank()) {
            return; // No token type validation configured
        }

        var actualType = decodedJwt.header().getTyp();
        if (actualType.isEmpty() || !expectedType.equalsIgnoreCase(actualType.get())) {
            String actual = actualType.orElse("(missing)");
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_TYPE_MISMATCH, actual, expectedType);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_TYPE_MISMATCH);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.TOKEN_TYPE_MISMATCH,
                    "Token type '%s' does not match expected type '%s'".formatted(actual, expectedType)
            );
        }
        LOGGER.debug("Token type is valid: %s", actualType.get());
    }

}
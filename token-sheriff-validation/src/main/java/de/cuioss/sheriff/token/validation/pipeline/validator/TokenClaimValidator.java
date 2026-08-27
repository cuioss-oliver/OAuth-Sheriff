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
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.tools.collect.MoreCollections;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;

import java.util.Set;

/**
 * Validator for JWT claims as defined in RFC 7519.
 * <p>
 * This class validates the following mandatory claims:
 * <ul>
 *   <li>Subject (sub)</li>
 *   <li>Expiration Time (exp)</li>
 *   <li>Issued At (iat)</li>
 *   <li>Not Before (nbf) - if present</li>
 *   <li>Audience (aud) - if expected audience is provided</li>
 *   <li>Authorized Party (azp) - if expected client ID is provided</li>
 * </ul>
 * <p>
 * The validator logs appropriate warning messages for validation failures.
 * <p>
 * The azp claim validation is an important security measure to prevent client confusion attacks
 * where tokens issued for one client are used with a different client.
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc">Security Specification</a>
 * <p>
 * Note: Issuer (iss) validation is handled by {@link TokenHeaderValidator}.
 * <p>
 * This class uses composition to delegate specific validation responsibilities to specialized validators:
 * <ul>
 *   <li>{@link AudienceValidator} - for audience claim validation</li>
 *   <li>{@link ExpirationValidator} - for expiration and not-before validation</li>
 *   <li>{@link MandatoryClaimsValidator} - for mandatory claims validation</li>
 *   <li>{@link AuthorizedPartyValidator} - for authorized party validation</li>
 * </ul>
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
public class TokenClaimValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenClaimValidator.class);

    @Getter
    private final Set<String> expectedAudience;

    @Getter
    private final Set<String> expectedClientId;

    private final AudienceValidator audienceValidator;
    private final ExpirationValidator expirationValidator;
    private final MandatoryClaimsValidator mandatoryClaimsValidator;
    private final AuthorizedPartyValidator authorizedPartyValidator;

    /**
     * Constructs a TokenClaimValidator with the specified IssuerConfig.
     *
     * @param issuerConfig the issuer configuration containing expected audience and client ID
     * @param securityEventCounter the counter for security events
     */
    public TokenClaimValidator(IssuerConfig issuerConfig, SecurityEventCounter securityEventCounter) {
        this.expectedAudience = issuerConfig.getExpectedAudience();
        this.expectedClientId = issuerConfig.getExpectedClientId();

        this.audienceValidator = new AudienceValidator(expectedAudience, securityEventCounter,
                issuerConfig.isAccessTokenAudienceOptional(), issuerConfig.isAzpAudienceFallbackEnabled());
        this.expirationValidator = new ExpirationValidator(securityEventCounter);
        this.mandatoryClaimsValidator = new MandatoryClaimsValidator(issuerConfig, securityEventCounter);
        this.authorizedPartyValidator = new AuthorizedPartyValidator(expectedClientId, securityEventCounter,
                issuerConfig.isClientIdFallbackEnabled());

        if (MoreCollections.isEmpty(expectedAudience) && !issuerConfig.isAudienceValidationDisabled()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT, "expectedAudience");
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);
        }

        if (MoreCollections.isEmpty(expectedClientId)) {
            LOGGER.debug("No expectedClientId configured — azp claim validation disabled (optional per OIDC spec)");
        }

        if (issuerConfig.getExpectedTokenType() == null) {
            LOGGER.debug("No expectedTokenType configured — typ header validation disabled (optional, set expected-token-type for RFC 9068 IdPs)");
        }
    }


    /**
     * Validates a token against expected values for issuer, audience, and client ID using the provided validation context.
     * <p>
     * This method eliminates synchronous OffsetDateTime.now() calls by using the cached
     * current time from the ValidationContext, significantly improving performance under
     * concurrent load.
     *
     * @param token the token to validate
     * @param context the validation context containing cached current time
     * @return The validated token content
     * @throws TokenValidationException if validation fails
     */
    public TokenContent validate(TokenContent token, ValidationContext context) {
        LOGGER.trace("Validating token: %s", token);
        mandatoryClaimsValidator.validateMandatoryClaims(token);
        expirationValidator.validateMandatoryClaimsNonBlank(token);
        audienceValidator.validateAudience(token);
        authorizedPartyValidator.validateAuthorizedParty(token);
        expirationValidator.validateNotBefore(token, context);
        expirationValidator.validateNotExpired(token, context);
        expirationValidator.validateIssuedAtNotInFuture(token, context);
        expirationValidator.validateTokenAge(token, context);
        LOGGER.debug("Token is valid");
        return token;
    }

}

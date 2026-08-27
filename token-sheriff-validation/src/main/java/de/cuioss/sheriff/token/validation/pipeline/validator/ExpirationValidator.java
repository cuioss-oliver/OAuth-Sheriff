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
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.tools.logging.CuiLogger;
import lombok.RequiredArgsConstructor;

import java.time.OffsetDateTime;

/**
 * Validator for JWT expiration and time-based claims.
 * <p>
 * This class validates:
 * <ul>
 *   <li>Expiration time (exp) - tokens must not be expired</li>
 *   <li>Not before time (nbf) - tokens must not be used before their valid time</li>
 *   <li>Issued at time (iat) - must not be unreasonably in the future</li>
 *   <li>Non-blank mandatory claims (sub, iss) - a present claim must not be an empty string</li>
 * </ul>
 * <p>
 * The validator applies the per-issuer configurable clock skew tolerance (provided via the
 * {@link de.cuioss.sheriff.token.validation.domain.context.ValidationContext}) to the
 * expiration and not-before validation, accounting for time differences between token
 * issuer and validator.
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
public class ExpirationValidator {

    private static final CuiLogger LOGGER = new CuiLogger(ExpirationValidator.class);


    private final SecurityEventCounter securityEventCounter;

    /**
     * Validates that the token is not expired using the provided validation context.
     * <p>
     * This method eliminates synchronous OffsetDateTime.now() calls by using the cached
     * current time from the ValidationContext, significantly improving performance under
     * concurrent load.
     *
     * @param token the token to validate
     * @param context the validation context containing cached current time
     * @throws TokenValidationException if the token is expired
     */
    public void validateNotExpired(TokenContent token, ValidationContext context) {
        LOGGER.debug("validate expiration. Can be done directly, because %s", token);
        if (token.isExpired(context)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_EXPIRED);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_EXPIRED);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.TOKEN_EXPIRED,
                    "Token is expired. Current time: " + context.getCurrentTime() + " (with " + context.getClockSkewSeconds() + "s clock skew tolerance)"
            );
        }
        LOGGER.debug("Token is not expired");
    }

    /**
     * Validates the "not before time" claim using the provided validation context.
     * <p>
     * This method eliminates synchronous OffsetDateTime.now() calls by using the cached
     * current time from the ValidationContext, significantly improving performance under
     * concurrent load.
     * <p>
     * The "nbf" (not before) claim identifies the time before which the JWT must not be accepted for processing.
     * This claim is optional, so if it's not present, the validation passes.
     * <p>
     * If the claim is present, this method checks if the token's not-before time is more than the configured
     * clock skew seconds in the future. This window allows for clock skew between the token issuer and the token validator.
     * If the not-before time is more than the clock skew in the future, the token is considered invalid.
     * If the not-before time is in the past or within the clock skew tolerance, the token is considered valid.
     *
     * @param token the JWT claims
     * @param context the validation context containing cached current time
     * @throws TokenValidationException if the "not before" time is invalid
     */
    public void validateNotBefore(TokenContent token, ValidationContext context) {
        var notBefore = token.getNotBeforeDateTime();
        if (notBefore.isEmpty()) {
            LOGGER.debug("Not before claim is optional, so if it's not present, validation passes");
            return;
        }

        if (context.isNotBeforeInvalid(notBefore.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_NBF_FUTURE, context.getClockSkewSeconds());
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_NBF_FUTURE);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.TOKEN_NBF_FUTURE,
                    "Token not valid yet: not before time is more than " + context.getClockSkewSeconds() + " seconds in the future. Not before time: " + notBefore.get() + ", Current time: " + context.getCurrentTime() + " (with " + context.getClockSkewSeconds() + "s clock skew tolerance)"
            );
        }
        LOGGER.debug("Not before claim is present, and not more than " + context.getClockSkewSeconds() + " seconds in the future");
    }

    /**
     * Validates that the token is not too old based on its issued-at time.
     * <p>
     * This implements the MP-JWT 2.1 {@code mp.jwt.verify.token.age} concept.
     * A token is rejected when {@code now - iat > maxTokenAgeSeconds + clockSkewSeconds}.
     * <p>
     * This validation is only performed when {@link de.cuioss.sheriff.token.validation.domain.context.ValidationContext#isTokenAgeValidationEnabled()}
     * returns true.
     *
     * @param token the token to validate
     * @param context the validation context containing max token age configuration
     * @throws TokenValidationException if the token is too old
     */
    public void validateTokenAge(TokenContent token, ValidationContext context) {
        if (!context.isTokenAgeValidationEnabled()) {
            return;
        }

        var issuedAt = token.getIssuedAtDateTime();
        if (context.isTokenTooOld(issuedAt)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_AGE_EXCEEDED);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_AGE_EXCEEDED);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.TOKEN_AGE_EXCEEDED,
                    "Token is too old. Issued at: %s, Max age: %ds (with %ds clock skew tolerance)".formatted(
                            issuedAt, context.getMaxTokenAgeSeconds(), context.getClockSkewSeconds())
            );
        }
        LOGGER.debug("Token age is within acceptable range");
    }

    /**
     * Validates that the token's issued-at (iat) claim is not unreasonably in the future.
     * <p>
     * A token whose {@code iat} is more than the configured clock-skew tolerance in the future
     * indicates a misconfigured issuer or a forged token and is rejected. When the {@code iat}
     * claim is absent, this validation passes (mandatory-claim presence is enforced elsewhere).
     * <p>
     * The failure is reported under {@link SecurityEventCounter.EventType#TOKEN_NBF_FUTURE}, the
     * time-claim-in-the-future event category shared with the not-before check.
     *
     * @param token the token to validate
     * @param context the validation context containing cached current time and clock-skew tolerance
     * @throws TokenValidationException if the issued-at time is unreasonably in the future
     */
    public void validateIssuedAtNotInFuture(TokenContent token, ValidationContext context) {
        var issuedAtClaim = token.getClaimOption(ClaimName.ISSUED_AT);
        if (issuedAtClaim.isEmpty()) {
            LOGGER.debug("Issued-at claim not present, skipping future-iat guard");
            return;
        }

        OffsetDateTime issuedAt = issuedAtClaim.get().getDateTime();
        if (context.isNotBeforeInvalid(issuedAt)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_NBF_FUTURE, context.getClockSkewSeconds());
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_NBF_FUTURE);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.TOKEN_NBF_FUTURE,
                    "Token issued-at (iat) is more than " + context.getClockSkewSeconds()
                            + " seconds in the future. Issued at: " + issuedAt + ", Current time: "
                            + context.getCurrentTime() + " (with " + context.getClockSkewSeconds() + "s clock skew tolerance)"
            );
        }
        LOGGER.debug("Token issued-at is not unreasonably in the future");
    }

    /**
     * Validates that present mandatory string claims are non-blank.
     * <p>
     * The mandatory-claim presence check keys on claim presence only, so an empty-string {@code sub}
     * or {@code iss} counts as present and slips through. This guard rejects a present-but-blank
     * subject or issuer claim, closing that gap without forcing presence (optionality is enforced
     * by the mandatory-claim validator).
     *
     * @param token the token to validate
     * @throws TokenValidationException if a present {@code sub} or {@code iss} claim is blank
     */
    public void validateMandatoryClaimsNonBlank(TokenContent token) {
        rejectBlankClaim(token, ClaimName.SUBJECT);
        rejectBlankClaim(token, ClaimName.ISSUER);
    }

    @SuppressWarnings("java:S125") // false positive: explanatory prose comment, not commented-out code
    private void rejectBlankClaim(TokenContent token, ClaimName claimName) {
        var claim = token.getClaimOption(claimName);
        // A custom SPI ClaimMapper may construct a ClaimValue with a null originalString;
        // treat null the same as blank so it is rejected as MISSING_CLAIM rather than throwing an NPE.
        if (claim.isPresent() && isNullOrBlank(claim.get().getOriginalString())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, claimName.getName());
            securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.MISSING_CLAIM,
                    "Mandatory claim '" + claimName.getName() + "' is present but blank (empty string). "
                            + "A blank mandatory claim is treated as missing."
            );
        }
    }

    private static boolean isNullOrBlank(String value) {
        return value == null || value.isBlank();
    }
}
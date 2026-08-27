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
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.tools.logging.CuiLogger;
import lombok.RequiredArgsConstructor;

import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Validator for mandatory JWT claims based on token type.
 * <p>
 * This class validates that all mandatory claims for a specific token type are present and properly set.
 * The mandatory claims are defined by the {@link de.cuioss.sheriff.token.validation.TokenType} and vary between
 * access tokens, ID tokens, and refresh tokens.
 * <p>
 * The validator checks both claim presence and claim value validity. For certain claims like "sub" (subject),
 * the validation can be configured per-issuer to accommodate identity providers that don't include the
 * subject claim in access tokens by default.
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
public class MandatoryClaimsValidator {

    private static final CuiLogger LOGGER = new CuiLogger(MandatoryClaimsValidator.class);


    private final IssuerConfig issuerConfig;


    private final SecurityEventCounter securityEventCounter;

    /**
     * Validates whether all mandatory claims for the current token type are present and set.
     *
     * @param tokenContent the token content to validate
     * @throws TokenValidationException if any mandatory claims are missing
     */
    public void validateMandatoryClaims(TokenContent tokenContent) {
        var mandatoryNames = tokenContent.getTokenType().getMandatoryClaims().stream()
                .map(ClaimName::getName)
                .collect(Collectors.toSet());

        LOGGER.debug("%s, verifying mandatory claims: %s", tokenContent.getTokenType(), mandatoryNames);

        SortedSet<String> missingClaims = collectMissingClaims(tokenContent, mandatoryNames);

        if (missingClaims.isEmpty()) {
            LOGGER.debug("All mandatory claims are present and set as expected");
            return;
        }

        handleMissingClaims(tokenContent, missingClaims);
    }

    private SortedSet<String> collectMissingClaims(TokenContent tokenContent, Set<String> mandatoryNames) {
        SortedSet<String> missingClaims = new TreeSet<>();

        for (var claimName : mandatoryNames) {
            // Check if this claim should be skipped based on issuer configuration
            if (shouldSkipClaimValidation(claimName)) {
                LOGGER.debug("Skipping validation for claim '%s' due to issuer configuration (claimSubOptional=true)", claimName);
                continue;
            }

            if (isClaimMissing(tokenContent, claimName)) {
                missingClaims.add(claimName);
            }
        }

        return missingClaims;
    }

    /**
     * Determines if validation for a specific claim should be skipped based on issuer configuration.
     * <p>
     * Currently supports making the "sub" (subject) claim optional when claimSubOptional is enabled.
     * This provides a workaround for identity providers that don't include the subject claim in
     * access tokens by default.
     * </p>
     *
     * @param claimName the name of the claim to check
     * @return {@code true} if validation should be skipped, {@code false} otherwise
     */
    private boolean shouldSkipClaimValidation(String claimName) {
        // Design Decision: sub-only skip is intentional, tied to IssuerConfig.claimSubOptional
        // (see H-4). A generic Set<ClaimName> optionalClaims would be premature until additional
        // IdP-specific claim exemptions are needed.
        return ClaimName.SUBJECT.getName().equals(claimName) && issuerConfig.isClaimSubOptional();
    }

    private boolean isClaimMissing(TokenContent tokenContent, String claimName) {
        return !tokenContent.getClaims().containsKey(claimName);
    }

    private void handleMissingClaims(TokenContent tokenContent, SortedSet<String> missingClaims) {
        LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, missingClaims);
        securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);

        String errorMessage = buildErrorMessage(tokenContent, missingClaims);

        throw new TokenValidationException(
                SecurityEventCounter.EventType.MISSING_CLAIM,
                errorMessage
        );
    }

    private String buildErrorMessage(TokenContent tokenContent, SortedSet<String> missingClaims) {
        StringBuilder errorMessage = new StringBuilder("Missing mandatory claims: ").append(missingClaims);

        String claimSpecs = buildClaimSpecifications(missingClaims);
        if (!claimSpecs.isEmpty()) {
            errorMessage.append("\n\nClaim specifications:").append(claimSpecs);
        }

        errorMessage.append("\n\nAvailable claims: ").append(tokenContent.getClaims().keySet())
                .append(". Please ensure the token includes all required claims.");

        return errorMessage.toString();
    }

    private String buildClaimSpecifications(SortedSet<String> missingClaims) {
        StringBuilder claimSpecs = new StringBuilder();

        for (String missingClaim : missingClaims) {
            var claimNameEnum = ClaimName.fromString(missingClaim);
            claimNameEnum.ifPresent(claimName ->
                    claimSpecs.append("\n- ").append(missingClaim).append(": ").append(claimName.getSpec())
            );
        }

        return claimSpecs.toString();
    }
}
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
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.tools.logging.CuiLogger;
import lombok.RequiredArgsConstructor;

import java.util.Set;

/**
 * Validator for JWT authorized party (azp) claims.
 * <p>
 * This class validates the authorized party claim which is used to prevent client confusion attacks
 * where tokens issued for one client are used with a different client.
 * <p>
 * The azp claim identifies the client that the token was issued for and must match
 * one of the expected client IDs if client ID validation is configured.
 * <p>
 * RFC 9068 permits falling back to the {@code client_id} claim when {@code azp} is absent. This
 * substitution can be disabled per-issuer via {@code IssuerConfig#clientIdFallbackEnabled(false)}; when
 * disabled, a token that omits {@code azp} is never accepted on the strength of a matching {@code client_id}.
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
class AuthorizedPartyValidator {

    private static final CuiLogger LOGGER = new CuiLogger(AuthorizedPartyValidator.class);


    private final Set<String> expectedClientId;


    private final SecurityEventCounter securityEventCounter;

    /**
     * Whether the RFC 9068 {@code client_id}→{@code azp} fallback is enabled. When {@code false}, a token
     * that omits {@code azp} is never accepted on the strength of a matching {@code client_id} claim.
     */
    private final boolean clientIdFallbackEnabled;

    /**
     * Validates the authorized party claim.
     * <p>
     * The "azp" (authorized party) claim identifies the client that the token was issued for.
     * This claim is used to prevent client confusion attacks where tokens issued for one client
     * are used with a different client.
     * <p>
     * If the expected client ID is provided, this method checks if the token's azp claim
     * matches the expected client ID.
     * <p>
     * If the azp claim is missing but expected client ID is provided, the validation fails.
     *
     * @param token the JWT claims
     * @throws TokenValidationException if the authorized party is invalid
     */
    public void validateAuthorizedParty(TokenContent token) {
        if (expectedClientId.isEmpty()) {
            LOGGER.debug("No expectedClientId configured to check against");
            return;
        }

        var azpObj = token.getClaimOption(ClaimName.AUTHORIZED_PARTY);
        if (azpObj.isPresent()) {
            String azp = azpObj.get().getOriginalString();
            if (expectedClientId.contains(azp)) {
                LOGGER.debug("Successfully validated authorized party via azp: %s", azp);
                return;
            }
            LOGGER.warn(JWTValidationLogMessages.WARN.AZP_MISMATCH, azp, expectedClientId);
            securityEventCounter.increment(SecurityEventCounter.EventType.AZP_MISMATCH);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.AZP_MISMATCH,
                    "Authorized party mismatch: token azp '%s' does not match any expected client ID %s".formatted(azp, expectedClientId)
            );
        }

        // RFC 9068 fallback: check client_id claim when azp is absent (unless the fallback is disabled)
        if (clientIdFallbackEnabled) {
            var clientIdObj = token.getClaimOption(ClaimName.CLIENT_ID);
            if (clientIdObj.isPresent()) {
                String clientId = clientIdObj.get().getOriginalString();
                if (expectedClientId.contains(clientId)) {
                    LOGGER.warn(JWTValidationLogMessages.WARN.AZP_CLIENT_ID_FALLBACK, clientId);
                    return;
                }
                LOGGER.warn(JWTValidationLogMessages.WARN.AZP_MISMATCH, clientId, expectedClientId);
                securityEventCounter.increment(SecurityEventCounter.EventType.AZP_MISMATCH);
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.AZP_MISMATCH,
                        "Authorized party mismatch: token client_id '%s' does not match any expected client ID %s".formatted(clientId, expectedClientId)
                );
            }
        }

        LOGGER.warn(JWTValidationLogMessages.WARN.MISSING_CLAIM, ClaimName.AUTHORIZED_PARTY.getName());
        securityEventCounter.increment(SecurityEventCounter.EventType.MISSING_CLAIM);
        throw new TokenValidationException(
                SecurityEventCounter.EventType.MISSING_CLAIM,
                "Missing required authorized party claim (azp or client_id)"
        );
    }
}
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
package de.cuioss.sheriff.token.validation.cache;

import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.OffsetDateTime;

/**
 * Immutable wrapper for cached access tokens.
 * <p>
 * This class encapsulates a validated access token along with its raw string representation
 * and expiration time. The raw token is stored to verify cache hits against the original
 * token string, preventing false positives from hash collisions.
 * <p>
 * The expiration time is cached to enable efficient background eviction of expired tokens
 * without needing to parse the token content.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
@Builder
@Getter
public final class CachedToken {

    /**
     * The raw JWT token string as received from the client.
     * Used to verify cache hits by comparing against the queried token.
     */
   
    private final String rawToken;

    /**
     * The validated access token content.
     * This is the result of successful JWT validation and parsing.
     */
   
    private final AccessTokenContent content;

    /**
     * The expiration time of the token.
     * Used for efficient expiration checks and background eviction.
     */
   
    private final OffsetDateTime expirationTime;

    /**
     * Checks if this cached token has expired, accounting for clock skew tolerance.
     *
     * @param currentTime the current time to check against
     * @param clockSkewSeconds the clock skew tolerance in seconds (subtracted from current time)
     * @return true if the token has expired even with clock skew tolerance, false otherwise
     */
    public boolean isExpired(OffsetDateTime currentTime, int clockSkewSeconds) {
        return ValidationContext.isExpired(expirationTime, clockSkewSeconds, currentTime);
    }

    /**
     * Verifies that the provided token matches the cached raw token.
     * This prevents false cache hits from hash collisions.
     * 
     * @param tokenToVerify the token string to verify
     * @return true if the tokens match, false otherwise
     */
    public boolean verifyToken(String tokenToVerify) {
        return rawToken.equals(tokenToVerify);
    }
}
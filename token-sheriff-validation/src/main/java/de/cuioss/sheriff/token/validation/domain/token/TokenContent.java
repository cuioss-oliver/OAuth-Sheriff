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
package de.cuioss.sheriff.token.validation.domain.token;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.context.ValidationContext;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Base interface for JWT Token content.
 * <p>
 * This interface defines the common contract for all JWT token objects,
 * providing structured access to token claims and metadata. It extends
 * {@link MinimalTokenContent} for basic token information.
 * <p>
 * The interface provides:
 * <ul>
 *   <li>Typed accessors for mandatory claims (issuer, expiration, issued-at)</li>
 *   <li>Optional-returning accessors for optional claims (subject, not-before)</li>
 *   <li>Access to all claims in the token via {@link #getClaims()}</li>
 *   <li>Type-safe claim retrieval via {@link #getClaimOption(ClaimName)}</li>
 *   <li>Expiration checking</li>
 * </ul>
 * <p>
 * JWT tokens implementing this interface follow the standards defined in
 * <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519</a>.
 * <p>
 * For more details on token structure, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-structure">Token Structure</a>
 * specification.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public sealed interface TokenContent extends MinimalTokenContent permits BaseTokenContent {

    /**
     * Gets all claims in this token.
     *
     * @return a map of claim names to claim objects
     */
    Map<String, ClaimValue> getClaims();

    /**
     * Gets a specific claim by name.
     *
     * @param name the claim name
     * @return an Optional containing the claim if present, or empty otherwise
     */
    default Optional<ClaimValue> getClaimOption(ClaimName name) {
        return Optional.ofNullable(getClaims().get(name.getName()));
    }

    /**
     * Gets the issuer claim value.
     * <p>
     * Since 'iss' is a mandatory claim, this method will never return null.
     *
     * @return the issuer
     * @throws IllegalStateException if the issuer claim is not present (should never happen
     *                               for a properly constructed validation)
     */
    default String getIssuer() {
        return getClaimOption(ClaimName.ISSUER)
                .map(ClaimValue::getOriginalString)
                .orElseThrow(() -> new IllegalStateException("Issuer claim not present in token"));
    }

    /**
     * Gets the subject claim as an Optional.
     * <p>
     * The 'sub' (subject) claim is required by RFC 7519 specification, but this implementation
     * allows it to be optional when the issuer configuration has claimSubOptional
     * set to {@code true}. This provides compatibility with token issuers like Keycloak
     * that may not include the subject claim in certain token types (e.g., access tokens).
     *
     * @return an Optional containing the subject if present, or empty otherwise
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 - 4.1.2. "sub" (Subject) Claim</a>
     */
    default Optional<String> getSubject() {
        return getClaimOption(ClaimName.SUBJECT)
                .map(ClaimValue::getOriginalString);
    }

    /**
     * Gets the set of all claim names in this token.
     *
     * @return a set of claim name strings
     */
    default Set<String> getClaimNames() {
        return getClaims().keySet();
    }

    /**
     * Gets the expiration time as an OffsetDateTime.
     *
     * @return the expiration time
     * @throws IllegalStateException if the expiration claim is not present
     */
    default OffsetDateTime getExpirationDateTime() {
        return getClaimOption(ClaimName.EXPIRATION)
                .map(ClaimValue::getDateTime)
                .orElseThrow(() -> new IllegalStateException("ExpirationTime claim not present in token"));
    }

    /**
     * Gets the issued-at time as an OffsetDateTime.
     *
     * @return the issued-at time
     * @throws IllegalStateException if the issued-at claim is not present
     */
    default OffsetDateTime getIssuedAtDateTime() {
        return getClaimOption(ClaimName.ISSUED_AT)
                .map(ClaimValue::getDateTime)
                .orElseThrow(() -> new IllegalStateException("issued at time claim not present in token"));
    }

    /**
     * Gets the optional not-before claim value as an OffsetDateTime.
     *
     * @return an Optional containing the not-before time if present
     */
    default Optional<OffsetDateTime> getNotBeforeDateTime() {
        return getClaimOption(ClaimName.NOT_BEFORE)
                .map(ClaimValue::getDateTime);
    }

    /**
     * Checks if the token has expired using the provided validation context.
     * <p>
     * This method eliminates synchronous OffsetDateTime.now() calls by using the cached
     * current time from the ValidationContext, significantly improving performance under
     * concurrent load.
     *
     * @param context the validation context containing cached current time
     * @return true if the token has expired, false otherwise
     */
    default boolean isExpired(ValidationContext context) {
        return context.isExpired(getExpirationDateTime());
    }
}

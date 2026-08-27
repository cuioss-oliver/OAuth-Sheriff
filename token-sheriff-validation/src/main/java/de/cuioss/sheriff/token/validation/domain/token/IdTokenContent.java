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

import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.Serial;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Represents the content of an OpenID Connect ID Token.
 * <p>
 * This class provides access to ID Token specific claims and functionality, focusing on
 * user identity information as defined in the OpenID Connect Core specification.
 * <p>
 * ID Tokens typically contain:
 * <ul>
 *   <li>Standard JWT claims (iss, sub, exp, iat)</li>
 *   <li>Authentication information (auth_time, nonce, acr)</li>
 *   <li>User identity information (name, email, etc.)</li>
 *   <li>Audience (aud) and authorized party (azp) claims</li>
 * </ul>
 * <p>
 * The ID Token is used for authentication purposes and contains claims about the authentication
 * event and the authenticated user. It is not intended for authorization purposes - that's
 * what the access token is for.
 * <p>
 * This implementation follows the standards defined in:
 * <ul>
 *   <li><a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JWT</a></li>
 * </ul>
 * <p>
 * For more details on token structure and usage, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-types">Token Types</a>
 * specification.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public final class IdTokenContent extends BaseTokenContent {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new IdTokenContent with the given claims and raw token.
     *
     * @param claims   the token claims
     * @param rawToken the raw token string
     */
    public IdTokenContent(Map<String, ClaimValue> claims, String rawToken) {
        super(claims, rawToken, TokenType.ID_TOKEN);
    }

    /**
     * Gets the audience claim value.
     * <p>
     * 'aud' is mandatory for {@link TokenType#ID_TOKEN}.
     *
     * @return the audience as a set of strings
     * @throws IllegalStateException if the audience claim is not present
     */
    public Set<String> getAudience() {
        return getClaimOption(ClaimName.AUDIENCE)
                .map(ClaimValue::getAsList)
                .<Set<String>>map(list -> new LinkedHashSet<>(list))
                .orElseThrow(() -> new IllegalStateException("Audience claim not present in token"));
    }

    /**
     * Gets the display name from the OIDC "name" claim.
     * <p>
     * Note: This is the OIDC "name" claim (full display name), not a principal name.
     * Use {@link #getDisplayName()} for clarity.
     *
     * @return an Optional containing the display name if present, or empty otherwise
     */
    public Optional<String> getDisplayName() {
        return getClaimOption(ClaimName.NAME)
                .map(ClaimValue::getOriginalString);
    }

    /**
     * Gets the email from the token claims.
     *
     * @return an Optional containing the email if present, or empty otherwise
     */
    public Optional<String> getEmail() {
        return getClaimOption(ClaimName.EMAIL)
                .map(ClaimValue::getOriginalString);
    }

}

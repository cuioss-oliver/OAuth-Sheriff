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
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.util.Map;

/**
 * Base implementation of {@link TokenContent}.
 * <p>
 * This abstract class provides common functionality for token content implementations,
 * including storage of claims, the raw token string, and token type. It serves as
 * the foundation for specific token type implementations like:
 * <ul>
 *   <li>{@link AccessTokenContent} - For OAuth2/OIDC access tokens</li>
 *   <li>{@link IdTokenContent} - For OIDC ID tokens</li>
 *   <li>{@link UnvalidatedRefreshToken} - For OAuth2 refresh tokens</li>
 * </ul>
 * <p>
 * The class is immutable and thread-safe: the claims map is defensively copied into an
 * unmodifiable map in the constructor, so callers can neither mutate the stored claims
 * through the constructor argument nor through {@link #getClaims()}. Equality and string
 * representation are implemented via Lombok's {@code @EqualsAndHashCode} and {@code @ToString}.
 * <p>
 * For more details on token structure, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-structure">Token Structure</a>
 * specification.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public abstract sealed class BaseTokenContent implements TokenContent
        permits AccessTokenContent, IdTokenContent {

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    private final Map<String, ClaimValue> claims;

    @Getter
    @ToString.Exclude
    private final String rawToken;

    @Getter
    private final TokenType tokenType;

    /**
     * Constructor for BaseTokenContent.
     * <p>
     * The given claims map is defensively copied into an unmodifiable map, guaranteeing
     * immutability even when the token content is shared across threads (e.g. via the
     * access token cache). The map must not contain {@code null} keys or values.
     *
     * @param claims    the token claims
     * @param rawToken  the raw token string
     * @param tokenType the token type
     */
    protected BaseTokenContent(Map<String, ClaimValue> claims, String rawToken,
            TokenType tokenType) {
        this.claims = Map.copyOf(claims);
        this.rawToken = rawToken;
        this.tokenType = tokenType;
    }
}

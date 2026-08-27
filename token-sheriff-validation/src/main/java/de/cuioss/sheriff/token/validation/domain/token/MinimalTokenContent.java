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

import java.io.Serializable;

/**
 * Minimal interface for token content that applies to all token types.
 * <p>
 * Unlike {@link TokenContent}, this interface does not provide access to JWT-specific
 * content like claims. It contains only the most fundamental token properties:
 * <ul>
 *   <li>The raw token string</li>
 *   <li>The token type (access token, ID token, refresh token)</li>
 * </ul>
 * <p>
 * This interface is particularly important for {@link TokenType#REFRESH_TOKEN}
 * which may not be a standard JWT token with claims but might use a different
 * format or structure based on the authorization server implementation.
 * <p>
 * All token content classes in the library implement this interface, providing
 * a common base for token handling regardless of the specific token format.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public sealed interface MinimalTokenContent extends Serializable
        permits TokenContent, UnvalidatedRefreshToken {

    /**
     * Gets the raw token string.
     *
     * @return the raw JWT token string
     */
    String getRawToken();

    /**
     * Gets the token type.
     *
     * @return the token type (ACCESS_TOKEN, ID_TOKEN, or REFRESH_TOKEN)
     */
    TokenType getTokenType();
}

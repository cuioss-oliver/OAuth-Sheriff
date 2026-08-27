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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;

import java.util.Objects;

/**
 * Bridges retrieved tokens into the {@code token-sheriff-validation} pipeline ({@code CLIENT-15}).
 * <p>
 * Every access token the client retrieves from a token endpoint is validated through the same
 * multi-issuer validation pipeline that guards inbound tokens — signature, {@code iss}, {@code aud},
 * {@code exp} / {@code iat}, and issuer-specific claim rules. The client never trusts a retrieved
 * token on the strength of a successful HTTP exchange alone.
 * <p>
 * Validation failures propagate as the pipeline's
 * {@code de.cuioss.sheriff.token.validation.exception.TokenValidationException}; a caller therefore
 * never receives an unvalidated {@link AccessTokenContent}.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class TokenValidationBridge {

    private final TokenValidator tokenValidator;

    /**
     * @param tokenValidator the configured multi-issuer validator; must not be {@code null}
     */
    public TokenValidationBridge(TokenValidator tokenValidator) {
        this.tokenValidator = Objects.requireNonNull(tokenValidator, "tokenValidator must not be null");
    }

    /**
     * Validates a retrieved access token through the validation pipeline.
     *
     * @param accessToken the raw access token string; must not be {@code null}
     * @return the validated access token content
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if the token
     *         fails validation
     */
    public AccessTokenContent validateAccessToken(String accessToken) {
        Objects.requireNonNull(accessToken, "accessToken must not be null");
        return tokenValidator.createAccessToken(AccessTokenRequest.of(accessToken));
    }
}

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
package de.cuioss.sheriff.token.validation.test.generator;

import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import lombok.Builder;
import lombok.Value;

/**
 * Parameter object for controlling which claims should be included or excluded
 * when generating token content.
 * Used by {@link TestTokenHolder} to create
 * both valid and invalid tokens for testing purposes.
 */
@Value
@Builder
public class ClaimControlParameter {

    /**
     * Enum defining the size of the token.
     */
    public enum TokenSize {
        /**
         * Default size, approximately 1KB or less.
         */
        SMALL,

        /**
         * Medium size, approximately 5KB.
         */
        MEDIUM,

        /**
         * Large size, approximately 10KB or more.
         */
        LARGE
    }

    /**
     * Enum defining the complexity of the token claims.
     */
    public enum TokenComplexity {
        /**
         * Basic set of claims.
         */
        SIMPLE,

        /**
         * Additional nested claims or more numerous claims.
         */
        COMPLEX
    }

    @Builder.Default
    boolean missingIssuer = false;

    @Builder.Default
    boolean missingSubject = false;

    @Builder.Default
    boolean missingExpiration = false;

    @Builder.Default
    boolean expiredToken = false;

    @Builder.Default
    boolean missingIssuedAt = false;

    @Builder.Default
    boolean missingTokenType = false;

    @Builder.Default
    boolean missingScope = false;

    @Builder.Default
    boolean missingAudience = false;

    @Builder.Default
    boolean missingAuthorizedParty = false;

    /**
     * The size of the token.
     */
    @Builder.Default
    TokenSize tokenSize = TokenSize.SMALL;

    /**
     * The complexity of the token claims.
     */
    @Builder.Default
    TokenComplexity tokenComplexity = TokenComplexity.SIMPLE;

    /**
     * Creates default parameters for a valid validation of the given type.
     * This method sets appropriate defaults based on the validation type.
     *
     * @param tokenType the type of validation
     * @return a new ClaimControlParameter with default settings for valid tokens
     */
    public static ClaimControlParameter defaultForTokenType(TokenType tokenType) {
        if (tokenType == null) {
            throw new IllegalArgumentException("TokenType must not be null");
        }

        // All tokens have the same default settings for valid tokens
        return builder().build();
    }
}

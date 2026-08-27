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
import de.cuioss.test.generator.TypedGenerator;
import lombok.experimental.UtilityClass;

/**
 * Factory for creating TypedGenerator instances that produce TestTokenHolder objects.
 * <p>
 * This factory provides methods for creating generators for different token types:
 * <ul>
 *   <li>Access tokens</li>
 *   <li>ID tokens</li>
 *   <li>Refresh tokens</li>
 * </ul>
 * <p>
 * It also provides methods for creating generators with specific token sizes and complexities.
 * <p>
 * These generators are intended to replace the existing token generators in the project.
 */
@UtilityClass
public class TestTokenGenerators {

    /**
     * Creates a generator for TestTokenHolder objects with ACCESS_TOKEN type.
     *
     * @return a TypedGenerator that produces TestTokenHolder objects with ACCESS_TOKEN type
     */
    public static TypedGenerator<TestTokenHolder> accessTokens() {
        return () -> new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));
    }

    /**
     * Creates a generator for TestTokenHolder objects with ID_TOKEN type.
     *
     * @return a TypedGenerator that produces TestTokenHolder objects with ID_TOKEN type
     */
    public static TypedGenerator<TestTokenHolder> idTokens() {
        return () -> new TestTokenHolder(TokenType.ID_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ID_TOKEN));
    }

    /**
     * Creates a generator for TestTokenHolder objects with REFRESH_TOKEN type.
     *
     * @return a TypedGenerator that produces TestTokenHolder objects with REFRESH_TOKEN type
     */
    public static TypedGenerator<TestTokenHolder> refreshTokens() {
        return () -> new TestTokenHolder(TokenType.REFRESH_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.REFRESH_TOKEN));
    }

    /**
     * Creates a generator for TestTokenHolder objects with ACCESS_TOKEN type and specified size.
     *
     * @param size the size of the token
     * @return a TypedGenerator that produces TestTokenHolder objects with ACCESS_TOKEN type and specified size
     */
    public static TypedGenerator<TestTokenHolder> accessTokens(ClaimControlParameter.TokenSize size) {
        return () -> {
            ClaimControlParameter params = ClaimControlParameter.builder()
                    .tokenSize(size)
                    .build();
            return new TestTokenHolder(TokenType.ACCESS_TOKEN, params);
        };
    }

    /**
     * Creates a generator for TestTokenHolder objects with ID_TOKEN type and specified size.
     *
     * @param size the size of the token
     * @return a TypedGenerator that produces TestTokenHolder objects with ID_TOKEN type and specified size
     */
    public static TypedGenerator<TestTokenHolder> idTokens(ClaimControlParameter.TokenSize size) {
        return () -> {
            ClaimControlParameter params = ClaimControlParameter.builder()
                    .tokenSize(size)
                    .build();
            return new TestTokenHolder(TokenType.ID_TOKEN, params);
        };
    }

    /**
     * Creates a generator for TestTokenHolder objects with REFRESH_TOKEN type and specified size.
     *
     * @param size the size of the token
     * @return a TypedGenerator that produces TestTokenHolder objects with REFRESH_TOKEN type and specified size
     */
    public static TypedGenerator<TestTokenHolder> refreshTokens(ClaimControlParameter.TokenSize size) {
        return () -> {
            ClaimControlParameter params = ClaimControlParameter.builder()
                    .tokenSize(size)
                    .build();
            return new TestTokenHolder(TokenType.REFRESH_TOKEN, params);
        };
    }

    /**
     * Creates a generator for TestTokenHolder objects with ACCESS_TOKEN type, specified size, and complexity.
     *
     * @param size the size of the token
     * @param complexity the complexity of the token claims
     * @return a TypedGenerator that produces TestTokenHolder objects with ACCESS_TOKEN type, specified size, and complexity
     */
    public static TypedGenerator<TestTokenHolder> accessTokens(ClaimControlParameter.TokenSize size,
            ClaimControlParameter.TokenComplexity complexity) {
        return () -> {
            ClaimControlParameter params = ClaimControlParameter.builder()
                    .tokenSize(size)
                    .tokenComplexity(complexity)
                    .build();
            return new TestTokenHolder(TokenType.ACCESS_TOKEN, params);
        };
    }

    /**
     * Creates a generator for TestTokenHolder objects with ID_TOKEN type, specified size, and complexity.
     *
     * @param size the size of the token
     * @param complexity the complexity of the token claims
     * @return a TypedGenerator that produces TestTokenHolder objects with ID_TOKEN type, specified size, and complexity
     */
    public static TypedGenerator<TestTokenHolder> idTokens(ClaimControlParameter.TokenSize size,
            ClaimControlParameter.TokenComplexity complexity) {
        return () -> {
            ClaimControlParameter params = ClaimControlParameter.builder()
                    .tokenSize(size)
                    .tokenComplexity(complexity)
                    .build();
            return new TestTokenHolder(TokenType.ID_TOKEN, params);
        };
    }

    /**
     * Creates a generator for TestTokenHolder objects with REFRESH_TOKEN type, specified size, and complexity.
     *
     * @param size the size of the token
     * @param complexity the complexity of the token claims
     * @return a TypedGenerator that produces TestTokenHolder objects with REFRESH_TOKEN type, specified size, and complexity
     */
    public static TypedGenerator<TestTokenHolder> refreshTokens(ClaimControlParameter.TokenSize size,
            ClaimControlParameter.TokenComplexity complexity) {
        return () -> {
            ClaimControlParameter params = ClaimControlParameter.builder()
                    .tokenSize(size)
                    .tokenComplexity(complexity)
                    .build();
            return new TestTokenHolder(TokenType.REFRESH_TOKEN, params);
        };
    }
}

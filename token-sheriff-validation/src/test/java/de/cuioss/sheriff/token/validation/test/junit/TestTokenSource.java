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
package de.cuioss.sheriff.token.validation.test.junit;

import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.lang.annotation.*;

/**
 * Annotation for providing test tokens of a specific type to parameterized tests.
 * <p>
 * This annotation is used to inject {@link TestTokenHolder}
 * instances into test methods. The token type determines which generator method from
 * {@link de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators} will be used.
 * <p>
 * Example usage:
 * <pre>
 * {@code
 * @ParameterizedTest
 * @TestTokenSource(TokenType.ACCESS_TOKEN)
 * void testWithAccessToken(TestTokenHolder tokenHolder) {
 *     // Test code using the token holder
 * }
 * }
 * </pre>
 *
 * @author Oliver Wolff
 * @see de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators
 * @see TestTokenHolder
 */
@Target({ElementType.METHOD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@ArgumentsSource(TestTokenSourceProvider.class)
public @interface TestTokenSource {

    /**
     * The type of token to generate.
     *
     * @return the token type
     */
    TokenType value();

    /**
     * The number of test tokens to generate.
     * <p>
     * Defaults to 1.
     *
     * @return the number of test tokens
     */
    int count() default 1;
}
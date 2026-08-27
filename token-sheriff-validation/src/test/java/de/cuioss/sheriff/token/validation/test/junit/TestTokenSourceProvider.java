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
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.TypedGenerator;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.ParameterDeclarations;

import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Provider for test tokens based on the token type specified in the {@link TestTokenSource} annotation.
 * <p>
 * This provider selects the appropriate generator method from {@link TestTokenGenerators} based on
 * the token type and generates the specified number of test tokens.
 *
 * @author Oliver Wolff
 * @see TestTokenSource
 * @see TestTokenGenerators
 */
class TestTokenSourceProvider implements ArgumentsProvider {

    @Override
    public Stream<Arguments> provideArguments(ParameterDeclarations parameters, ExtensionContext context) {
        // Get the TestTokenSource annotation from the test method
        var annotatedElement = context.getElement().orElseThrow(() ->
                new IllegalStateException("No annotated element found"));

        TestTokenSource annotation = annotatedElement.getAnnotation(TestTokenSource.class);
        if (annotation == null) {
            throw new IllegalStateException("No @TestTokenSource annotation found on test method");
        }

        // Get the token type and count from the annotation
        TokenType tokenType = annotation.value();
        int count = annotation.count();

        // Select the appropriate generator based on the token type
        TypedGenerator<TestTokenHolder> generator = getGeneratorForTokenType(tokenType);

        // Generate the specified number of test tokens
        return IntStream.range(0, count)
                .mapToObj(i -> Arguments.of(generator.next()));
    }

    /**
     * Gets the appropriate generator for the specified token type.
     *
     * @param tokenType the token type
     * @return the generator for the specified token type
     */
    private TypedGenerator<TestTokenHolder> getGeneratorForTokenType(TokenType tokenType) {
        return switch (tokenType) {
            case ACCESS_TOKEN -> TestTokenGenerators.accessTokens();
            case ID_TOKEN -> TestTokenGenerators.idTokens();
            case REFRESH_TOKEN -> TestTokenGenerators.refreshTokens();
            default -> throw new IllegalArgumentException("Unsupported token type: " + tokenType);
        };
    }
}

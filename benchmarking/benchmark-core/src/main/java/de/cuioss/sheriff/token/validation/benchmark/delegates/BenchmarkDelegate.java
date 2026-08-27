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
package de.cuioss.sheriff.token.validation.benchmark.delegates;

import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.benchmark.MockTokenRepository;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;

/**
 * Base class for benchmark delegates that encapsulate the core benchmark logic.
 * This allows the same logic to be used by both regular and JFR-instrumented benchmarks.
 *
 * @author Oliver Wolff
 */
public abstract class BenchmarkDelegate {

    protected final TokenValidator tokenValidator;
    protected final MockTokenRepository tokenRepository;

    protected BenchmarkDelegate(TokenValidator tokenValidator, MockTokenRepository tokenRepository) {
        this.tokenValidator = tokenValidator;
        this.tokenRepository = tokenRepository;
    }

    /**
     * Validates a token and returns the result.
     *
     * @param token the token to validate
     * @return the validated access token content
     * @throws TokenValidationException if validation fails
     */
    protected AccessTokenContent validateToken(String token) throws TokenValidationException {
        return tokenValidator.createAccessToken(AccessTokenRequest.of(token));
    }

}
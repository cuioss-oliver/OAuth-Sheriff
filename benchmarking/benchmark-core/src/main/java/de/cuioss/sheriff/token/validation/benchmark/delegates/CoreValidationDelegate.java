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
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Delegate for core validation benchmarks including average time and throughput.
 *
 * @author Oliver Wolff
 */
public class CoreValidationDelegate extends BenchmarkDelegate {

    private final AtomicInteger tokenIndex = new AtomicInteger(0);

    public CoreValidationDelegate(TokenValidator tokenValidator, MockTokenRepository tokenRepository) {
        super(tokenValidator, tokenRepository);
    }

    /**
     * Performs token validation using the full token spectrum with rotation.
     * Rotates through all tokens in the pool for maximum cache testing.
     *
     * @return the validated access token content
     * @throws IllegalStateException if validation fails unexpectedly
     */
    public AccessTokenContent validateWithFullSpectrum() {
        try {
            // Use rotation through entire token pool for full spectrum testing
            String token = tokenRepository.getToken(tokenIndex.getAndIncrement());
            return validateToken(token);
        } catch (TokenValidationException e) {
            throw new IllegalStateException("Unexpected validation failure during full spectrum validation", e);
        }
    }

    /**
     * Gets the current token for the given operation type.
     *
     * @param operationType the type of operation (e.g., "primary", "rotation", "full_spectrum")
     * @return the token to use for validation
     */
    public String getCurrentToken(String operationType) {
        if ("rotation".equals(operationType) || "full_spectrum".equals(operationType)) {
            return tokenRepository.getToken(tokenIndex.get());
        }
        return tokenRepository.getPrimaryToken();
    }
}
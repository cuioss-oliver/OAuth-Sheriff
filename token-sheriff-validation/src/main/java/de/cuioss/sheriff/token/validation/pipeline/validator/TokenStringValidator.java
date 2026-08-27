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
package de.cuioss.sheriff.token.validation.pipeline.validator;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwe.JweDecryptionConfig;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import org.jspecify.annotations.Nullable;

import java.nio.charset.StandardCharsets;

/**
 * Validates the raw JWT token string before pipeline processing.
 * <p>
 * Performs early validation checks on the token string including:
 * <ul>
 *   <li>Null check</li>
 *   <li>Empty/blank check</li>
 *   <li>Maximum token size enforcement (from ParserConfig)</li>
 * </ul>
 * <p>
 * This validator ensures that token-type-specific pipelines can safely assume
 * a valid non-null, non-empty token string within size limits.
 * <p>
 * This class is thread-safe and stateless after construction.
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
public class TokenStringValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenStringValidator.class);

    private final int maxTokenSize;
    private final SecurityEventCounter securityEventCounter;

    /**
     * Creates a new TokenStringValidator that uses the JWE max token size when JWE is configured.
     *
     * @param parserConfig the parser configuration
     * @param securityEventCounter the security event counter
     * @param jweDecryptionConfig optional JWE config — uses its maxEncryptedTokenSize if present
     */
    public TokenStringValidator(ParserConfig parserConfig,
            SecurityEventCounter securityEventCounter,
            @Nullable JweDecryptionConfig jweDecryptionConfig) {
        this.maxTokenSize = jweDecryptionConfig != null
                ? jweDecryptionConfig.getMaxEncryptedTokenSize()
                : parserConfig.getMaxTokenSize();
        this.securityEventCounter = securityEventCounter;
    }

    /**
     * Validates the raw token string.
     * <p>
     * This method performs the following checks in order:
     * <ol>
     *   <li>Null/blank check - throws if token is null, empty, or contains only whitespace</li>
     *   <li>Size limit check - throws if token exceeds maximum byte size</li>
     * </ol>
     *
     * @param tokenString the token string to validate (may be null)
     * @throws TokenValidationException if the token string is invalid
     */
    public void validate(String tokenString) {
        // Check null/blank/empty (MoreStrings.isBlank handles null internally)
        if (MoreStrings.isBlank(tokenString)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_EMPTY);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.TOKEN_EMPTY,
                    "Token is null, empty, or blank"
            );
        }

        // Check size limit (use byte length for accurate size measurement)
        int tokenByteLength = tokenString.getBytes(StandardCharsets.UTF_8).length;
        if (tokenByteLength > maxTokenSize) {
            LOGGER.warn(JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED, maxTokenSize);
            securityEventCounter.increment(SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED,
                    "Token size %d exceeds maximum %d".formatted(tokenByteLength, maxTokenSize)
            );
        }
    }
}

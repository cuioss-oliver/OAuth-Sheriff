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
package de.cuioss.sheriff.token.validation;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.domain.context.IdTokenRequest;
import de.cuioss.sheriff.token.validation.pipeline.IdTokenValidationPipeline;
import de.cuioss.sheriff.token.validation.pipeline.NonValidatingJwtParser;
import de.cuioss.sheriff.token.validation.pipeline.SignatureTemplateManager;
import de.cuioss.sheriff.token.validation.pipeline.TokenBuilder;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenHeaderValidator;
import de.cuioss.sheriff.token.validation.pipeline.validator.TokenSignatureValidator;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the defensive null-check branches in {@link IdTokenValidationPipeline}.
 * <p>
 * These guard against misconfiguration where an issuer resolves successfully
 * but no validator was pre-created for it in the maps. Each test constructs
 * the pipeline directly with missing validator entries to trigger the
 * IllegalStateException branches.
 * <p>
 * This test class is in the {@code de.cuioss.sheriff.token.validation} package
 * to access the package-private {@link IssuerConfigCache} constructor.
 */
@EnableTestLogger
@DisplayName("IdTokenValidationPipeline null-check branches")
class IdTokenValidationPipelineNullCheckTest {

    private TestTokenHolder tokenHolder;
    private NonValidatingJwtParser jwtParser;
    private IssuerConfigCache issuerConfigCache;
    private SecurityEventCounter securityEventCounter;
    private IssuerConfig issuerConfig;

    @BeforeEach
    void setUp() {
        tokenHolder = TestTokenGenerators.idTokens().next();
        securityEventCounter = new SecurityEventCounter();
        jwtParser = NonValidatingJwtParser.builder()
                .config(ParserConfig.builder().build())
                .securityEventCounter(securityEventCounter)
                .build();
        // Create a single IssuerConfig and share it between cache and validators
        issuerConfig = tokenHolder.getIssuerConfig();
        // Create IssuerConfigCache with the valid issuer config - this triggers async JWKS init
        issuerConfigCache = new IssuerConfigCache(
                List.of(issuerConfig),
                securityEventCounter
        );
        // Wait for async JWKS loading to complete by resolving the config
        issuerConfigCache.resolveConfig(issuerConfig.getIssuerIdentifier());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when header validator map is empty")
    void shouldThrowWhenHeaderValidatorMissing() {
        // Given - pipeline with empty validator maps
        IdTokenValidationPipeline pipeline = new IdTokenValidationPipeline(
                jwtParser,
                issuerConfigCache,
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                securityEventCounter
        );
        String tokenString = tokenHolder.getRawToken();
        var request = IdTokenRequest.of(tokenString);

        // When/Then
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> pipeline.validate(request)
        );
        assertTrue(exception.getMessage().contains("No header validator found for issuer"),
                "Should indicate missing header validator");
    }

    @Test
    @DisplayName("Should throw IllegalStateException when signature validator map is empty")
    void shouldThrowWhenSignatureValidatorMissing() {
        // Given - pipeline with header validator present but no signature validator
        String issuerId = issuerConfig.getIssuerIdentifier();

        IdTokenValidationPipeline pipeline = new IdTokenValidationPipeline(
                jwtParser,
                issuerConfigCache,
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(issuerId, new TokenHeaderValidator(issuerConfig, securityEventCounter)),
                securityEventCounter
        );
        String tokenString = tokenHolder.getRawToken();
        var request = IdTokenRequest.of(tokenString);

        // When/Then
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> pipeline.validate(request)
        );
        assertTrue(exception.getMessage().contains("No signature validator found for issuer"),
                "Should indicate missing signature validator");
    }

    @Test
    @DisplayName("Should throw IllegalStateException when token builder map is empty")
    void shouldThrowWhenTokenBuilderMissing() {
        // Given - pipeline with header and signature validators but no token builder
        String issuerId = issuerConfig.getIssuerIdentifier();

        IdTokenValidationPipeline pipeline = new IdTokenValidationPipeline(
                jwtParser,
                issuerConfigCache,
                Map.of(issuerId, new TokenSignatureValidator(
                        issuerConfig.getJwksLoader(), securityEventCounter,
                        new SignatureTemplateManager(issuerConfig.getAlgorithmPreferences()))),
                Map.of(),
                Map.of(),
                Map.of(issuerId, new TokenHeaderValidator(issuerConfig, securityEventCounter)),
                securityEventCounter
        );
        String tokenString = tokenHolder.getRawToken();
        var request = IdTokenRequest.of(tokenString);

        // When/Then
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> pipeline.validate(request)
        );
        assertTrue(exception.getMessage().contains("No token builder found for issuer"),
                "Should indicate missing token builder, got: " + exception.getMessage());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when claim validator map is empty")
    void shouldThrowWhenClaimValidatorMissing() {
        // Given - pipeline with header, signature, and token builder but no claim validator
        String issuerId = issuerConfig.getIssuerIdentifier();

        IdTokenValidationPipeline pipeline = new IdTokenValidationPipeline(
                jwtParser,
                issuerConfigCache,
                Map.of(issuerId, new TokenSignatureValidator(
                        issuerConfig.getJwksLoader(), securityEventCounter,
                        new SignatureTemplateManager(issuerConfig.getAlgorithmPreferences()))),
                Map.of(issuerId, new TokenBuilder(issuerConfig)),
                Map.of(),
                Map.of(issuerId, new TokenHeaderValidator(issuerConfig, securityEventCounter)),
                securityEventCounter
        );
        String tokenString = tokenHolder.getRawToken();
        var request = IdTokenRequest.of(tokenString);

        // When/Then
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> pipeline.validate(request)
        );
        assertTrue(exception.getMessage().contains("No claim validator found for issuer"),
                "Should indicate missing claim validator");
    }
}

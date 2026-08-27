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
package de.cuioss.sheriff.token.quarkus.producer;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.quarkus.config.JwtTestProfile;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Quarkus integration tests for {@link TokenValidatorProducer} focusing on CDI injection and integration.
 * Configuration validation is covered in the config package tests.
 */
@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
class QuarkusTokenValidatorProducerTest {

    @Inject
    TokenValidatorProducer producer;

    @Inject
    Config config;

    @Inject
    TokenValidator tokenValidator;

    @Inject
    List<IssuerConfig> issuerConfigs;

    @Test
    @DisplayName("Should successfully inject and initialize all JWT components via CDI")
    void shouldSuccessfullyInjectAndInitializeJwtComponents() {
        assertFalse(issuerConfigs.isEmpty(), "Should have at least one issuer config");

        // Verify SecurityEventCounter is accessible through TokenValidator
        SecurityEventCounter securityEventCounter = tokenValidator.getSecurityEventCounter();
        assertNotNull(securityEventCounter, "SecurityEventCounter should be accessible via TokenValidator");
        // Note: SecurityEventCounter may have counters from other tests as it's ApplicationScoped
        // We're just verifying it's accessible, not that it's empty

        assertTrue(issuerConfigs.stream()
                        .anyMatch(issuer -> "https://example.com/auth".equals(issuer.getIssuerIdentifier())),
                "Should load default issuer from JwtTestProfile");

        // Note: Log assertions are skipped in Quarkus test environment
        // as logs during CDI initialization may not be captured by test logger
    }

    @Test
    @DisplayName("Should reject invalid tokens in integrated environment")
    void shouldRejectInvalidTokensInIntegratedEnvironment() {
        String invalidToken = "invalid.token.format";

        var request = AccessTokenRequest.of(invalidToken);
        assertThrows(TokenValidationException.class, () -> tokenValidator.createAccessToken(request),
                "Integrated TokenValidator should reject invalid tokens");
    }

}

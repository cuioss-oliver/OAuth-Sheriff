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
package de.cuioss.sheriff.token.quarkus.deployment;

import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.QuarkusExtensionTest;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration test to verify the auto-configuration with different configuration scenarios.
 * <p>
 * This test checks:
 * <ul>
 * <li>Multiple issuers configuration</li>
 * <li>Custom parser settings</li>
 * <li>Overall integration</li>
 * </ul>
 */
@EnableTestLogger
class TokenSheriffIntegrationTest {

    /**
     * The Quarkus test framework.
     */
    @RegisterExtension
    static final QuarkusExtensionTest unitTest = new QuarkusExtensionTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class))
            .withConfigurationResource("application-integration.properties");

    @Inject
    Config config;

    @Test
    void multipleIssuersConfiguration() {
        assertNotNull(config, "Config should be injected");

        // Verify default issuer
        assertTrue(config.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("default"), Boolean.class).orElse(false),
                "Default issuer should be enabled");
        assertTrue(config.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("default"), String.class).isPresent(),
                "Default issuer should have identifier");

        // Verify keycloak issuer
        assertTrue(config.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("keycloak"), Boolean.class).orElse(false),
                "Keycloak issuer should be enabled");
        assertTrue(config.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("keycloak"), String.class).isPresent(),
                "Keycloak issuer should have identifier");

        // Verify parser configuration
        assertTrue(config.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).isPresent(),
                "Parser config should be present");
    }
}

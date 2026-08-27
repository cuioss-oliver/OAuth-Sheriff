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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for verifying the auto-configuration of the Token-Sheriff Quarkus extension.
 * <p>
 * This test checks:
 * <ul>
 * <li>The configuration is properly available</li>
 * <li>The extension can be deployed and used</li>
 * </ul>
 */
@EnableTestLogger
class TokenSheriffProcessorTest {

    /**
     * The Quarkus test framework.
     */
    @RegisterExtension
    static final QuarkusExtensionTest unitTest = new QuarkusExtensionTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class))
            .withConfigurationResource("application-test.properties");

    @Inject
    Config config;

    @Test
    void jwtConfigAvailable() {
        assertNotNull(config, "Config should be injected");

        // Verify the default issuer is configured
        assertTrue(config.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("default"), Boolean.class).orElse(false),
                "Default issuer should be enabled");
        assertTrue(config.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("default"), String.class).isPresent(),
                "Default issuer should have identifier");
        assertTrue(config.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).isPresent(),
                "Parser config should be present");
    }

    @Test
    void shouldTestProcessorBasicFunctionality() {
        // Test that processor can be instantiated without issues
        assertDoesNotThrow(TokenSheriffProcessor::new,
                "TokenSheriffProcessor should be instantiable without exceptions");

        TokenSheriffProcessor processor = new TokenSheriffProcessor();
        assertNotNull(processor, "Processor should not be null");
    }

}

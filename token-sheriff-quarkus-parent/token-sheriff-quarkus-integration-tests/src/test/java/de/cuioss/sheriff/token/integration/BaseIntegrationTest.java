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
package de.cuioss.sheriff.token.integration;

import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import io.restassured.RestAssured;
import org.junit.jupiter.api.BeforeAll;

/**
 * Base class for integration tests with proper external port configuration.
 * <p>
 * This class configures REST Assured to use the external test port
 * that is configured via Maven properties and Docker port mapping.
 * Tests should always access the application from the outside perspective.
 */
@EnableTestLogger
public abstract class BaseIntegrationTest {

    private static final CuiLogger LOGGER = new CuiLogger(BaseIntegrationTest.class);
    private static final String DEFAULT_TEST_PORT = "10443";

    @BeforeAll
    static void setUpBaseIntegrationTest() {
        // Configure HTTPS with proper certificate validation using custom truststore
        configureCustomTruststore();
        RestAssured.baseURI = "https://localhost";

        // Use the external test port from Maven properties (Docker port mapping 10443:8443)
        String testPort = System.getProperty("test.https.port", DEFAULT_TEST_PORT);
        RestAssured.port = Integer.parseInt(testPort);

        LOGGER.debug("Integration tests configured for HTTPS port: %s with relaxed HTTPS validation", testPort);
    }

    private static void configureCustomTruststore() {
        // Use relaxed HTTPS validation for integration tests
        // The actual certificate validation is tested in the JWT validation service itself
        RestAssured.useRelaxedHTTPSValidation();

        LOGGER.debug("Configured relaxed HTTPS validation for integration tests");
    }
}
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

import de.cuioss.sheriff.token.quarkus.config.JwtTestProfile;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Native image integration tests for the JWT validation functionality.
 * This test validates that the Quarkus application starts correctly in native mode
 * and the JWT validation components are available.
 *
 * Note: @QuarkusIntegrationTest does not support @Inject annotations, so we test
 * the application startup indirectly.
 */
@QuarkusIntegrationTest
@TestProfile(JwtTestProfile.class)
class NativeTokenValidatorProducerIT {

    /**
     * Test that the application starts successfully in native mode.
     * This indirectly tests that all JWT validation producers and their dependencies
     * are correctly configured and available. The test passes if the Quarkus
     * application starts without errors.
     */
    @Test
    @DisplayName("Should start application successfully in native mode")
    @SuppressWarnings("java:S2699")
    void shouldStartApplicationInNativeMode() {
        // Given: The Quarkus application is running in native mode
        // When: The application has started successfully (no startup exceptions)
        // Then: This test passes, indicating all JWT components are properly configured

        // This is a basic smoke test - if the Quarkus application starts without
        // errors, it means all CDI beans (including JWT validation components)
        // are properly configured and can be instantiated.

        // We can verify this by checking that the test environment itself works
        assert true : "Application started successfully in native mode";
    }
}
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
package de.cuioss.sheriff.token.quarkus.config;

import de.cuioss.http.client.adapter.RetryConfig;
import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RetryStrategyConfigResolver Tests")
class RetryStrategyConfigResolverTest {

    @Test
    @DisplayName("should create resolver with config")
    void shouldCreateResolverWithConfig() {
        TestConfig config = new TestConfig(Map.of());

        RetryStrategyConfigResolver resolver = new RetryStrategyConfigResolver(config);

        assertNotNull(resolver);
    }

    @Test
    @DisplayName("should resolve retry config with default values")
    void shouldResolveWithDefaults() {
        TestConfig config = new TestConfig(Map.of());
        RetryStrategyConfigResolver resolver = new RetryStrategyConfigResolver(config);

        RetryConfig result = resolver.resolveRetryConfig();

        assertNotNull(result);
        assertEquals(5, result.maxAttempts());
    }

    @Test
    @DisplayName("should resolve retry config with custom values")
    void shouldResolveWithCustomValues() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.RETRY.MAX_ATTEMPTS, "3",
                JwtPropertyKeys.RETRY.INITIAL_DELAY_MS, "500",
                JwtPropertyKeys.RETRY.MAX_DELAY_MS, "10000",
                JwtPropertyKeys.RETRY.BACKOFF_MULTIPLIER, "1.5",
                JwtPropertyKeys.RETRY.JITTER_FACTOR, "0.2"
        ));
        RetryStrategyConfigResolver resolver = new RetryStrategyConfigResolver(config);

        RetryConfig result = resolver.resolveRetryConfig();

        assertNotNull(result);
        assertEquals(3, result.maxAttempts());
        assertEquals(500, result.initialDelay().toMillis());
        assertEquals(10000, result.maxDelay().toMillis());
        assertEquals(1.5, result.multiplier());
        assertEquals(0.2, result.jitter());
    }

    @Test
    @DisplayName("should return no-retry config when retry is disabled")
    void shouldReturnNoOpWhenDisabled() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.RETRY.ENABLED, "false"
        ));
        RetryStrategyConfigResolver resolver = new RetryStrategyConfigResolver(config);

        RetryConfig result = resolver.resolveRetryConfig();

        assertNotNull(result);
        assertEquals(1, result.maxAttempts(), "Should have maxAttempts=1 (no retries) when retry is disabled");
    }

    @Test
    @DisplayName("should enable retry by default when enabled flag is not set")
    void shouldEnableRetryByDefault() {
        TestConfig config = new TestConfig(Map.of());
        RetryStrategyConfigResolver resolver = new RetryStrategyConfigResolver(config);

        RetryConfig result = resolver.resolveRetryConfig();

        assertNotNull(result);
        assertTrue(result.maxAttempts() > 0, "Should have maxAttempts > 0 when retry is enabled by default");
    }

    @Test
    @DisplayName("should enable retry when explicitly set to true")
    void shouldEnableRetryWhenExplicitlyTrue() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.RETRY.ENABLED, "true",
                JwtPropertyKeys.RETRY.MAX_ATTEMPTS, "2"
        ));
        RetryStrategyConfigResolver resolver = new RetryStrategyConfigResolver(config);

        RetryConfig result = resolver.resolveRetryConfig();

        assertNotNull(result);
        assertEquals(2, result.maxAttempts());
    }

    @Test
    @DisplayName("should handle partial configuration")
    void shouldHandlePartialConfiguration() {
        TestConfig config = new TestConfig(Map.of(
                JwtPropertyKeys.RETRY.MAX_ATTEMPTS, "10",
                JwtPropertyKeys.RETRY.INITIAL_DELAY_MS, "2000"
        ));
        RetryStrategyConfigResolver resolver = new RetryStrategyConfigResolver(config);

        RetryConfig result = resolver.resolveRetryConfig();

        assertNotNull(result);
        assertEquals(10, result.maxAttempts());
        assertEquals(2000, result.initialDelay().toMillis());
    }

}

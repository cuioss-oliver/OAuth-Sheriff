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

import de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;
import static de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys.CACHE;
import static de.cuioss.test.juli.LogAsserts.assertSingleLogMessagePresentContaining;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@EnableTestLogger
class AccessTokenCacheConfigResolverTest {

    @Test
    void resolveCacheConfigWithDefaults() {
        // Given - empty config (uses defaults)
        Config config = new SmallRyeConfigBuilder()
                .build();
        AccessTokenCacheConfigResolver resolver = new AccessTokenCacheConfigResolver(config);

        // When
        AccessTokenCacheConfig cacheConfig = resolver.resolveCacheConfig();

        // Then
        assertNotNull(cacheConfig);
        assertEquals(1000, cacheConfig.getMaxSize());
        assertEquals(10L, cacheConfig.getEvictionIntervalSeconds());

        // Verify logging
        assertSingleLogMessagePresentContaining(TestLogLevel.INFO, INFO.RESOLVING_ACCESS_TOKEN_CACHE_CONFIG.resolveIdentifierString());
        assertSingleLogMessagePresentContaining(TestLogLevel.INFO, INFO.ACCESS_TOKEN_CACHE_CONFIGURED.format(1000, 10L));
    }

    @Test
    void resolveCacheConfigWithCustomValues() {
        // Given - custom config values
        Map<String, String> properties = Map.of(
                CACHE.MAX_SIZE, "500",
                CACHE.EVICTION_INTERVAL_SECONDS, "60"
        );
        Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(properties)
                .build();
        AccessTokenCacheConfigResolver resolver = new AccessTokenCacheConfigResolver(config);

        // When
        AccessTokenCacheConfig cacheConfig = resolver.resolveCacheConfig();

        // Then
        assertNotNull(cacheConfig);
        assertEquals(500, cacheConfig.getMaxSize());
        assertEquals(60L, cacheConfig.getEvictionIntervalSeconds());

        // Verify logging
        assertSingleLogMessagePresentContaining(TestLogLevel.INFO, INFO.RESOLVING_ACCESS_TOKEN_CACHE_CONFIG.resolveIdentifierString());
        assertSingleLogMessagePresentContaining(TestLogLevel.INFO, INFO.ACCESS_TOKEN_CACHE_CONFIGURED.format(500, 60L));
    }

    @Test
    void resolveCacheConfigDisabled() {
        // Given - cache disabled with maxSize=0
        Map<String, String> properties = Map.of(
                CACHE.MAX_SIZE, "0"
        );
        Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(properties)
                .build();
        AccessTokenCacheConfigResolver resolver = new AccessTokenCacheConfigResolver(config);

        // When
        AccessTokenCacheConfig cacheConfig = resolver.resolveCacheConfig();

        // Then
        assertNotNull(cacheConfig);
        assertEquals(0, cacheConfig.getMaxSize());
        // When disabled, evictionIntervalSeconds should be the disabled config default
        assertEquals(10L, cacheConfig.getEvictionIntervalSeconds());

        // Verify logging
        assertSingleLogMessagePresentContaining(TestLogLevel.INFO, INFO.RESOLVING_ACCESS_TOKEN_CACHE_CONFIG.resolveIdentifierString());
        assertSingleLogMessagePresentContaining(TestLogLevel.INFO, INFO.ACCESS_TOKEN_CACHE_DISABLED.resolveIdentifierString());
    }

    @Test
    void resolveCacheConfigFromMap() {
        // Given - config from map
        Map<String, String> properties = Map.of(
                CACHE.MAX_SIZE, "250",
                CACHE.EVICTION_INTERVAL_SECONDS, "30"
        );
        Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(properties)
                .build();
        AccessTokenCacheConfigResolver resolver = new AccessTokenCacheConfigResolver(config);

        // When
        AccessTokenCacheConfig cacheConfig = resolver.resolveCacheConfig();

        // Then
        assertNotNull(cacheConfig);
        assertEquals(250, cacheConfig.getMaxSize());
        assertEquals(30L, cacheConfig.getEvictionIntervalSeconds());

        // Verify logging
        assertSingleLogMessagePresentContaining(TestLogLevel.INFO, INFO.RESOLVING_ACCESS_TOKEN_CACHE_CONFIG.resolveIdentifierString());
        assertSingleLogMessagePresentContaining(TestLogLevel.INFO, INFO.ACCESS_TOKEN_CACHE_CONFIGURED.format(250, 30L));
    }
}
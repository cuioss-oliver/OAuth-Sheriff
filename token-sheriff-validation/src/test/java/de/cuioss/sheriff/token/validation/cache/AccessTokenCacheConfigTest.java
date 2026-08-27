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
package de.cuioss.sheriff.token.validation.cache;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitorConfig;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.junit.jupiter.api.Assertions.*;

class AccessTokenCacheConfigTest {

    @Test
    void defaultConfig() {
        // When
        AccessTokenCacheConfig config = AccessTokenCacheConfig.defaultConfig();

        // Then
        assertEquals(AccessTokenCacheConfig.DEFAULT_MAX_SIZE, config.getMaxSize());
        assertEquals(AccessTokenCacheConfig.DEFAULT_EVICTION_INTERVAL_SECONDS, config.getEvictionIntervalSeconds());
        assertTrue(config.isCachingEnabled());
    }

    @Test
    void disabledConfig() {
        // When
        AccessTokenCacheConfig config = AccessTokenCacheConfig.disabled();

        // Then
        assertEquals(0, config.getMaxSize());
        assertFalse(config.isCachingEnabled());
    }

    @Test
    void customConfig() {
        // Given
        int customMaxSize = 500;
        long customEvictionInterval = 600L;

        // When
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(customMaxSize)
                .evictionIntervalSeconds(customEvictionInterval)
                .build();

        // Then
        assertEquals(customMaxSize, config.getMaxSize());
        assertEquals(customEvictionInterval, config.getEvictionIntervalSeconds());
        assertTrue(config.isCachingEnabled());
    }

    @Test
    void createCacheEnabled() {
        // Given
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(100)
                .evictionIntervalSeconds(300L)
                .build();

        // When
        AccessTokenCache cache = new AccessTokenCache(config, securityEventCounter, 0);

        // Then
        assertNotNull(cache);

        // Cleanup
        cache.shutdown();
    }

    @Test
    void createCacheDisabled() {
        // Given
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(0)
                .build();
        AccessTokenContent expectedContent = createAccessToken("https://example.com",
                OffsetDateTime.now().plusHours(1));

        // When
        AccessTokenCache cache = new AccessTokenCache(config, securityEventCounter, 0);

        // Then - cache is created but calls validation function directly (no caching)
        assertNotNull(cache);

        // Verify it calls validation function and returns result (transparent behavior)
        var performanceMonitor = TokenValidatorMonitorConfig.builder()
                .measurementTypes(TokenValidatorMonitorConfig.ALL_MEASUREMENT_TYPES)
                .build()
                .createMonitor();
        Optional<AccessTokenContent> cached = cache.get("token", performanceMonitor, OffsetDateTime.now());
        AccessTokenContent result;
        if (cached.isEmpty()) {
            result = expectedContent;
            cache.put("token", result, performanceMonitor);
        } else {
            result = cached.get();
        }
        assertEquals(expectedContent, result);

        // Verify cache remains empty (no caching occurred)
        assertEquals(0, cache.size());

        // Cleanup
        cache.shutdown();
    }

    private static AccessTokenContent createAccessToken(String issuer, OffsetDateTime expirationTime) {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString(issuer));
        if (expirationTime != null) {
            tokenHolder.withClaim(ClaimName.EXPIRATION.getName(), ClaimValue.forDateTime(String.valueOf(expirationTime.toEpochSecond()), expirationTime));
        }
        tokenHolder.withClaim(ClaimName.ISSUED_AT.getName(), ClaimValue.forDateTime(String.valueOf(OffsetDateTime.now().minusMinutes(5).toEpochSecond()), OffsetDateTime.now().minusMinutes(5)));
        tokenHolder.withClaim(ClaimName.TOKEN_ID.getName(), ClaimValue.forPlainString("jti-" + System.nanoTime()));
        return tokenHolder.asAccessTokenContent();
    }

    @Test
    void isCachingEnabledWithVariousSizes() {
        // Test enabled cases
        assertTrue(AccessTokenCacheConfig.builder().maxSize(1).build().isCachingEnabled());
        assertTrue(AccessTokenCacheConfig.builder().maxSize(1000).build().isCachingEnabled());
        assertTrue(AccessTokenCacheConfig.builder().maxSize(Integer.MAX_VALUE).build().isCachingEnabled());

        // Test disabled case
        assertFalse(AccessTokenCacheConfig.builder().maxSize(0).build().isCachingEnabled());
    }

    @Test
    void builderDefaults() {
        // When
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder().build();

        // Then
        assertEquals(AccessTokenCacheConfig.DEFAULT_MAX_SIZE, config.getMaxSize());
        assertEquals(AccessTokenCacheConfig.DEFAULT_EVICTION_INTERVAL_SECONDS, config.getEvictionIntervalSeconds());
        assertTrue(config.isCachingEnabled());
        assertNull(config.getScheduledExecutorService());
    }

    @Test
    void createScheduledExecutorServiceCreatesNewInstancePerCall() {
        // Given
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(100)
                .build();

        // When
        ScheduledExecutorService first = config.createScheduledExecutorService();
        ScheduledExecutorService second = config.createScheduledExecutorService();

        // Then
        assertNotNull(first);
        assertNotSame(first, second, "each call creates a new executor the caller owns");
        // Cleanup
        first.shutdown();
        second.shutdown();
    }

    @Test
    void callerSuppliedExecutorIsExposedViaGetter() {
        // Given
        ScheduledExecutorService providedExecutor = Executors.newSingleThreadScheduledExecutor();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(100)
                .scheduledExecutorService(providedExecutor)
                .build();

        // Then
        assertSame(providedExecutor, config.getScheduledExecutorService());
        // Cleanup
        providedExecutor.shutdown();
    }

    @Test
    void validateShouldPassForValidConfig() {
        // Given
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(100)
                .evictionIntervalSeconds(300L)
                .build();

        // When / Then - should not throw
        assertDoesNotThrow(config::validate);
    }

    @Test
    void validateShouldPassWhenCachingDisabled() {
        // Given - maxSize=0, evictionIntervalSeconds irrelevant
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(0)
                .evictionIntervalSeconds(0L)
                .build();

        // When / Then - should not throw because maxSize is 0
        assertDoesNotThrow(config::validate);
    }

    @Test
    void validateShouldThrowWhenMaxSizePositiveAndEvictionIntervalZero() {
        // Given
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(100)
                .evictionIntervalSeconds(0L)
                .build();

        // When / Then
        var exception = assertThrows(IllegalArgumentException.class, config::validate);
        assertTrue(exception.getMessage().contains("evictionIntervalSeconds must be positive"));
    }

    @Test
    void validateShouldThrowWhenMaxSizePositiveAndEvictionIntervalNegative() {
        // Given
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(100)
                .evictionIntervalSeconds(-5L)
                .build();

        // When / Then
        var exception = assertThrows(IllegalArgumentException.class, config::validate);
        assertTrue(exception.getMessage().contains("evictionIntervalSeconds must be positive"));
    }

    @Test
    void createCacheWithProvidedExecutor() {
        // Given
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();
        ScheduledExecutorService providedExecutor = Executors.newSingleThreadScheduledExecutor();
        AccessTokenCacheConfig config = AccessTokenCacheConfig.builder()
                .maxSize(100)
                .evictionIntervalSeconds(300L)
                .scheduledExecutorService(providedExecutor)
                .build();

        // When
        AccessTokenCache cache = new AccessTokenCache(config, securityEventCounter, 0);

        // Then
        assertNotNull(cache);

        // Cleanup
        cache.shutdown();
        providedExecutor.shutdown();
    }
}
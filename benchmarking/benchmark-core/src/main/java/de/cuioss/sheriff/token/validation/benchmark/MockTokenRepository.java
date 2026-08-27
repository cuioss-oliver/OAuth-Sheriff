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
package de.cuioss.sheriff.token.validation.benchmark;

import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.cache.AccessTokenCacheConfig;
import de.cuioss.sheriff.token.validation.metrics.TokenValidatorMonitorConfig;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import io.jsonwebtoken.Jwts;
import lombok.Builder;
import lombok.Getter;
import lombok.Value;

import java.time.Instant;
import java.util.*;

/**
 * Mock token repository for generating JWT tokens in-memory for library benchmark testing.
 * <p>
 * This implementation generates tokens locally without requiring external services,
 * making it ideal for isolated library benchmarks and performance testing.
 * It provides:
 * <ul>
 *   <li>Pre-generated token pools for multiple issuers</li>
 *   <li>Token metadata tracking (issuer, size, etc.)</li>
 *   <li>Pre-configured TokenValidator instances with monitoring</li>
 *   <li>Consistent token shuffling for randomized access patterns</li>
 * </ul>
 * <p>
 * The mock implementation uses pre-generated RSA keys to avoid key generation
 * overhead during benchmarks and provides deterministic token generation for
 * reproducible results.
 * </p>
 *
 * @author Oliver Wolff
 */
@Getter
public class MockTokenRepository {

    /**
     * Default number of different issuers to simulate issuer config resolution overhead
     */
    public static final int DEFAULT_ISSUER_COUNT = 3;

    /**
     * Default shared token pool size for reduced setup overhead
     */
    public static final int DEFAULT_TOKEN_POOL_SIZE = 600; // 200 tokens per issuer (3 issuers)

    /**
     * Default expected audience for benchmarking
     */
    public static final String DEFAULT_AUDIENCE = "benchmark-client";

    private final String[] tokenPool;
    private final Map<String, TokenMetadata> tokenMetadata;
    private final List<IssuerConfig> issuerConfigs;
    private final InMemoryKeyMaterialHandler.IssuerKeyMaterial[] issuers;
    private final Random random;
    private final Config config;

    /**
     * Metadata for a generated token
     */
    @Value
    @Builder
    public static class TokenMetadata {
        String issuerIdentifier;
        int tokenSize;
        String keyId;
    }

    /**
     * Configuration for MockTokenRepository
     */
    @Value
    @Builder
    public static class Config {
        @Builder.Default
        int issuerCount = DEFAULT_ISSUER_COUNT;

        @Builder.Default
        int tokenPoolSize = DEFAULT_TOKEN_POOL_SIZE;

        @Builder.Default
        String expectedAudience = DEFAULT_AUDIENCE;

        @Builder.Default
        long randomSeed = 42L; // Fixed seed for reproducibility

        @Builder.Default
        int cacheSize = 100;
    }

    /**
     * Creates a new MockTokenRepository with the specified configuration
     */
    @SuppressWarnings("java:S2245") // ok for test-code
    public MockTokenRepository(Config config) {
        this.config = config;
        this.random = new Random(config.randomSeed);
        this.tokenMetadata = new HashMap<>();

        // Use pre-generated keys from cache to avoid RSA generation during benchmarks
        this.issuers = BenchmarkKeyCache.getPreGeneratedIssuers(config.issuerCount);

        List<IssuerConfig> configs = new ArrayList<>();
        List<String> allTokens = new ArrayList<>();

        // Create issuer configs and generate tokens for each issuer
        for (InMemoryKeyMaterialHandler.IssuerKeyMaterial issuer : issuers) {
            // Create issuer config with the issuer's JWKS
            IssuerConfig issuerConfig = IssuerConfig.builder()
                    .issuerIdentifier(issuer.getIssuerIdentifier())
                    .jwksContent(issuer.getJwks())
                    .expectedAudience(config.expectedAudience)
                    .expectedClientId(config.expectedAudience) // azp claim validation
                    .build();

            configs.add(issuerConfig);

            // Generate tokens for this issuer
            int tokensPerIssuer = config.tokenPoolSize / config.issuerCount;
            for (int j = 0; j < tokensPerIssuer; j++) {
                String token = generateTokenForIssuer(issuer, config.expectedAudience);
                allTokens.add(token);

                // Store metadata
                tokenMetadata.put(token, TokenMetadata.builder()
                        .issuerIdentifier(issuer.getIssuerIdentifier())
                        .tokenSize(token.length())
                        .keyId(issuer.getKeyId())
                        .build());
            }
        }

        this.issuerConfigs = Collections.unmodifiableList(configs);

        // Convert token list to array and shuffle
        this.tokenPool = allTokens.toArray(new String[0]);
        shuffleArray(this.tokenPool);
    }

    /**
     * Creates a pre-configured TokenValidator with the specified monitor configuration.
     * Uses this repository's configuration for the cache size.
     *
     * @param monitorConfig The monitor configuration to use
     * @return A new TokenValidator instance
     */
    public TokenValidator createTokenValidator(TokenValidatorMonitorConfig monitorConfig) {
        return TokenValidator.builder()
                .issuerConfigs(issuerConfigs)
                .monitorConfig(monitorConfig)
                .cacheConfig(AccessTokenCacheConfig.builder().maxSize(config.cacheSize).build())
                .build();
    }

    /**
     * Gets a token from the pool at the specified index
     *
     * @param index The index in the token pool
     * @return The token at the specified index
     */
    public String getToken(int index) {
        return tokenPool[index % tokenPool.length];
    }

    /**
     * Gets the primary validation token (first in the pool)
     *
     * @return The primary token for validation
     */
    public String getPrimaryToken() {
        return tokenPool[0];
    }

    /**
     * Gets the issuer identifier for a specific token
     *
     * @param token The token to get the issuer for
     * @return The issuer identifier, or empty if not found
     */
    public Optional<String> getTokenIssuer(String token) {
        TokenMetadata metadata = tokenMetadata.get(token);
        return metadata != null ? Optional.of(metadata.getIssuerIdentifier()) : Optional.empty();
    }

    /**
     * Generates a valid JWT token for the given issuer
     */
    private String generateTokenForIssuer(InMemoryKeyMaterialHandler.IssuerKeyMaterial issuer, String audience) {
        Instant now = Instant.now();

        return Jwts.builder()
                .header()
                .keyId(issuer.getKeyId())
                .and()
                .issuer(issuer.getIssuerIdentifier())
                .subject("benchmark-user-" + UUID.randomUUID())
                .audience().add(audience).and()
                .expiration(Date.from(now.plusSeconds(3600)))
                .notBefore(Date.from(now.minusSeconds(60)))
                .issuedAt(Date.from(now))
                .id(UUID.randomUUID().toString())
                .claim("typ", "Bearer")
                .claim("azp", audience)
                .claim("scope", "openid profile email")
                .claim("email_verified", true)
                .claim("name", "Benchmark User")
                .claim("preferred_username", "benchmark")
                .claim("given_name", "Benchmark")
                .claim("family_name", "User")
                .claim("email", "benchmark@example.com")
                // Add some variable-size claims to create different token sizes
                .claim("custom_data", generateRandomData())
                .signWith(issuer.getPrivateKey())
                .compact();
    }

    /**
     * Generates random data for token size variation
     */
    private String generateRandomData() {
        int size = 50 + random.nextInt(200); // 50-250 characters
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }

    /**
     * Shuffles the array using Fisher-Yates algorithm
     */
    private void shuffleArray(String[] array) {
        for (int i = array.length - 1; i > 0; i--) {
            int index = random.nextInt(i + 1);
            String temp = array[index];
            array[index] = array[i];
            array[i] = temp;
        }
    }
}

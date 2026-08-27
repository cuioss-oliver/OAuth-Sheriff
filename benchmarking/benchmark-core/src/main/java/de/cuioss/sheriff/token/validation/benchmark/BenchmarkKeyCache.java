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

import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler.IssuerKeyMaterial;
import de.cuioss.tools.logging.CuiLogger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO;

/**
 * Pre-generates and caches RSA key pairs for benchmarking to avoid key generation
 * during benchmark measurements.
 * <p>
 * This class ensures that expensive RSA key generation happens during class loading,
 * not during benchmark execution, preventing p99 latency spikes caused by setup costs.
 * 
 * @author Oliver Wolff
 */
public final class BenchmarkKeyCache {

    private static final CuiLogger LOGGER = new CuiLogger(BenchmarkKeyCache.class);

    /**
     * Cache of pre-generated issuer key materials by count
     */
    private static final Map<Integer, IssuerKeyMaterial[]> ISSUER_CACHE = new ConcurrentHashMap<>();

    /**
     * The issuer count that is eagerly warmed up at class load — the default used by
     * all benchmarks. Other counts are generated lazily on first request.
     */
    private static final int WARMED_UP_ISSUER_COUNT = 3;

    static {
        // Warm up only the count actually used by the benchmarks; generating key
        // material for unused counts wasted ~95% of the startup RSA generation.
        long startTime = System.currentTimeMillis();
        LOGGER.info(INFO.KEY_PREGENERATION_STARTING);

        ISSUER_CACHE.put(WARMED_UP_ISSUER_COUNT,
                InMemoryKeyMaterialHandler.createMultipleIssuers(WARMED_UP_ISSUER_COUNT));

        long duration = System.currentTimeMillis() - startTime;
        LOGGER.info(INFO.KEY_PREGENERATION_COMPLETED, WARMED_UP_ISSUER_COUNT, duration);
    }

    /**
     * Private constructor to prevent instantiation
     */
    private BenchmarkKeyCache() {
        throw new AssertionError("Utility class - do not instantiate");
    }

    /**
     * Gets pre-generated issuer key materials for the specified count.
     * If the count exceeds the pre-generated cache, generates new keys (with a warning).
     * 
     * @param count The number of issuers needed
     * @return Array of pre-generated IssuerKeyMaterial instances
     */
    public static IssuerKeyMaterial[] getPreGeneratedIssuers(int count) {
        if (count <= 0) {
            throw new IllegalArgumentException("Issuer count must be positive");
        }

        // Lazily generate and cache per requested count; arrays are immutable, no cloning needed
        return ISSUER_CACHE.computeIfAbsent(count, InMemoryKeyMaterialHandler::createMultipleIssuers);
    }


    /**
     * Forces initialization of the key cache.
     * This method can be called explicitly to ensure keys are generated
     * before any benchmarks start.
     */
    public static void initialize() {
        // The static initializer will run when this method is called
        LOGGER.info(INFO.KEY_CACHE_INITIALIZED, ISSUER_CACHE.size());
    }
}
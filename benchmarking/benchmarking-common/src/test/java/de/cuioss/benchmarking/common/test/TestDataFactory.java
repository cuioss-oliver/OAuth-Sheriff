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
package de.cuioss.benchmarking.common.test;

import com.google.gson.*;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Factory class for creating test data objects used across benchmark tests.
 * This class provides centralized test data creation to reduce duplication
 * and improve test maintainability.
 */
public final class TestDataFactory {

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    private TestDataFactory() {
        // utility class
    }

    /**
     * Creates a test JWT token string with specified claims.
     *
     * @param subject The subject claim
     * @param issuer The issuer claim
     * @param expirationTime The expiration time in milliseconds
     * @return A JWT token string for testing
     */
    public static String createTestToken(String subject, String issuer, long expirationTime) {
        // This is a dummy JWT for testing - not cryptographically valid
        String header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";

        JsonObject payload = new JsonObject();
        payload.addProperty("sub", subject);
        payload.addProperty("iss", issuer);
        payload.addProperty("exp", expirationTime / 1000);
        payload.addProperty("iat", System.currentTimeMillis() / 1000);
        payload.addProperty("jti", UUID.randomUUID().toString());

        String encodedPayload = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(GSON.toJson(payload).getBytes());

        String signature = "test-signature";

        return header + "." + encodedPayload + "." + signature;
    }

    /**
     * Creates a test metrics map with specified values.
     *
     * @param endpointName The name of the endpoint
     * @param sampleCount The number of samples
     * @param p50 The 50th percentile value
     * @param p95 The 95th percentile value
     * @param p99 The 99th percentile value
     * @return A map containing test metrics
     */
    public static Map<String, Object> createTestMetrics(String endpointName, int sampleCount,
            double p50, double p95, double p99) {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("name", endpointName);
        metrics.put("sample_count", sampleCount);
        metrics.put("timestamp", Instant.now().toString());
        metrics.put("source", "JMH benchmark - sample mode");

        Map<String, Object> percentiles = new HashMap<>();
        percentiles.put("p50_us", p50);
        percentiles.put("p95_us", p95);
        percentiles.put("p99_us", p99);
        metrics.put("percentiles", percentiles);

        Map<String, Object> statistics = new HashMap<>();
        statistics.put("mean_us", (p50 + p95 + p99) / 3.0);
        statistics.put("min_us", p50 * 0.8);
        statistics.put("max_us", p99 * 1.2);
        metrics.put("statistics", statistics);

        return metrics;
    }

    /**
     * Creates a test benchmark result JSON string.
     *
     * @return A JSON string representing benchmark results
     */
    public static String createTestBenchmarkResult() {
        return createTestBenchmarkResult("de.cuioss.jwt.benchmark.Test", "testMethod", "Sample", 1000);
    }

    /**
     * Creates a test benchmark result JSON string with specified parameters.
     *
     * @param benchmarkClass The fully qualified benchmark class name
     * @param methodName The benchmark method name
     * @param mode The benchmark mode (e.g., "Sample", "Throughput")
     * @param sampleCount The number of samples
     * @return A JSON string representing benchmark results
     */
    public static String createTestBenchmarkResult(String benchmarkClass, String methodName,
            String mode, int sampleCount) {
        JsonArray results = new JsonArray();
        JsonObject result = new JsonObject();

        result.addProperty("jmhVersion", "1.37");
        result.addProperty("benchmark", benchmarkClass + "." + methodName);
        result.addProperty("mode", mode);

        JsonObject params = new JsonObject();
        params.addProperty("iterations", "2");
        params.addProperty("warmupIterations", "1");
        result.add("params", params);

        JsonObject primaryMetric = new JsonObject();
        primaryMetric.addProperty("score", 100.0);
        primaryMetric.addProperty("scoreError", 5.0);
        primaryMetric.addProperty("scoreUnit", "us/op");

        JsonObject percentiles = new JsonObject();
        percentiles.addProperty("50.0", 50.0);
        percentiles.addProperty("95.0", 95.0);
        percentiles.addProperty("99.0", 99.0);
        percentiles.addProperty("99.9", 99.9);
        percentiles.addProperty("99.99", 99.99);
        percentiles.addProperty("99.999", 99.999);
        percentiles.addProperty("99.9999", 99.9999);
        percentiles.addProperty("100.0", 100.0);
        primaryMetric.add("scorePercentiles", percentiles);

        JsonArray rawData = new JsonArray();
        JsonArray iteration1 = new JsonArray();
        for (int i = 0; i < sampleCount / 2; i++) {
            iteration1.add(new JsonPrimitive(50.0 + ThreadLocalRandom.current().nextDouble() * 50));
        }
        rawData.add(iteration1);

        JsonArray iteration2 = new JsonArray();
        for (int i = 0; i < sampleCount / 2; i++) {
            iteration2.add(new JsonPrimitive(50.0 + ThreadLocalRandom.current().nextDouble() * 50));
        }
        rawData.add(iteration2);

        primaryMetric.add("rawData", rawData);
        result.add("primaryMetric", primaryMetric);

        results.add(result);

        return GSON.toJson(results);
    }

    /**
     * Creates test HTTP metrics JSON string.
     *
     * @return A JSON string containing HTTP metrics
     */
    public static String createTestHttpMetrics() {
        Map<String, Object> httpMetrics = new HashMap<>();
        httpMetrics.put("jwt_validation", createTestMetrics("JWT Validation", 1000, 45.0, 85.0, 95.0));
        httpMetrics.put("health", createTestMetrics("Health Check", 500, 10.0, 20.0, 30.0));
        return GSON.toJson(httpMetrics);
    }

    /**
     * Creates test integration metrics JSON string.
     *
     * @return A JSON string containing integration metrics
     */
    public static String createTestIntegrationMetrics() {
        Map<String, Object> integrationMetrics = new HashMap<>();

        Map<String, Object> throughput = new HashMap<>();
        throughput.put("ops_per_second", 10000.0);
        throughput.put("mean_time_us", 100.0);
        integrationMetrics.put("throughput", throughput);

        Map<String, Object> latency = new HashMap<>();
        latency.put("p50_us", 50.0);
        latency.put("p95_us", 95.0);
        latency.put("p99_us", 99.0);
        integrationMetrics.put("latency", latency);

        integrationMetrics.put("timestamp", Instant.now().toString());
        integrationMetrics.put("benchmark_type", "integration");

        return GSON.toJson(integrationMetrics);
    }

    /**
     * Creates a test JMH RunResult JSON string for library benchmarks.
     *
     * @return A JSON string representing JMH library benchmark results
     */
    public static String createTestLibraryBenchmarkResult() {
        JsonArray results = new JsonArray();

        // Add throughput benchmark
        results.add(createBenchmarkObject(
                "SimpleCoreValidationBenchmark.measureThroughput",
                "Throughput",
                25000.0,
                "ops/s"
        ));

        // Add latency benchmark  
        results.add(createBenchmarkObject(
                "SimpleCoreValidationBenchmark.measureAverageTime",
                "AverageTime",
                40.0,
                "us/op"
        ));

        return GSON.toJson(results);
    }

    private static JsonObject createBenchmarkObject(String benchmark, String mode, double score, String unit) {
        JsonObject result = new JsonObject();
        result.addProperty("jmhVersion", "1.37");
        result.addProperty("benchmark", "de.cuioss.sheriff.token.validation.benchmark." + benchmark);
        result.addProperty("mode", mode);

        JsonObject primaryMetric = new JsonObject();
        primaryMetric.addProperty("score", score);
        primaryMetric.addProperty("scoreError", score * 0.05); // 5% error margin
        primaryMetric.addProperty("scoreUnit", unit);

        result.add("primaryMetric", primaryMetric);
        return result;
    }
}
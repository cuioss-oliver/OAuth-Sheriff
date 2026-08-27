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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Utility class for loading test resources from the classpath or filesystem.
 * Provides centralized resource loading functionality for benchmark tests.
 */
public final class TestResourceLoader {

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    private TestResourceLoader() {
        // utility class
    }

    /**
     * Loads a JSON resource from the classpath and deserializes it.
     *
     * @param resourcePath The path to the resource (e.g., "/test-data/metrics.json")
     * @param clazz The class type to deserialize to
     * @param <T> The type parameter
     * @return The deserialized object
     * @throws IOException If the resource cannot be loaded
     */
    public static <T> T loadJsonResource(String resourcePath, Class<T> clazz) throws IOException {
        try (InputStream stream = TestResourceLoader.class.getResourceAsStream(resourcePath)) {
            if (stream == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            try (Reader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return GSON.fromJson(reader, clazz);
            }
        }
    }

    /**
     * Loads a JSON resource from the classpath and deserializes it using a Type token.
     *
     * @param resourcePath The path to the resource
     * @param type The type token for complex types (e.g., Map, List)
     * @param <T> The type parameter
     * @return The deserialized object
     * @throws IOException If the resource cannot be loaded
     */
    @SuppressWarnings("unchecked")
    public static <T> T loadJsonResource(String resourcePath, Type type) throws IOException {
        try (InputStream stream = TestResourceLoader.class.getResourceAsStream(resourcePath)) {
            if (stream == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            try (Reader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return (T) GSON.fromJson(reader, type);
            }
        }
    }

    /**
     * Loads a text resource from the classpath as a String.
     *
     * @param resourcePath The path to the resource
     * @return The resource content as a String
     * @throws IOException If the resource cannot be loaded
     */
    public static String loadTextResource(String resourcePath) throws IOException {
        try (InputStream stream = TestResourceLoader.class.getResourceAsStream(resourcePath)) {
            if (stream == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Writes test data to a temporary file for testing.
     *
     * @param tempDir The temporary directory to write to
     * @param fileName The name of the file to create
     * @param content The content to write
     * @return The path to the created file
     * @throws IOException If the file cannot be written
     */
    public static Path writeTestFile(Path tempDir, String fileName, String content) throws IOException {
        Path filePath = tempDir.resolve(fileName);
        Files.writeString(filePath, content);
        return filePath;
    }

    /**
     * Writes test JSON data to a temporary file.
     *
     * @param tempDir The temporary directory to write to
     * @param fileName The name of the file to create
     * @param data The data object to serialize to JSON
     * @return The path to the created file
     * @throws IOException If the file cannot be written
     */
    public static Path writeTestJsonFile(Path tempDir, String fileName, Object data) throws IOException {
        Path filePath = tempDir.resolve(fileName);
        try (FileWriter writer = new FileWriter(filePath.toFile(), StandardCharsets.UTF_8)) {
            GSON.toJson(data, writer);
        }
        return filePath;
    }

    /**
     * Copies a resource from the classpath to a file.
     *
     * @param resourcePath The path to the resource in the classpath
     * @param targetFile The target file to copy to
     * @throws IOException If the resource cannot be copied
     */
    public static void copyResourceToFile(String resourcePath, File targetFile) throws IOException {
        try (InputStream stream = TestResourceLoader.class.getResourceAsStream(resourcePath)) {
            if (stream == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }
            Files.copy(stream, targetFile.toPath());
        }
    }

    /**
     * Creates a temporary directory with test benchmark files.
     *
     * @param tempDir The base temporary directory
     * @return The path to the created directory containing test files
     * @throws IOException If files cannot be created
     */
    public static Path setupTestBenchmarkDirectory(Path tempDir) throws IOException {
        Path benchmarkDir = tempDir.resolve("benchmark-results");
        Files.createDirectories(benchmarkDir);

        // Create standard test files
        writeTestJsonFile(benchmarkDir, "micro-result.json",
                TestDataFactory.createTestLibraryBenchmarkResult());
        writeTestJsonFile(benchmarkDir, "integration-benchmark-result.json",
                TestDataFactory.createTestBenchmarkResult());
        writeTestJsonFile(benchmarkDir, "http-metrics.json",
                TestDataFactory.createTestHttpMetrics());
        writeTestJsonFile(benchmarkDir, "integration-metrics.json",
                TestDataFactory.createTestIntegrationMetrics());

        return benchmarkDir;
    }

    /**
     * Loads the standard library benchmark result from resources.
     *
     * @return The loaded benchmark result as a Map
     * @throws IOException If the resource cannot be loaded
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadLibraryBenchmarkResult() throws IOException {
        return loadJsonResource("/library-benchmark-results/micro-result.json", Map.class);
    }

    /**
     * Loads the standard integration benchmark result from resources.
     *
     * @return The loaded benchmark result as a Map
     * @throws IOException If the resource cannot be loaded
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadIntegrationBenchmarkResult() throws IOException {
        return loadJsonResource("/integration-benchmark-results/integration-result.json", Map.class);
    }

    /**
     * Loads the standard HTTP metrics from resources.
     *
     * @return The loaded metrics as a Map
     * @throws IOException If the resource cannot be loaded
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadHttpMetrics() throws IOException {
        return loadJsonResource("/integration-benchmark-results/http-metrics.json", Map.class);
    }

    /**
     * Loads the standard integration metrics from resources.
     *
     * @return The loaded metrics as a Map
     * @throws IOException If the resource cannot be loaded
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadIntegrationMetrics() throws IOException {
        return loadJsonResource("/integration-benchmark-results/integration-metrics.json", Map.class);
    }
}
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
package de.cuioss.benchmarking.common;

import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.runner.BenchmarkResultProcessor;
import de.cuioss.benchmarking.common.test.TestResourceLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openjdk.jmh.results.RunResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link BenchmarkResultProcessor} using JUnit Jupiter API.
 * <p>
 * Tests comprehensive artifact generation pipeline including badges, reports,
 * metrics, and GitHub Pages structure creation.
 */
class BenchmarkResultProcessorTest {

    @Test
    void completeArtifactGeneration(@TempDir Path tempDir) throws Exception {
        // Use TestResourceLoader to copy test JSON file to expected location
        Path targetJson = tempDir.resolve("micro-result.json");
        TestResourceLoader.copyResourceToFile("/library-benchmark-results/micro-result.json", targetJson.toFile());

        // Use empty results - the processor will read from JSON file
        Collection<RunResult> results = List.of();

        // Process results - use actual benchmark names from the test data
        BenchmarkResultProcessor processor = new BenchmarkResultProcessor(
                BenchmarkType.MICRO
        // This is in SimpleCoreValidationBenchmark.measureThroughput
        );  // This is in SimpleCoreValidationBenchmark.measureAverageTime
        String outputDir = tempDir.toString();
        processor.processResults(results, outputDir);

        // Verify all artifacts were created in gh-pages-ready structure
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready/badges/performance-badge.json")),
                "Performance badge should be generated");
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready/badges/trend-badge.json")),
                "Trend badge should be generated");
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready/badges/last-run-badge.json")),
                "Last run badge should be generated");
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready/data/original-jmh-result.json")),
                "Original JMH result file should be copied to data directory");
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready/index.html")),
                "Index HTML report should be generated");
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready/trends.html")),
                "Trends HTML report should be generated");
        assertTrue(Files.isDirectory(Path.of(outputDir, "gh-pages-ready")),
                "GitHub Pages directory should be created");

        // Verify badge content structure
        String badgeContent = Files.readString(Path.of(outputDir, "gh-pages-ready/badges/performance-badge.json"));
        assertNotNull(badgeContent, "Badge content should not be null");
        assertFalse(badgeContent.isEmpty(), "Badge content should not be empty");
        assertTrue(badgeContent.contains("\"schemaVersion\""), "Badge should have schema version");
        assertTrue(badgeContent.contains("\"label\""), "Badge should have label");
        assertTrue(badgeContent.contains("\"message\""), "Badge should have message");
        assertTrue(badgeContent.contains("\"color\""), "Badge should have color");
    }

    @Test
    void emptyResultsHandling(@TempDir Path tempDir) {
        BenchmarkResultProcessor processor = new BenchmarkResultProcessor(
                BenchmarkType.MICRO
        );
        List<RunResult> emptyResults = List.of();

        String outputDir = tempDir.toString();

        // Should FAIL FAST when JSON file doesn't exist
        assertThrows(IllegalStateException.class,
                () -> processor.processResults(emptyResults, outputDir),
                "Processing should fail when JSON file doesn't exist");
    }

    @Test
    void directoryCreation(@TempDir Path tempDir) throws Exception {
        // Copy test JSON file to expected location
        Path nestedDir = tempDir.resolve("nested/benchmark/results");
        Files.createDirectories(nestedDir);
        Path sourceJson = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        Path targetJson = nestedDir.resolve("micro-result.json");
        Files.copy(sourceJson, targetJson);

        BenchmarkResultProcessor processor = new BenchmarkResultProcessor(
                BenchmarkType.MICRO
        // This is in SimpleCoreValidationBenchmark.measureThroughput
        );  // This is in SimpleCoreValidationBenchmark.measureAverageTime
        String outputDir = nestedDir.toString();

        // Use empty results - processor will read from JSON
        processor.processResults(List.of(), outputDir);

        // Verify nested directories are created in gh-pages-ready
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready/badges")),
                "Nested badges directory should be created");
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready/data")),
                "Nested data directory should be created");
        assertTrue(Files.exists(Path.of(outputDir, "gh-pages-ready")),
                "Nested GitHub Pages directory should be created");
    }
}
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

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.converter.JmhBenchmarkConverter;
import de.cuioss.benchmarking.common.model.BenchmarkData;
import de.cuioss.benchmarking.common.report.ReportGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ReportGenerator}.
 */
class ReportGeneratorTest {

    private static final Gson gson = new Gson();

    @Test
    void generateDataJsonWithResults(@TempDir Path tempDir) throws Exception {
        // Use real micro benchmark test data
        Path sourceJson = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        Path jsonFile = tempDir.resolve("micro-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        generator.generateIndexPage(benchmarkData, BenchmarkType.MICRO, outputDir);

        // Verify data file was created with expected structure
        Path dataFile = tempDir.resolve("data/benchmark-data.json");
        assertTrue(Files.exists(dataFile), "Data JSON file should be created");

        String content = Files.readString(dataFile);
        assertFalse(content.isEmpty(), "Data JSON should not be empty");

        // Parse the JSON and verify structure
        JsonObject dataJson = gson.fromJson(content, JsonObject.class);

        // Check metadata
        assertTrue(dataJson.has("metadata"), "Should have metadata");
        JsonObject metadata = dataJson.getAsJsonObject("metadata");
        assertEquals("Micro Performance", metadata.get("benchmarkType").getAsString());

        // Check overview
        assertTrue(dataJson.has("overview"), "Should have overview");
        JsonObject overview = dataJson.getAsJsonObject("overview");
        assertTrue(overview.has("throughput"));
        assertTrue(overview.has("latency"));
        assertTrue(overview.has("performanceScore"));
        assertTrue(overview.has("performanceGrade"));

        // Check benchmarks
        assertTrue(dataJson.has("benchmarks"), "Should have benchmarks");
        JsonArray benchmarkArray = dataJson.getAsJsonArray("benchmarks");
        assertFalse(benchmarkArray.isEmpty(), "Should have benchmark results");
    }

    @Test
    void generateIndexPage(@TempDir Path tempDir) throws Exception {
        Path sourceJson = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        Path jsonFile = tempDir.resolve("micro-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        generator.generateIndexPage(benchmarkData, BenchmarkType.MICRO, outputDir);

        Path indexFile = tempDir.resolve("index.html");
        assertTrue(Files.exists(indexFile), "Index HTML file should be created");

        String htmlContent = Files.readString(indexFile);
        assertTrue(htmlContent.contains("<!DOCTYPE html>"));
        assertTrue(htmlContent.contains("Benchmarking Dashboard"));

        // Verify data loader script is included
        assertTrue(htmlContent.contains("data-loader.js"));
    }

    @Test
    void generateIndexPageIntegrationBenchmark(@TempDir Path tempDir) throws Exception {
        Path sourceJson = Path.of("src/test/resources/integration-benchmark-results/integration-result.json");
        Path jsonFile = tempDir.resolve("integration-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.INTEGRATION);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        // Generate index page for integration benchmark
        generator.generateIndexPage(benchmarkData, BenchmarkType.INTEGRATION, outputDir);

        // Verify data file was created
        Path dataFile = tempDir.resolve("data/benchmark-data.json");
        assertTrue(Files.exists(dataFile));

        // Verify metadata shows correct benchmark type
        String content = Files.readString(dataFile);
        JsonObject dataJson = gson.fromJson(content, JsonObject.class);
        JsonObject metadata = dataJson.getAsJsonObject("metadata");
        assertEquals("Integration Performance", metadata.get("benchmarkType").getAsString());
    }

    @Test
    void generateTrendsPage(@TempDir Path tempDir) throws Exception {
        Path sourceJson = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        Path jsonFile = tempDir.resolve("micro-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        generator.generateIndexPage(benchmarkData, BenchmarkType.MICRO, outputDir);
        generator.generateTrendsPage(outputDir);

        Path trendsFile = tempDir.resolve("trends.html");
        assertTrue(Files.exists(trendsFile), "Trends HTML file should be created");

        String htmlContent = Files.readString(trendsFile);
        assertTrue(htmlContent.contains("<!DOCTYPE html>"));
        assertTrue(htmlContent.contains("Benchmarking Dashboard"));
    }

    @Test
    void generateDetailedPage(@TempDir Path tempDir) throws Exception {
        Path sourceJson = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        Path jsonFile = tempDir.resolve("micro-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        generator.generateIndexPage(benchmarkData, BenchmarkType.MICRO, outputDir);
        generator.generateDetailedPage(outputDir);

        Path detailedFile = tempDir.resolve("detailed.html");
        assertTrue(Files.exists(detailedFile), "Detailed HTML file should be created");

        String htmlContent = Files.readString(detailedFile);
        assertTrue(htmlContent.contains("<!DOCTYPE html>"));
        assertTrue(htmlContent.contains("Interactive JMH Visualizer"));
    }

    @Test
    void copySupportFiles(@TempDir Path tempDir) throws Exception {
        Path sourceJson = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        Path jsonFile = tempDir.resolve("micro-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        generator.generateIndexPage(benchmarkData, BenchmarkType.MICRO, outputDir);
        generator.copySupportFiles(outputDir);

        // Check CSS file
        Path cssFile = tempDir.resolve("report-styles.css");
        assertTrue(Files.exists(cssFile), "CSS file should be copied");

        // Check data loader script
        Path jsFile = tempDir.resolve("data-loader.js");
        assertTrue(Files.exists(jsFile), "JavaScript file should be copied");

        // robots.txt and sitemap.xml are deployment assets generated exactly once
        // by GitHubPagesGenerator — copySupportFiles must NOT write them anymore
        assertFalse(Files.exists(tempDir.resolve("robots.txt")),
                "robots.txt is written by GitHubPagesGenerator only");
        assertFalse(Files.exists(tempDir.resolve("sitemap.xml")),
                "sitemap.xml is written by GitHubPagesGenerator only");
    }

    @Test
    void verifyChartDataStructure(@TempDir Path tempDir) throws Exception {
        Path sourceJson = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        Path jsonFile = tempDir.resolve("micro-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        generator.generateIndexPage(benchmarkData, BenchmarkType.MICRO, outputDir);

        Path dataFile = tempDir.resolve("data/benchmark-data.json");
        String content = Files.readString(dataFile);
        JsonObject dataJson = gson.fromJson(content, JsonObject.class);

        // Verify chartData structure
        assertTrue(dataJson.has("chartData"), "Should have chartData for JavaScript consumption");
        JsonObject chartData = dataJson.getAsJsonObject("chartData");
        assertTrue(chartData.has("labels"), "Chart data should have labels");
        assertTrue(chartData.has("throughput"), "Chart data should have throughput data");
        assertTrue(chartData.has("latency"), "Chart data should have latency data");

        // Verify percentiles data structure
        assertTrue(chartData.has("percentilesData"), "Should have percentiles data");
        JsonObject percentilesData = chartData.getAsJsonObject("percentilesData");
        assertTrue(percentilesData.has("percentileLabels"), "Should have percentile labels");
    }
}
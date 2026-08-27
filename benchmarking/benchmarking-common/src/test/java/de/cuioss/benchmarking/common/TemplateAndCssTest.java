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

import com.google.gson.JsonParser;
import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.converter.JmhBenchmarkConverter;
import de.cuioss.benchmarking.common.model.BenchmarkData;
import de.cuioss.benchmarking.common.report.ReportGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for template and CSS resource availability.
 * Note: We don't test HTML/CSS content as templates are static files that are simply copied.
 * The actual logic to test is the JSON data generation, not the static HTML structure.
 */
class TemplateAndCssTest {

    @Test
    void templateResourcesExist() {
        // Verify that required template resources are available in classpath
        assertDoesNotThrow(() -> {
            try (InputStream is = getClass().getResourceAsStream("/templates/index.html")) {
                assertNotNull(is, "index.html template should exist in resources");
            }
        });

        assertDoesNotThrow(() -> {
            try (InputStream is = getClass().getResourceAsStream("/templates/trends.html")) {
                assertNotNull(is, "trends.html template should exist in resources");
            }
        });

        assertDoesNotThrow(() -> {
            try (InputStream is = getClass().getResourceAsStream("/templates/detailed.html")) {
                assertNotNull(is, "detailed.html template should exist in resources");
            }
        });
    }

    @Test
    void supportingFilesExist() {
        // Verify that supporting files are available in classpath
        assertDoesNotThrow(() -> {
            try (InputStream is = getClass().getResourceAsStream("/templates/report-styles.css")) {
                assertNotNull(is, "CSS file should exist in resources");
            }
        });

        assertDoesNotThrow(() -> {
            try (InputStream is = getClass().getResourceAsStream("/templates/data-loader.js")) {
                assertNotNull(is, "JavaScript file should exist in resources");
            }
        });
    }

    @Test
    void templatesCopiedToOutput(@TempDir Path tempDir) throws Exception {
        // Test that template files are properly copied to output directory
        Path sourceJson = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        Path jsonFile = tempDir.resolve("micro-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        generator.generateIndexPage(benchmarkData, BenchmarkType.MICRO, outputDir);
        generator.generateTrendsPage(outputDir);
        generator.generateDetailedPage(outputDir);
        generator.copySupportFiles(outputDir);

        // Verify files were copied
        assertTrue(Files.exists(Path.of(outputDir, "index.html")), "Index template should be copied");
        assertTrue(Files.exists(Path.of(outputDir, "trends.html")), "Trends template should be copied");
        assertTrue(Files.exists(Path.of(outputDir, "detailed.html")), "Detailed template should be copied");
        assertTrue(Files.exists(Path.of(outputDir, "report-styles.css")), "CSS should be copied");
        assertTrue(Files.exists(Path.of(outputDir, "data-loader.js")), "JavaScript should be copied");
    }

    @Test
    void dataJsonIsGeneratedNotTemplates(@TempDir Path tempDir) throws Exception {
        // Verify that the actual output is JSON data, not modified templates
        Path sourceJson = Path.of("src/test/resources/integration-benchmark-results/integration-result.json");
        Path jsonFile = tempDir.resolve("integration-result.json");
        Files.copy(sourceJson, jsonFile);

        JmhBenchmarkConverter converter = new JmhBenchmarkConverter(BenchmarkType.INTEGRATION);
        BenchmarkData benchmarkData = converter.convert(jsonFile);

        ReportGenerator generator = new ReportGenerator();
        String outputDir = tempDir.toString();

        generator.generateIndexPage(benchmarkData, BenchmarkType.INTEGRATION, outputDir);

        // The important output is the JSON data file
        Path dataFile = Path.of(outputDir, "data", "benchmark-data.json");
        assertTrue(Files.exists(dataFile), "Data JSON should be generated");

        // Verify it's valid JSON
        String jsonContent = Files.readString(dataFile);
        assertDoesNotThrow(() -> {
            JsonParser.parseString(jsonContent);
        }, "Generated data should be valid JSON");

        // Verify HTML templates are copied unchanged (not modified)
        Path indexFile = Path.of(outputDir, "index.html");
        if (Files.exists(indexFile)) {
            String htmlContent = Files.readString(indexFile);
            // Templates should have data-loader.js reference (not embedded data)
            assertTrue(htmlContent.contains("data-loader.js"),
                    "HTML should reference data loader, not contain embedded data");
        }
    }
}
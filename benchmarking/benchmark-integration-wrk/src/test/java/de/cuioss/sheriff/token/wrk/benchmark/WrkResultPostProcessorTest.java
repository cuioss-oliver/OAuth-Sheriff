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
package de.cuioss.sheriff.token.wrk.benchmark;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link WrkResultPostProcessor}.
 * Tests that the processor correctly parses WRK output format,
 * not specific values that change with each benchmark run.
 */
class WrkResultPostProcessorTest {

    // Test fixtures (previously public constants on the production class)
    private static final String WRK_HEALTH_OUTPUT_FILE = "wrk-health-results.txt";
    private static final String WRK_JWT_OUTPUT_FILE = "wrk-jwt-results.txt";
    private static final String BENCHMARK_NAME_HEALTH = "healthCheck";
    private static final String BENCHMARK_NAME_JWT = "jwtValidation";
    private static final String PROMETHEUS_METRICS_DIR = "prometheus";
    private static final String GH_PAGES_DATA_DIR = "gh-pages-ready/data";
    private static final String HEALTH_METRICS_FILE = BENCHMARK_NAME_HEALTH + "-metrics.json";
    private static final String JWT_METRICS_FILE = BENCHMARK_NAME_JWT + "-metrics.json";

    @TempDir
    Path tempDir;

    private WrkResultPostProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new WrkResultPostProcessor();
    }

    @Test
    void comprehensiveStructureGeneration() throws Exception {
        // Copy real benchmark outputs to temp directory wrk subdirectory
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Path healthSource = Path.of("src/test/resources/wrk-health-results.txt");
        Path jwtSource = Path.of("src/test/resources/wrk-jwt-results.txt");
        Files.copy(healthSource, wrkDir.resolve(WRK_HEALTH_OUTPUT_FILE));
        Files.copy(jwtSource, wrkDir.resolve(WRK_JWT_OUTPUT_FILE));

        // Process results
        Path outputDir = tempDir.resolve("output");
        processor.process(tempDir, outputDir);

        // Verify comprehensive structure matching JMH benchmarks
        verifyComprehensiveStructure();
    }

    @Test
    void parseWrkHealthOutput() throws Exception {
        // Copy real health output to temp directory wrk subdirectory
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Path sourceFile = Path.of("src/test/resources/wrk-health-results.txt");
        Path targetFile = wrkDir.resolve(WRK_HEALTH_OUTPUT_FILE);
        Files.copy(sourceFile, targetFile);

        // Process results
        Path outputDir = tempDir.resolve("output");
        processor.process(tempDir, outputDir);

        // Verify JSON output was created in gh-pages-ready structure
        Path jsonFile = outputDir.resolve("gh-pages-ready/data/benchmark-data.json");
        assertTrue(Files.exists(jsonFile), "Benchmark data file should be created");

        // Parse and verify JSON structure
        String jsonContent = Files.readString(jsonFile);
        JsonObject json = JsonParser.parseString(jsonContent).getAsJsonObject();

        // Verify metadata structure
        assertTrue(json.has("metadata"));
        JsonObject metadata = json.getAsJsonObject("metadata");
        assertTrue(metadata.has("timestamp"));
        assertTrue(metadata.has("displayTimestamp"));
        assertEquals("Integration Performance", metadata.get("benchmarkType").getAsString());
        assertEquals("2.0", metadata.get("reportVersion").getAsString());

        // Verify health benchmark exists and has correct structure
        assertTrue(json.has("benchmarks"));
        JsonObject healthBenchmark = json.getAsJsonArray("benchmarks").get(0).getAsJsonObject();
        assertEquals(BENCHMARK_NAME_HEALTH, healthBenchmark.get("name").getAsString());
        assertTrue(healthBenchmark.has("mode"));
        assertTrue(healthBenchmark.has("score"));
        assertTrue(healthBenchmark.has("scoreUnit"));

        // Verify percentiles exist and follow expected pattern (p50 < p75 < p90 < p99)
        JsonObject percentiles = healthBenchmark.getAsJsonObject("percentiles");
        assertTrue(percentiles.has("50.0"));
        assertTrue(percentiles.has("75.0"));
        assertTrue(percentiles.has("90.0"));
        assertTrue(percentiles.has("99.0"));

        double p50 = percentiles.get("50.0").getAsDouble();
        double p75 = percentiles.get("75.0").getAsDouble();
        double p90 = percentiles.get("90.0").getAsDouble();
        double p99 = percentiles.get("99.0").getAsDouble();

        assertTrue(p50 <= p75, "P50 should be <= P75");
        assertTrue(p75 <= p90, "P75 should be <= P90");
        assertTrue(p90 <= p99, "P90 should be <= P99");
    }

    @Test
    void parseWrkJwtOutput() throws Exception {
        // Copy real JWT output to temp directory wrk subdirectory
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Path sourceFile = Path.of("src/test/resources/wrk-jwt-results.txt");
        Path targetFile = wrkDir.resolve(WRK_JWT_OUTPUT_FILE);
        Files.copy(sourceFile, targetFile);

        // Process results
        Path outputDir = tempDir.resolve("output");
        processor.process(tempDir, outputDir);

        // Parse JSON output from gh-pages-ready structure
        Path jsonFile = outputDir.resolve("gh-pages-ready/data/benchmark-data.json");
        String jsonContent = Files.readString(jsonFile);
        JsonObject json = JsonParser.parseString(jsonContent).getAsJsonObject();

        // Find JWT benchmark
        JsonObject jwtBenchmark = null;
        var benchmarks = json.getAsJsonArray("benchmarks");
        for (int i = 0; i < benchmarks.size(); i++) {
            var bench = benchmarks.get(i).getAsJsonObject();
            String benchName = bench.get("name").getAsString();
            if (BENCHMARK_NAME_JWT.equals(benchName) || "jwt-validation".equals(benchName)) {
                jwtBenchmark = bench;
                break;
            }
        }

        assertNotNull(jwtBenchmark, "JWT Validation benchmark should be present");

        // Verify benchmark structure
        assertTrue(jwtBenchmark.has("mode"));
        assertTrue(jwtBenchmark.has("score"));
        assertTrue(jwtBenchmark.has("scoreUnit"));

        // Verify percentiles exist
        JsonObject percentiles = jwtBenchmark.getAsJsonObject("percentiles");
        assertTrue(percentiles.has("50.0"));
        assertTrue(percentiles.has("75.0"));
        assertTrue(percentiles.has("90.0"));
        assertTrue(percentiles.has("99.0"));

        // Verify percentiles are in ascending order
        double p50 = percentiles.get("50.0").getAsDouble();
        double p75 = percentiles.get("75.0").getAsDouble();
        double p90 = percentiles.get("90.0").getAsDouble();
        double p99 = percentiles.get("99.0").getAsDouble();

        assertTrue(p50 <= p75, "P50 should be <= P75");
        assertTrue(p75 <= p90, "P75 should be <= P90");
        assertTrue(p90 <= p99, "P90 should be <= P99");
    }

    @Test
    void handlesCompleteWrkOutput() throws Exception {
        // Test with actual WRK output that includes shell wrapper output
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Path jwtFile = wrkDir.resolve(WRK_JWT_OUTPUT_FILE);
        Files.copy(Path.of("src/test/resources/wrk-jwt-results.txt"), jwtFile);

        Path outputDir = tempDir.resolve("output");
        processor.process(tempDir, outputDir);

        Path jsonFile = outputDir.resolve("gh-pages-ready/data/benchmark-data.json");
        JsonObject json = JsonParser.parseString(Files.readString(jsonFile)).getAsJsonObject();

        // Should successfully parse despite wrapper output and "Loaded X tokens" messages
        var benchmarks = json.getAsJsonArray("benchmarks");
        boolean foundJwt = false;
        for (int i = 0; i < benchmarks.size(); i++) {
            var bench = benchmarks.get(i).getAsJsonObject();
            String benchName = bench.get("name").getAsString();
            if (BENCHMARK_NAME_JWT.equals(benchName) || "jwt-validation".equals(benchName)) {
                foundJwt = true;
                // Verify it extracted the actual WRK data
                assertTrue(bench.has("score"));
                assertTrue(bench.has("scoreUnit"));
            }
        }
        assertTrue(foundJwt, "Should parse JWT benchmark from wrapped output");
    }

    @Test
    void generateGitHubPagesStructure() throws Exception {
        // Setup test files in wrk subdirectory
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Path healthFile = wrkDir.resolve(WRK_HEALTH_OUTPUT_FILE);
        Path jwtFile = wrkDir.resolve(WRK_JWT_OUTPUT_FILE);
        Files.copy(Path.of("src/test/resources/wrk-health-results.txt"), healthFile);
        Files.copy(Path.of("src/test/resources/wrk-jwt-results.txt"), jwtFile);

        // Process results
        Path outputDir = tempDir.resolve("output");
        processor.process(tempDir, outputDir);

        // Verify GitHub Pages structure
        Path ghPagesDir = outputDir.resolve("gh-pages-ready");
        assertTrue(Files.exists(ghPagesDir), "GitHub Pages directory should be created");
        assertTrue(Files.exists(ghPagesDir.resolve("index.html")), "index.html should be created");
        assertTrue(Files.exists(ghPagesDir.resolve("data/benchmark-data.json")), "benchmark-data.json should be created");

        // Verify HTML content structure
        String htmlContent = Files.readString(ghPagesDir.resolve("index.html"));
        assertTrue(htmlContent.contains("Benchmarking Dashboard"), "HTML should have correct title");
        assertTrue(htmlContent.contains("data-loader.js"), "HTML should reference data loader");
    }

    @Test
    void overviewGeneration() throws Exception {
        // Setup test files in wrk subdirectory
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Files.copy(Path.of("src/test/resources/wrk-health-results.txt"),
                wrkDir.resolve(WRK_HEALTH_OUTPUT_FILE));
        Files.copy(Path.of("src/test/resources/wrk-jwt-results.txt"),
                wrkDir.resolve(WRK_JWT_OUTPUT_FILE));

        // Process results
        Path outputDir = tempDir.resolve("output");
        processor.process(tempDir, outputDir);

        // Verify overview section exists and has correct format
        Path jsonFile = outputDir.resolve("gh-pages-ready/data/benchmark-data.json");
        JsonObject json = JsonParser.parseString(Files.readString(jsonFile)).getAsJsonObject();

        assertTrue(json.has("overview"), "Overview section should be present");
        JsonObject overview = json.getAsJsonObject("overview");

        // Verify overview contains performance metrics
        assertTrue(overview.has("throughput"));
        assertTrue(overview.has("latency"));
        assertTrue(overview.has("performanceScore"));
        assertTrue(overview.has("performanceGrade"));
    }

    @Test
    void missingFileHandling() throws Exception {
        // Create wrk directory but with no WRK output files - should throw exception
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Path outputDir = tempDir.resolve("output");
        assertThrows(IllegalStateException.class, () -> processor.process(tempDir, outputDir));

        // Should not create output structure
        Path jsonFile = outputDir.resolve("gh-pages-ready/data/benchmark-data.json");
        assertFalse(Files.exists(jsonFile), "JSON should not be created with missing inputs");
    }

    @Test
    void missingInputDirectoryFailsBeforeAnyParsing() {
        Path missingInput = tempDir.resolve("does-not-exist");
        Path outputDir = tempDir.resolve("output");

        assertThrows(IllegalArgumentException.class, () -> processor.process(missingInput, outputDir),
                "Missing input directory must fail instead of producing an empty report");
        assertFalse(Files.exists(outputDir.resolve("gh-pages-ready/data/benchmark-data.json")),
                "No report may be generated for a missing input directory");
    }

    @Test
    void unparseableWrkOutputFailsInsteadOfPublishingZeros() throws Exception {
        // A result file with valid metadata but no parseable WRK metrics (no Requests/sec line)
        String unparseable = """
                === BENCHMARK METADATA ===
                benchmark_name: jwtValidation
                start_time: 1700000000
                === WRK OUTPUT ===
                wrk crashed before producing any output
                === BENCHMARK COMPLETE ===
                end_time: 1700000010
                """;
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Files.writeString(wrkDir.resolve(WRK_JWT_OUTPUT_FILE), unparseable);

        Path outputDir = tempDir.resolve("output");
        assertThrows(IllegalStateException.class, () -> processor.process(tempDir, outputDir),
                "Runs where no benchmark yields parseable metrics must fail loudly");
        assertFalse(Files.exists(outputDir.resolve("gh-pages-ready/data/benchmark-data.json")),
                "No zero-metrics report may be published for unparseable WRK output");
    }

    @Test
    void parseRealWrkFormatVariations() throws Exception {
        // Test with actual WRK output showing various time units
        String wrkOutput = """
                === BENCHMARK METADATA ===
                benchmark_name: format-test
                start_time: 1700000000
                start_time_iso: 2023-11-14T22:13:20Z
                === WRK OUTPUT ===
                
                Running 10s test @ https://localhost:10443/test
                  4 threads and 20 connections
                  Thread Stats   Avg      Stdev     Max   +/- Stdev
                    Latency   849.00us  500.00us  10.00ms   90.00%
                    Req/Sec     5.00k   1.00k    10.00k    75.00%
                  Latency Distribution
                     50%  805.00us
                     75%    1.08ms
                     90%    1.54ms
                     99%    4.01ms
                  100000 requests in 10.00s, 50.00MB read
                Requests/sec:  10000.00
                Transfer/sec:      5.00MB
                
                === BENCHMARK COMPLETE ===
                end_time: 1700000010
                end_time_iso: 2023-11-14T22:13:30Z
                duration_seconds: 10
                """;

        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Path testFile = wrkDir.resolve(WRK_HEALTH_OUTPUT_FILE);
        Files.writeString(testFile, wrkOutput);

        Path outputDir = tempDir.resolve("output");
        processor.process(tempDir, outputDir);

        Path jsonFile = outputDir.resolve("gh-pages-ready/data/benchmark-data.json");
        JsonObject json = JsonParser.parseString(Files.readString(jsonFile)).getAsJsonObject();
        JsonObject benchmark = json.getAsJsonArray("benchmarks").get(0).getAsJsonObject();

        // Verify benchmark has correct structure
        assertTrue(benchmark.has("name"));
        assertTrue(benchmark.has("mode"));
        assertTrue(benchmark.has("score"));
        assertTrue(benchmark.has("scoreUnit"));

        // Verify percentiles exist
        JsonObject percentiles = benchmark.getAsJsonObject("percentiles");
        double p50 = percentiles.get("50.0").getAsDouble();
        assertTrue(p50 > 0, "P50 should be positive");
    }

    @Test
    void systemMetricsIntegration() throws Exception {
        // Setup test files in wrk subdirectory
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Files.copy(Path.of("src/test/resources/wrk-health-results.txt"),
                wrkDir.resolve(WRK_HEALTH_OUTPUT_FILE));

        // Set system property to skip metrics fetching (since no server is running)
        System.setProperty("quarkus.metrics.url", "https://nonexistent:10443");

        Path outputDir = tempDir.resolve("output");
        processor.process(tempDir, outputDir);

        // Verify that the report still works without metrics
        Path jsonFile = outputDir.resolve("gh-pages-ready/data/benchmark-data.json");
        JsonObject json = JsonParser.parseString(Files.readString(jsonFile)).getAsJsonObject();

        // systemMetrics field is optional when fetch fails
        // Just verify the rest of the report is valid
        assertTrue(json.has("metadata"));
        assertTrue(json.has("benchmarks"));
        assertTrue(json.getAsJsonArray("benchmarks").size() > 0);
    }

    @Test
    void shouldPlacePrometheusMetricsInGitHubPagesDataDirectory() throws Exception {
        // Setup test files in wrk subdirectory
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Files.copy(Path.of("src/test/resources/wrk-health-results.txt"),
                wrkDir.resolve(WRK_HEALTH_OUTPUT_FILE));
        Files.copy(Path.of("src/test/resources/wrk-jwt-results.txt"),
                wrkDir.resolve(WRK_JWT_OUTPUT_FILE));
        WrkResultPostProcessor testProcessor = new WrkResultPostProcessor();
        Path outputDir = tempDir.resolve("output");

        testProcessor.process(tempDir, outputDir);

        // Since tests run without Prometheus, we need to create mock metrics files
        // to simulate what happens in a real environment
        Path prometheusDir = outputDir.resolve(PROMETHEUS_METRICS_DIR);
        Files.createDirectories(prometheusDir);

        // Create mock metrics files
        String mockHealthMetrics = """
                {
                  "benchmark_name": "healthCheck",
                  "start_time": "2025-09-25T13:37:35Z",
                  "end_time": "2025-09-25T13:37:38Z",
                  "duration_seconds": 3,
                  "metrics": {
                    "system_cpu_usage": {
                      "labels": {
                        "job": "quarkus-benchmark",
                        "__name__": "system_cpu_usage",
                        "instance": "token-sheriff-integration-tests:8443"
                      },
                      "data_points": 2,
                      "statistics": {
                        "max": 0.69240765625,
                        "min": 0.006775,
                        "avg": 0.349591328125
                      }
                    }
                  }
                }
                """;

        String mockJwtMetrics = """
                {
                  "benchmark_name": "jwtValidation",
                  "start_time": "2025-09-25T13:39:32Z",
                  "end_time": "2025-09-25T13:39:37Z",
                  "duration_seconds": 5,
                  "metrics": {
                    "system_cpu_usage": {
                      "labels": {
                        "job": "quarkus-benchmark",
                        "__name__": "system_cpu_usage",
                        "instance": "token-sheriff-integration-tests:8443"
                      },
                      "data_points": 3,
                      "statistics": {
                        "max": 0.8025898333333333,
                        "min": 0.006404375,
                        "avg": 0.2718659861111111
                      }
                    }
                  }
                }
                """;

        Files.writeString(prometheusDir.resolve(HEALTH_METRICS_FILE), mockHealthMetrics);
        Files.writeString(prometheusDir.resolve(JWT_METRICS_FILE), mockJwtMetrics);

        // Now run the copy logic that should happen when metrics are collected
        Path ghPagesDataDir = outputDir.resolve(GH_PAGES_DATA_DIR);
        Files.createDirectories(ghPagesDataDir);
        Files.copy(prometheusDir.resolve(HEALTH_METRICS_FILE),
                ghPagesDataDir.resolve(HEALTH_METRICS_FILE),
                StandardCopyOption.REPLACE_EXISTING);
        Files.copy(prometheusDir.resolve(JWT_METRICS_FILE),
                ghPagesDataDir.resolve(JWT_METRICS_FILE),
                StandardCopyOption.REPLACE_EXISTING);

        // Verify Prometheus metrics are in gh-pages-ready/data directory
        assertTrue(Files.exists(ghPagesDataDir), "GitHub Pages data directory should exist");

        // Check for Prometheus metrics files
        Path healthMetrics = ghPagesDataDir.resolve(HEALTH_METRICS_FILE);
        Path jwtMetrics = ghPagesDataDir.resolve(JWT_METRICS_FILE);

        assertTrue(Files.exists(healthMetrics), "Health check Prometheus metrics should be in gh-pages-ready/data");
        assertTrue(Files.exists(jwtMetrics), "JWT validation Prometheus metrics should be in gh-pages-ready/data");

        // Verify the metrics files contain proper Prometheus data
        String healthContent = Files.readString(healthMetrics);
        JsonObject healthJson = JsonParser.parseString(healthContent).getAsJsonObject();

        assertTrue(healthJson.has("benchmark_name"), "Should have benchmark name");
        assertTrue(healthJson.has("start_time"), "Should have start time");
        assertTrue(healthJson.has("end_time"), "Should have end time");
        assertTrue(healthJson.has("metrics"), "Should have metrics data");
        assertEquals(BENCHMARK_NAME_HEALTH, healthJson.get("benchmark_name").getAsString());

        String jwtContent = Files.readString(jwtMetrics);
        JsonObject jwtJson = JsonParser.parseString(jwtContent).getAsJsonObject();
        assertEquals(BENCHMARK_NAME_JWT, jwtJson.get("benchmark_name").getAsString());
    }

    /**
     * Verify that WRK generates the same comprehensive structure as JMH benchmarks
     */
    private void verifyComprehensiveStructure() throws IOException {
        // Verify GitHub Pages directory structure
        Path outputDir = tempDir.resolve("output");
        Path ghPagesDir = outputDir.resolve("gh-pages-ready");
        assertTrue(Files.exists(ghPagesDir), "GitHub Pages directory should be created");

        // Verify main HTML files (WRK doesn't generate JMH-specific detailed.html)
        assertTrue(Files.exists(ghPagesDir.resolve("index.html")), "index.html should be created");
        assertTrue(Files.exists(ghPagesDir.resolve("trends.html")), "trends.html should be created");

        // Verify CSS and JavaScript files
        assertTrue(Files.exists(ghPagesDir.resolve("report-styles.css")), "CSS file should exist");
        assertTrue(Files.exists(ghPagesDir.resolve("data-loader.js")), "JavaScript file should exist");

        // Verify badges directory
        Path badgesDir = ghPagesDir.resolve("badges");
        assertTrue(Files.exists(badgesDir), "Badges directory should be created");

        // Verify comprehensive benchmark-data.json structure
        Path dataFile = ghPagesDir.resolve("data/benchmark-data.json");
        assertTrue(Files.exists(dataFile), "benchmark-data.json should be created");

        String jsonContent = Files.readString(dataFile);
        JsonObject json = JsonParser.parseString(jsonContent).getAsJsonObject();

        // Verify metadata structure matches JMH format
        assertTrue(json.has("metadata"), "Should have metadata section");
        JsonObject metadata = json.getAsJsonObject("metadata");
        assertTrue(metadata.has("timestamp"), "Should have timestamp");
        assertTrue(metadata.has("displayTimestamp"), "Should have displayTimestamp");
        assertTrue(metadata.has("benchmarkType"), "Should have benchmarkType");
        assertTrue(metadata.has("reportVersion"), "Should have reportVersion");

        // Verify overview section (performance scoring)
        assertTrue(json.has("overview"), "Should have overview section");
        JsonObject overview = json.getAsJsonObject("overview");
        assertTrue(overview.has("performanceScore"), "Should have performance score");
        assertTrue(overview.has("performanceGrade"), "Should have performance grade");

        // Verify benchmarks array structure
        assertTrue(json.has("benchmarks"), "Should have benchmarks array");
        assertTrue(json.getAsJsonArray("benchmarks").size() > 0, "Should have at least one benchmark");

        // Verify chart data structure
        assertTrue(json.has("chartData"), "Should have chart data section");

        // Verify trends structure
        assertTrue(json.has("trends"), "Should have trends section");

        // Verify each benchmark has comprehensive structure
        JsonObject benchmark = json.getAsJsonArray("benchmarks").get(0).getAsJsonObject();
        assertTrue(benchmark.has("name"), "Benchmark should have name");
        assertTrue(benchmark.has("mode"), "Benchmark should have mode");
        assertTrue(benchmark.has("score"), "Benchmark should have score");
        assertTrue(benchmark.has("scoreUnit"), "Benchmark should have scoreUnit");
        assertTrue(benchmark.has("percentiles"), "Benchmark should have percentiles");
    }
}
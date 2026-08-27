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

import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.converter.WrkBenchmarkConverter;
import de.cuioss.benchmarking.common.metrics.PrometheusMetricsManager;
import de.cuioss.benchmarking.common.model.BenchmarkData;
import de.cuioss.benchmarking.common.output.OutputDirectoryStructure;
import de.cuioss.benchmarking.common.report.GitHubPagesGenerator;
import de.cuioss.benchmarking.common.report.ReportGenerator;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.ERROR;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO;

/**
 * Post-processor for WRK benchmark results.
 * <p>
 * This class converts WRK output files to the central BenchmarkData format
 * and uses the unified report generation infrastructure from cui-benchmarking-common.
 */
public class WrkResultPostProcessor {

    private static final CuiLogger LOGGER = new CuiLogger(WrkResultPostProcessor.class);

    // File naming constants
    public static final String WRK_OUTPUT_FILE_SUFFIX = "-results.txt";
    public static final String WRK_HEALTH_OUTPUT_FILE = "wrk-health-results.txt";
    public static final String WRK_JWT_OUTPUT_FILE = "wrk-jwt-results.txt";

    private final WrkBenchmarkConverter converter = new WrkBenchmarkConverter();
    private final ReportGenerator reportGenerator = new ReportGenerator();
    private final GitHubPagesGenerator gitHubPagesGenerator = new GitHubPagesGenerator();
    private final PrometheusMetricsManager prometheusMetricsManager = new PrometheusMetricsManager();

    // Map to store benchmark metadata (name -> timestamps)
    private final Map<String, BenchmarkMetadata> benchmarkMetadataMap = new HashMap<>();

    /**
     * Holds metadata for a benchmark execution.
     */
    private record BenchmarkMetadata(String name, Instant startTime, Instant endTime) {
    }

    /**
     * Main entry point for processing WRK benchmark results.
     * Usage:
     *   - args[0]=inputDir, args[1]=outputDir (optional)
     * <p>
     * Exits with a non-zero code when processing fails, including when the input
     * directory is missing or no benchmark yields parseable metrics.
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            LOGGER.error(ERROR.WRK_USAGE_ERROR);
            System.exit(1);
        }

        try {
            Path inputDir = Path.of(args[0]);
            WrkResultPostProcessor processor = new WrkResultPostProcessor();

            // Normal processing mode
            Path outputDir = args.length > 1 ?
                    Path.of(args[1]) :
                    inputDir.getParent().resolve("benchmark-results");

            processor.process(inputDir, outputDir);

            LOGGER.info(INFO.RESULTS_AVAILABLE, outputDir);

        } catch (IOException | IllegalStateException | IllegalArgumentException e) {
            LOGGER.error(e, ERROR.WRK_PROCESSOR_FAILED);
            System.exit(1);
        }
    }

    /**
     * Processes WRK output files and generates reports.
     *
     * @param inputDir Directory containing WRK output files
     * @param outputDir Directory to write reports to
     * @throws IOException if processing fails
     * @throws IllegalArgumentException if the input directory is missing or not a directory
     * @throws IllegalStateException if no benchmark yields parseable metrics
     */
    public void process(Path inputDir, Path outputDir) throws IOException {
        LOGGER.info(INFO.WRK_PROCESSING_START);

        // Validate input directory BEFORE any parsing
        if (!Files.exists(inputDir)) {
            throw new IllegalArgumentException("Input directory does not exist: " + inputDir);
        }

        if (!Files.isDirectory(inputDir)) {
            throw new IllegalArgumentException("Input path is not a directory: " + inputDir);
        }

        // Parse all WRK result files to extract metadata (fails if no result files exist)
        parseBenchmarkMetadata(inputDir);

        // Convert WRK output to BenchmarkData from wrk subdirectory
        Path wrkDir = inputDir.resolve("wrk");
        if (!Files.exists(wrkDir)) {
            LOGGER.error(ERROR.WRK_DIR_NOT_EXIST, wrkDir);
            throw new IllegalStateException("WRK output directory does not exist: " + wrkDir);
        }

        BenchmarkData benchmarkData = converter.convert(wrkDir);

        // Fail loudly instead of publishing a report with fabricated zero-metrics
        if (benchmarkData.getBenchmarks() == null || benchmarkData.getBenchmarks().isEmpty()) {
            LOGGER.error(ERROR.NO_BENCHMARK_DATA);
            throw new IllegalStateException(
                    "No benchmark yielded parseable metrics from WRK output in: " + wrkDir);
        }

        // Generate reports using new OutputDirectoryStructure (no duplication)
        Files.createDirectories(outputDir);

        // Create OutputDirectoryStructure for organized file generation
        OutputDirectoryStructure structure = new OutputDirectoryStructure(outputDir);
        structure.ensureDirectories();

        // Generate HTML reports directly to gh-pages-ready directory
        String deploymentPath = structure.getDeploymentDir().toString();
        reportGenerator.generateIndexPage(benchmarkData, BenchmarkType.INTEGRATION, deploymentPath);
        reportGenerator.generateTrendsPage(deploymentPath);
        reportGenerator.copySupportFiles(deploymentPath);

        // Collect real-time Prometheus metrics for the benchmark execution
        collectPrometheusMetrics(benchmarkData, structure);

        // Generate GitHub Pages deployment-specific assets (404.html, robots.txt, sitemap.xml)
        gitHubPagesGenerator.generateDeploymentAssets(structure);
    }


    /**
     * Collect real-time metrics from Prometheus for the benchmark execution.
     * This captures time-series data during the actual benchmark run.
     * Metrics are stored in the raw prometheus directory and copied to deployment data directory.
     *
     * @param benchmarkData The benchmark data containing benchmark names
     * @param structure The output directory structure
     */
    private void collectPrometheusMetrics(BenchmarkData benchmarkData, OutputDirectoryStructure structure) {
        // Skip if no metadata available
        if (benchmarkMetadataMap.isEmpty()) {
            LOGGER.error(ERROR.NO_PROMETHEUS_METADATA);
            return;
        }

        // Process each benchmark result
        if (benchmarkData.getBenchmarks() != null) {
            for (BenchmarkData.Benchmark benchmark : benchmarkData.getBenchmarks()) {
                // Try to find metadata by matching the benchmark name
                BenchmarkMetadata metadata = findMetadataForBenchmark(benchmark.getName());

                if (metadata == null) {
                    LOGGER.error(ERROR.NO_METADATA_FOR_BENCHMARK, benchmark.getName());
                    continue;
                }

                // Use centralized PrometheusMetricsManager to collect metrics
                // Metrics are collected to the main benchmark results directory
                prometheusMetricsManager.collectMetricsForWrkBenchmark(
                        metadata.name,
                        metadata.startTime,
                        metadata.endTime,
                        structure.getBenchmarkResultsDir().toString()
                );
            }
        }

        // Copy Prometheus metrics from raw directory to deployment data directory
        copyPrometheusMetricsToDeployment(structure);
    }

    /**
     * Copies Prometheus metrics from the raw prometheus directory to the deployment data directory.
     * This ensures metrics are available in the deployable GitHub Pages structure.
     *
     * @param structure The output directory structure
     */
    private void copyPrometheusMetricsToDeployment(OutputDirectoryStructure structure) {
        try {
            Path prometheusRawDir = structure.getPrometheusRawDir();
            Path deploymentDataDir = structure.getDataDir();

            if (!Files.exists(prometheusRawDir)) {
                return;
            }

            // Copy all JSON files from prometheus/ to gh-pages-ready/data/
            try (Stream<Path> files = Files.list(prometheusRawDir)) {
                files.filter(file -> file.getFileName().toString().endsWith(".json"))
                        .forEach(sourceFile -> {
                            try {
                                Path targetFile = deploymentDataDir.resolve(sourceFile.getFileName());
                                Files.copy(sourceFile, targetFile, StandardCopyOption.REPLACE_EXISTING);
                            } catch (IOException e) {
                                LOGGER.error(e, ERROR.FAILED_COPY_PROMETHEUS, sourceFile);
                            }
                        });
            }
        } catch (IOException e) {
            LOGGER.error(e, ERROR.FAILED_COPY_PROMETHEUS_DIR);
        }
    }

    /**
     * Parse benchmark metadata from WRK result files.
     * Each result file contains embedded metadata including name, start time, and end time.
     *
     * @param inputDir The directory containing benchmark results
     * @throws IllegalStateException if no valid benchmark metadata is found
     */
    private void parseBenchmarkMetadata(Path inputDir) throws IOException {
        // Find all WRK result files in the wrk subdirectory
        Path wrkDir = inputDir.resolve("wrk");
        if (!Files.exists(wrkDir)) {
            return;
        }

        try (Stream<Path> files = Files.list(wrkDir)) {
            List<Path> wrkFiles = files
                    .filter(p -> p.getFileName().toString().endsWith(WRK_OUTPUT_FILE_SUFFIX))
                    .toList();

            if (wrkFiles.isEmpty()) {
                String message = "CRITICAL: No WRK result files (*%s) found in %s. Ensure benchmarks were run successfully."
                        .formatted(WRK_OUTPUT_FILE_SUFFIX, inputDir);
                LOGGER.error(ERROR.NO_WRK_FILES, inputDir);
                throw new IllegalStateException(message);
            }

            // Parse metadata from each file
            for (Path wrkFile : wrkFiles) {
                parseSingleBenchmarkMetadata(wrkFile);
            }

            if (benchmarkMetadataMap.isEmpty()) {
                String message = "CRITICAL: No valid benchmark metadata found in any result files";
                LOGGER.error(ERROR.NO_BENCHMARK_DATA);
                throw new IllegalStateException(message);
            }
        }
    }

    /**
     * Parse metadata from a single WRK result file.
     *
     * @param resultFile Path to the WRK result file
     */
    private void parseSingleBenchmarkMetadata(Path resultFile) {
        try {
            List<String> lines = Files.readAllLines(resultFile);
            String benchmarkName = null;
            Instant startTime = null;
            Instant endTime = null;
            boolean inMetadata = false;

            for (String line : lines) {
                if ("=== BENCHMARK METADATA ===".equals(line)) {
                    inMetadata = true;
                } else if ("=== WRK OUTPUT ===".equals(line)) {
                    inMetadata = false;
                } else if (inMetadata || line.startsWith("end_time:")) {
                    if (line.startsWith("benchmark_name: ")) {
                        benchmarkName = line.substring(16).trim();
                    } else if (line.startsWith("start_time: ")) {
                        long epochSeconds = Long.parseLong(line.substring(12).trim());
                        startTime = Instant.ofEpochSecond(epochSeconds);
                    } else if (line.startsWith("end_time: ")) {
                        long epochSeconds = Long.parseLong(line.substring(10).trim());
                        endTime = Instant.ofEpochSecond(epochSeconds);
                    }
                }
            }

            // Validate we have all required metadata
            if (benchmarkName == null || startTime == null || endTime == null) {
                LOGGER.error(ERROR.INCOMPLETE_METADATA, resultFile, benchmarkName, startTime, endTime);
                return;
            }

            // Store the metadata
            BenchmarkMetadata metadata = new BenchmarkMetadata(benchmarkName, startTime, endTime);
            benchmarkMetadataMap.put(benchmarkName, metadata);

        } catch (IOException | NumberFormatException e) {
            LOGGER.error(ERROR.FAILED_PARSE_METADATA, resultFile, e.getMessage());
        }
    }

    /**
     * Find metadata for a benchmark based on its result file name.
     *
     * @param benchmarkFileName The benchmark file name from BenchmarkData
     * @return The matching metadata or null if not found
     */
    private BenchmarkMetadata findMetadataForBenchmark(String benchmarkFileName) {
        // First try exact match
        if (benchmarkMetadataMap.containsKey(benchmarkFileName)) {
            return benchmarkMetadataMap.get(benchmarkFileName);
        }

        // Try to extract base name and match
        String baseName = benchmarkFileName;
        if (baseName.endsWith(".txt")) {
            baseName = baseName.substring(0, baseName.length() - 4);
        }
        if (baseName.endsWith("-results")) {
            baseName = baseName.substring(0, baseName.length() - 8);
        }

        // Exact normalized-name match only: substring or single-benchmark fallbacks can
        // silently attach the wrong Prometheus window (e.g. healthCheck vs healthLiveCheck).
        // The caller logs NO_METADATA_FOR_BENCHMARK when this returns null.
        return benchmarkMetadataMap.get(baseName);
    }
}
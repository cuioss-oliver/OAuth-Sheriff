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
package de.cuioss.benchmarking.common.util;

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;

/**
 * Provides structured logging messages for the cui-benchmarking-common module.
 * All messages follow the format: Benchmarking-[identifier]: [message]
 * <p>
 * Message identifier ranges:
 * <ul>
 *   <li>001-099: INFO messages</li>
 *   <li>100-199: WARN messages</li>
 *   <li>200-299: ERROR messages</li>
 *   <li>500-599: DEBUG messages</li>
 * </ul>
 *
 */
public final class BenchmarkingLogMessages {

    private static final String PREFIX = "Benchmarking";

    /** Private constructor to prevent instantiation. */
    private BenchmarkingLogMessages() {
        // utility class
    }

    /**
     * INFO level messages for normal benchmark operations.
     */
    public static final class INFO {

        /** Private constructor to prevent instantiation. */
        private INFO() {
            // utility class
        }

        /** Message when starting benchmark runner. */
        public static final LogRecord BENCHMARK_RUNNER_STARTING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("Starting CUI benchmark runner...")
                .build();

        /** Message when benchmarks complete successfully. */
        public static final LogRecord BENCHMARKS_COMPLETED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(3)
                .template("Benchmarks completed successfully with %s results")
                .build();

        /** Message when all artifacts are generated. */
        public static final LogRecord ARTIFACTS_GENERATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(4)
                .template("All artifacts generated successfully")
                .build();

        /** Message when processing benchmark results. */
        public static final LogRecord PROCESSING_RESULTS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(5)
                .template("Processing %s benchmark results to generate artifacts")
                .build();

        /** Message showing detected benchmark type. */
        public static final LogRecord BENCHMARK_TYPE_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(6)
                .template("Detected benchmark type: %s")
                .build();

        /** Message when generating performance badges. */
        /** Message when generating metrics. */
        /** Message when generating HTML reports. */
        public static final LogRecord GENERATING_REPORTS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(9)
                .template("Generating HTML reports")
                .build();

        /** Message when generating GitHub Pages structure. */
        public static final LogRecord GENERATING_GITHUB_PAGES = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(10)
                .template("Generating GitHub Pages deployment structure")
                .build();

        /** Message when writing benchmark summary. */
        /** Message when generating metrics JSON. */
        /** Message when metrics file is generated. */
        public static final LogRecord METRICS_FILE_GENERATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(13)
                .template("Generated metrics file: %s")
                .build();

        /** Message when individual metric files are generated. */
        /** Message when performance badge is generated. */
        public static final LogRecord BADGE_GENERATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(15)
                .template("Generated %s badge: %s")
                .build();

        /** Message when GitHub Pages is being prepared. */
        public static final LogRecord PREPARING_GITHUB_PAGES = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(16)
                .template("Preparing GitHub Pages deployment structure")
                .build();

        /** Message showing source directory. */
        /** Message showing deploy directory. */
        public static final LogRecord DEPLOY_DIRECTORY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(18)
                .template("Deploy: %s")
                .build();

        /** Message when GitHub Pages is ready. */
        public static final LogRecord GITHUB_PAGES_READY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(19)
                .template("GitHub Pages deployment structure ready")
                .build();

        /** Message when generating index page. */
        public static final LogRecord GENERATING_INDEX_PAGE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(20)
                .template("Generating index page for %s benchmark results")
                .build();

        /** Message when index page is generated. */
        public static final LogRecord INDEX_PAGE_GENERATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(21)
                .template("Generated index page: %s")
                .build();

        /** Message when generating trends page. */
        public static final LogRecord GENERATING_TRENDS_PAGE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(22)
                .template("Generating trends page")
                .build();

        /** Message when trends page is generated. */
        public static final LogRecord TRENDS_PAGE_GENERATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(23)
                .template("Generated trends page: %s")
                .build();

        /** Message when detailed page is generated. */
        public static final LogRecord DETAILED_PAGE_GENERATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(2)
                .template("Generated detailed page: %s")
                .build();

        /** Message when writing benchmark summary. */
        /** Message when summary file is generated. */
        /** Message when JMH result file is copied to data directory. */
        public static final LogRecord JMH_RESULT_COPIED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(26)
                .template("Copied JMH result to data directory: %s")
                .build();

        /** Message when JWT validation micro benchmarks start with key cache initialized. */
        public static final LogRecord JWT_BENCHMARKS_STARTING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(27)
                .template("JWT validation micro benchmarks starting - Key cache initialized")
                .build();

        /** Message when RSA key pre-generation starts. */
        public static final LogRecord KEY_PREGENERATION_STARTING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(28)
                .template("BenchmarkKeyCache: Starting RSA key pre-generation...")
                .build();

        /** Message when RSA key pre-generation completes. */
        public static final LogRecord KEY_PREGENERATION_COMPLETED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(29)
                .template("BenchmarkKeyCache: Pre-generated keys for %s issuer configurations in %s ms")
                .build();

        /** Message when unified report generation starts. */
        /** Message when unified report generation completes. */
        /** Message when generating data file. */
        /** Message when data file is generated. */
        /** Message when generating HTML files. */
        /** Message when HTML files are generated. */
        /** Message when generating badges (unified). */
        /** Message when badges are generated. */
        /** Message when generating API endpoints. */
        /** Message when API endpoints are generated. */
        /** Message when copying Prometheus metrics. */
        /** Message when Prometheus metrics are copied. */
        /** Message when copying support files. */
        /** Message when support files are copied. */
        /** Message when key cache is initialized. */
        public static final LogRecord KEY_CACHE_INITIALIZED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(44)
                .template("BenchmarkKeyCache: Initialized with %s configurations")
                .build();

        /** Message when Quarkus JWT integration benchmarks start. */
        /** Message when processing results starts. */
        /** Message when results are available. */
        public static final LogRecord RESULTS_AVAILABLE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(47)
                .template("Results available at: %s")
                .build();

        /** Message when starting to process WRK results. */
        public static final LogRecord WRK_PROCESSING_START = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(48)
                .template("Start processing WRK results")
                .build();

        /** Message when JFR instrumented benchmarks start. */
        public static final LogRecord JFR_BENCHMARKS_STARTING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(49)
                .template("JFR-instrumented benchmarks starting - Key cache initialized")
                .build();

        /** Message when JFR recording will be saved. */
        public static final LogRecord JFR_RECORDING_PATH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(50)
                .template("JFR recording will be saved to: %s")
                .build();

        /** Message when JFR benchmark completed. */
        public static final LogRecord JFR_BENCHMARK_COMPLETED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(51)
                .template("JFR benchmark completed. To analyze variance:")
                .build();

        /** Message showing how to run variance analysis. */
        public static final LogRecord JFR_VARIANCE_COMMAND = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(52)
                .template("java -cp \"target/classes:target/dependency/*\" de.cuioss.sheriff.token.validation.benchmark.jfr.JfrVarianceAnalyzer %s")
                .build();

        /** Message when iteration windows are parsed from timestamp file. */
        /** Message when using precise timestamps for benchmark. */
        /** Message when starting benchmark runner with configuration details. */
        public static final LogRecord BENCHMARK_RUNNER_STARTING_WITH_DETAILS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(55)
                .template("Starting CUI benchmark runner - Type: %s, Output: %s")
                .build();

        /** Message when benchmarks complete with artifact location. */
        public static final LogRecord BENCHMARKS_COMPLETED_WITH_ARTIFACTS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(56)
                .template("Benchmarks completed successfully with %s results, artifacts in %s")
                .build();

        /** Message when Prometheus metrics collection is enabled. */
        public static final LogRecord PROMETHEUS_ENABLED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(57)
                .template("Prometheus metrics collection enabled - URL: %s")
                .build();

        /** Message when Prometheus metrics collection is disabled. */
        public static final LogRecord PROMETHEUS_DISABLED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(58)
                .template("Prometheus metrics collection disabled - Prometheus not available at: %s")
                .build();

        /** Message when collecting real-time metrics from Prometheus. */
        /** Message when collecting real-time metrics for WRK benchmark. */
        public static final LogRecord COLLECTING_WRK_PROMETHEUS_METRICS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(60)
                .template("Collecting real-time metrics for WRK benchmark '%s' from Prometheus")
                .build();

        /** Message when Prometheus metrics are saved. */
        public static final LogRecord PROMETHEUS_METRICS_SAVED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(61)
                .template("Prometheus metrics saved to: %s/%s%s")
                .build();

        /** Message when using session timestamps for benchmark. */
        /** Message when collecting Prometheus metrics for benchmark. */
        /** Message when collecting real-time metrics for benchmark with time range. */
        public static final LogRecord COLLECTING_REALTIME_METRICS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(64)
                .template("Collecting real-time metrics for benchmark '%s' from %s to %s")
                .build();

        /** Message when real-time metrics are exported. */
        public static final LogRecord REALTIME_METRICS_EXPORTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(65)
                .template("Exported real-time metrics for '%s' to: %s")
                .build();

        /** Message when HTTP client is created. */
        public static final LogRecord HTTP_CLIENT_CREATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(66)
                .template("Created Java HttpClient with version: %s, timeout: %ss")
                .build();

        /** Message when using HTTP/1.1. */
        public static final LogRecord USING_HTTP_1_1 = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(67)
                .template("Using HTTP/1.1 only (configured via -D%s=http1)")
                .build();

        /** Message when using HTTP/2. */
        public static final LogRecord USING_HTTP_2 = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(68)
                .template("Using HTTP/2 (default or -D%s=http2)")
                .build();

        /** Message when Prometheus connectivity advice is given. */
        public static final LogRecord PROMETHEUS_CONNECTIVITY_ADVICE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(69)
                .template("Ensure Prometheus is running and accessible. You can verify with: curl %s/api/v1/query?query=up")
                .build();

        /** Message when using external history directory. */
        /** Message when history directory not found. */
        public static final LogRecord HISTORY_DIR_NOT_FOUND = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(71)
                .template("History directory not found: %s")
                .build();

        /** Message when benchmark data is archived. */
        public static final LogRecord ARCHIVED_BENCHMARK_DATA = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(72)
                .template("Archived benchmark data to %s")
                .build();

        /** Message when old history file is removed. */
        public static final LogRecord REMOVED_HISTORY_FILE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(73)
                .template("Removed old history file: %s")
                .build();

    }

    /**
     * WARN level messages for potential issues.
     */
    public static final class WARN {

        /** Private constructor to prevent instantiation. */
        private WARN() {
            // utility class
        }

        /** Warning when failed to copy HTML file. */
        /** Warning when failed to copy badge file. */
        /** Warning when failed to copy data file. */
        /** Warning for issues during index generation or processing. */
        public static final LogRecord ISSUE_DURING_INDEX_GENERATION = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(103)
                .template("Issue during %s")
                .build();

        /** Warning when key cache miss occurs during benchmark. */
        /** Warning when invalid metrics data type. */
        public static final LogRecord INVALID_METRICS_TYPE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(105)
                .template("Invalid metrics data type: expected TokenValidatorMonitor, got %s")
                .build();

        /** Warning when timestamp file does not exist. */
        /** Warning when failed to parse timestamp line. */
        /** Warning when failed to parse timestamp file. */
        /** Warning when no timestamp data found for benchmark. */
        /** Warning when no measurement windows found for benchmark. */
        /** Warning when failed to query metric. */
        public static final LogRecord FAILED_QUERY_METRIC = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(111)
                .template("Failed to query metric '%s': %s")
                .build();

        /** Warning when overwriting existing start time. */
        /** Warning when invalid timestamps detected. */
        /** Warning when failed to collect Prometheus metrics. */
        public static final LogRecord FAILED_COLLECT_PROMETHEUS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(114)
                .template("Failed to collect Prometheus metrics: %s")
                .build();

        /** Warning when skipping Prometheus metrics collection. */
        public static final LogRecord SKIPPING_PROMETHEUS_COLLECTION = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(115)
                .template("Skipping Prometheus metrics collection - Prometheus not available at URL: %s")
                .build();

        /** Warning when cannot collect metrics due to missing timestamps. */
        public static final LogRecord MISSING_TIMESTAMPS_FOR_COLLECTION = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(116)
                .template("Cannot collect metrics for benchmark '%s' - missing timestamps")
                .build();

        /** Warning when no valid timestamps found. */
        /** Warning when failed to collect metrics for benchmark. */
        /** Warning when failed to create target directory. */
        public static final LogRecord FAILED_CREATE_TARGET_DIR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(119)
                .template("Failed to create target directory: %s")
                .build();

        /** Warning when failed to read existing metrics file. */
        public static final LogRecord FAILED_READ_METRICS_FILE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(120)
                .template("Failed to read existing metrics file %s: %s")
                .build();

        /** Warning when a corrupt metrics file has been moved aside for later inspection. */
        public static final LogRecord CORRUPT_METRICS_FILE_PRESERVED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(121)
                .template("Corrupt metrics file preserved as: %s")
                .build();

        /** Warning when a corrupt metrics file could not be moved aside. */
        public static final LogRecord FAILED_PRESERVE_CORRUPT_FILE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(127)
                .template("Failed to move corrupt metrics file aside: %s")
                .build();

        /** Warning when unknown result format detected. */
        public static final LogRecord UNKNOWN_RESULT_FORMAT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(122)
                .template("Unknown result format: %s, defaulting to JSON")
                .build();

        /** Warning when unknown time unit detected. */
        public static final LogRecord UNKNOWN_TIME_UNIT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(123)
                .template("Unknown time unit '%s' in '%s', defaulting to seconds")
                .build();

        /** Warning when token pool is empty. */
        /** Warning when issue parsing history file. */
        public static final LogRecord ISSUE_PARSING_HISTORY_FILE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(125)
                .template("Issue during parsing history file: %s")
                .build();

        /** Warning when a secret-bearing system property is forwarded to a forked JVM command line. */
        public static final LogRecord SECRET_PROPERTY_ON_FORK_COMMAND_LINE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(126)
                .template("Secret system property '%s' is forwarded on the forked JVM command line and may be visible in process listings")
                .build();
    }

    /**
     * ERROR level messages for serious failures.
     */
    public static final class ERROR {

        /** Private constructor to prevent instantiation. */
        private ERROR() {
            // utility class
        }

        /** Error when export of benchmark metrics fails. */
        public static final LogRecord EXPORT_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(200)
                .template("Failed to export benchmark metrics")
                .build();

        /** Error when WRK result processor fails. */
        public static final LogRecord WRK_PROCESSOR_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(201)
                .template("Failed to execute WRK result processor")
                .build();

        /** Error when WRK usage is incorrect. */
        public static final LogRecord WRK_USAGE_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(202)
                .template("Usage: WrkResultPostProcessor <input-dir> [output-dir]")
                .build();

        /** Error when no WRK output files found. */
        public static final LogRecord NO_WRK_FILES = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(203)
                .template("No WRK output files found in: %s")
                .build();

        /** Error when WRK output directory does not exist. */
        public static final LogRecord WRK_DIR_NOT_EXIST = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(204)
                .template("WRK output directory does not exist: %s")
                .build();

        /** Error when no benchmark data extracted. */
        public static final LogRecord NO_BENCHMARK_DATA = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(205)
                .template("No benchmark data extracted from WRK output files")
                .build();

        /** Error when cannot collect Prometheus metrics. */
        public static final LogRecord NO_PROMETHEUS_METADATA = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(206)
                .template("Cannot collect Prometheus metrics: no benchmark metadata available")
                .build();

        /** Error when no metadata found for benchmark. */
        public static final LogRecord NO_METADATA_FOR_BENCHMARK = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(207)
                .template("No metadata found for benchmark: %s")
                .build();

        /** Error when failed to copy Prometheus metrics file. */
        public static final LogRecord FAILED_COPY_PROMETHEUS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(208)
                .template("Failed to copy Prometheus metrics file: %s")
                .build();

        /** Error when failed to copy Prometheus metrics to deployment directory. */
        public static final LogRecord FAILED_COPY_PROMETHEUS_DIR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(209)
                .template("Failed to copy Prometheus metrics to deployment directory")
                .build();

        /** Error when missing timestamps in results. */
        public static final LogRecord MISSING_TIMESTAMPS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(210)
                .template("Missing start or end timestamp in result file: %s")
                .build();

        /** Error when failed to parse metadata. */
        public static final LogRecord FAILED_PARSE_METADATA = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(211)
                .template("Failed to parse metadata from %s: %s")
                .build();

        /** Error when incomplete metadata found. */
        public static final LogRecord INCOMPLETE_METADATA = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(212)
                .template("Incomplete metadata in file %s (name=%s, start=%s, end=%s)")
                .build();

        /** Error when failed to collect Prometheus metrics for benchmark. */
        public static final LogRecord FAILED_COLLECT_PROMETHEUS_BENCHMARK = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(213)
                .template("Failed to collect Prometheus metrics for benchmark '%s' from URL: %s")
                .build();

        /** Error when Prometheus connectivity check failed. */
        public static final LogRecord PROMETHEUS_CONNECTIVITY_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(214)
                .template("Prometheus connectivity check failed at URL: %s - Error: %s (%s)")
                .build();

        /** Error when failed to collect real-time Prometheus metrics. */
        public static final LogRecord FAILED_COLLECT_REALTIME_PROMETHEUS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(215)
                .template("Failed to collect Prometheus metrics for benchmark '%s': %s")
                .build();

        /** Error when failed to fetch token. */
        /** Error when failed to parse WRK file. */
        public static final LogRecord FAILED_PARSE_WRK_FILE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(217)
                .template("Failed to parse WRK file: %s")
                .build();

        /** Error for JfrVarianceAnalyzer usage. */
        public static final LogRecord JFR_VARIANCE_USAGE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(218)
                .template("Usage: JfrVarianceAnalyzer <path-to-jfr-file>")
                .build();
    }

}
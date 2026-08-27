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
package de.cuioss.benchmarking.common.constants;

import lombok.experimental.UtilityClass;

/**
 * Consolidated constants for benchmark modules.
 * Organized using the DSL-Style Nested Constants Pattern with static imports.
 */
@SuppressWarnings("java:S1075")
// False positive, no URL Parameter
@UtilityClass
public final class BenchmarkConstants {

    /**
     * Metrics-related constants for measurement and reporting.
     */
    @UtilityClass
    public static final class Metrics {

        /**
         * The common prefix for all JWT metrics.
         */
        public static final String PREFIX = "sheriff.token";

        /**
         * Benchmark modes.
         */
        @UtilityClass
        public static final class Modes {
            public static final String THROUGHPUT = "thrpt";
            public static final String AVERAGE_TIME = "avgt";
            public static final String SAMPLE = "sample";
        }

        /**
         * Unit strings for benchmark measurements.
         */
        @UtilityClass
        public static final class Units {
            // Operations per time unit
            public static final String OPS_PER_SEC = "ops/s";
            public static final String OPS_PER_SEC_ALT = "ops/sec";
            public static final String OPS_PER_MS = "ops/ms";
            public static final String OPS_PER_US = "ops/us";
            public static final String OPS_PER_NS = "ops/ns";
            public static final String OPS = "ops";

            // Time per operation
            public static final String SEC_PER_OP = "s/op";
            public static final String MS_PER_OP = "ms/op";
            public static final String US_PER_OP = "us/op";
            public static final String NS_PER_OP = "ns/op";

            // Display suffixes
            public static final String K_OPS_S = "K ops/s";
            public static final String M_OPS_S = "M ops/s";
            public static final String SPACE_OPS_S = " ops/s";
            public static final String SUFFIX_S = "s";
            public static final String SUFFIX_MS = "ms";
            public static final String SUFFIX_OP = "/op";
        }

        /**
         * Conversion factors between different units.
         */
        @UtilityClass
        public static final class Conversions {
            public static final double MILLIS_TO_SECONDS = 1000.0;
            public static final double MICROS_TO_SECONDS = 1_000_000.0;
            public static final double NANOS_TO_SECONDS = 1_000_000_000.0;
            public static final double MICROS_TO_MILLIS = 1000.0;
            public static final double NANOS_TO_MILLIS = 1_000_000.0;
        }

        /**
         * Percentile-related constants.
         */
        @UtilityClass
        public static final class Percentiles {
            // Percentile keys
            public static final String P_0 = "0.0";
            public static final String P_50 = "50.0";
            public static final String P_90 = "90.0";
            public static final String P_95 = "95.0";
            public static final String P_99 = "99.0";
            public static final String P_99_9 = "99.9";
            public static final String P_99_99 = "99.99";
            public static final String P_100 = "100.0";

            // Percentile labels
            public static final String LABEL_P0 = "P0";
            public static final String LABEL_P50 = "P50";
            public static final String LABEL_P90 = "P90";
            public static final String LABEL_P95 = "P95";
            public static final String LABEL_P99 = "P99";
            public static final String LABEL_P99_9 = "P99.9";
            public static final String LABEL_P99_99 = "P99.99";
            public static final String LABEL_P100 = "P100";

            public static final String SUFFIX_TH = "th";
        }
    }

    /**
     * Report-related constants for benchmark report generation.
     */
    @UtilityClass
    public static final class Report {

        /**
         * JSON field names used in benchmark data structures.
         */
        @UtilityClass
        public static final class JsonFields {
            // Primary fields
            public static final String PRIMARY_METRIC = "primaryMetric";
            public static final String BENCHMARK = "benchmark";
            public static final String MODE = "mode";
            public static final String SCORE = "score";
            public static final String SCORE_UNIT = "scoreUnit";
            public static final String TIMESTAMP = "timestamp";
            public static final String BENCHMARKS = "benchmarks";
            public static final String SUMMARY = "summary";

            // Report data fields
            public static final String METADATA = "metadata";
            public static final String OVERVIEW = "overview";
            public static final String CHART_DATA = "chartData";
            public static final String TRENDS = "trends";
            public static final String DISPLAY_TIMESTAMP = "displayTimestamp";
            public static final String BENCHMARK_TYPE = "benchmarkType";
            public static final String REPORT_VERSION = "reportVersion";

            // Metrics fields
            public static final String THROUGHPUT = "throughput";
            public static final String LATENCY = "latency";
            public static final String THROUGHPUT_BENCHMARK_NAME = "throughputBenchmarkName";
            public static final String LATENCY_BENCHMARK_NAME = "latencyBenchmarkName";
            public static final String PERFORMANCE_SCORE = "performanceScore";
            public static final String PERFORMANCE_GRADE = "performanceGrade";
            public static final String PERFORMANCE_GRADE_CLASS = "performanceGradeClass";

            // Result fields
            public static final String NAME = "name";
            public static final String FULL_NAME = "fullName";
            public static final String ERROR = "error";
            public static final String VARIABILITY_COEFFICIENT = "variabilityCoefficient";
            public static final String CONFIDENCE_LOW = "confidenceLow";
            public static final String CONFIDENCE_HIGH = "confidenceHigh";
            public static final String PERCENTILES = "percentiles";

            // Chart fields
            public static final String LABELS = "labels";
            public static final String PERCENTILES_DATA = "percentilesData";
            public static final String PERCENTILE_LABELS = "percentileLabels";
            public static final String DATA = "data";
            public static final String DATASETS = "datasets";

            // Status fields
            public static final String STATUS = "status";
            public static final String GENERATED = "generated";
            public static final String LAST_RUN = "last_run";
            public static final String LINKS = "links";
            public static final String AVAILABLE = "available";

            // Summary fields
            public static final String TOTAL_BENCHMARKS = "total_benchmarks";
            public static final String PERFORMANCE_GRADE_KEY = "performance_grade";
        }

        /**
         * Badge-related constants for shields.io integration.
         */
        @UtilityClass
        public static final class Badge {
            public static final String SCHEMA_VERSION = "schemaVersion";
            public static final String LABEL = "label";
            public static final String MESSAGE = "message";
            public static final String COLOR = "color";

            /**
             * Badge colors following shields.io color scheme.
             */
            @UtilityClass
            public static final class Colors {
                public static final String BRIGHT_GREEN = "brightgreen";
                public static final String GREEN = "green";
                public static final String YELLOW_GREEN = "yellowgreen";
                public static final String YELLOW = "yellow";
                public static final String ORANGE = "orange";
                public static final String RED = "red";
                public static final String BLUE = "blue";
                public static final String LIGHT_GRAY = "lightgray";
            }

            /**
             * Badge labels.
             */
            @UtilityClass
            public static final class Labels {
                public static final String PERFORMANCE = "Performance";
                public static final String TREND = "Trend";
                public static final String LAST_RUN = "Last Run";
            }

            /**
             * Trend indicators.
             */
            @UtilityClass
            public static final class Trends {
                public static final String STABLE = "→ stable";
            }

            /**
             * Badge messages.
             */
            @UtilityClass
            public static final class Messages {
                public static final String NO_HISTORY = "No history";
            }

            /**
             * Badge file names.
             */
            @UtilityClass
            public static final class FileNames {
                public static final String PERFORMANCE_BADGE_JSON = "performance-badge.json";
                public static final String TREND_BADGE_JSON = "trend-badge.json";
                public static final String INTEGRATION_PERFORMANCE_BADGE_JSON = "integration-performance-badge.json";
                public static final String INTEGRATION_TREND_BADGE_JSON = "integration-trend-badge.json";
                public static final String LAST_RUN_BADGE_JSON = "last-run-badge.json";
            }

            /**
             * Trend direction constants.
             */
            @UtilityClass
            public static final class TrendDirection {
                public static final String UP = "up";
                public static final String DOWN = "down";
                public static final String STABLE = "stable";
            }

            /**
             * Arrow symbols for trends.
             */
            @UtilityClass
            public static final class Arrows {
                public static final String UP = "↑";
                public static final String DOWN = "↓";
                public static final String RIGHT = "→";
                public static final String BULLET = "•";
            }
        }

        /**
         * Performance grade constants.
         */
        @UtilityClass
        public static final class Grades {
            public static final String A_PLUS = "A+";
            public static final String A = "A";
            public static final String B = "B";
            public static final String C = "C";
            public static final String D = "D";
            public static final String F = "F";

            /**
             * CSS class names for grades.
             */
            @UtilityClass
            public static final class CssClasses {
                public static final String GRADE_F = "grade-f";
            }
        }

        /**
         * Default values for missing data.
         */
        @UtilityClass
        public static final class Defaults {
            public static final String N_A = "N/A";
        }

        /**
         * Template paths and resources.
         */
        @UtilityClass
        public static final class Templates {
            public static final String PATH_PREFIX = "/templates/";
            public static final String NOT_FOUND_FORMAT = "Template not found: %s";
        }

        /**
         * Error messages.
         */
        @UtilityClass
        public static final class Errors {
            public static final String THROUGHPUT_NAME_REQUIRED = "Throughput benchmark name must be specified";
            public static final String LATENCY_NAME_REQUIRED = "Latency benchmark name must be specified";
            public static final String NO_RESULTS_PROVIDED = "No benchmark results provided";
            public static final String THROUGHPUT_NOT_FOUND_FORMAT = "Required throughput benchmark '%s' not found in results";
            public static final String LATENCY_NOT_FOUND_FORMAT = "Required latency benchmark '%s' not found in results";
            public static final String THROUGHPUT_NON_NEGATIVE = "Throughput must not be negative, got: ";
            public static final String LATENCY_NON_NEGATIVE = "Latency must not be negative, got: ";
            public static final String SCORE_NON_NEGATIVE = "Performance score must be non-negative, got: ";
        }

        /**
         * Messages for UI display.
         */
        @UtilityClass
        public static final class Messages {
            public static final String HISTORICAL_DATA_NOT_AVAILABLE = "Historical data not yet available";
            public static final String PERFORMANCE_STABLE_FORMAT = "Performance is stable (%.1f%% change)";
            public static final String PERFORMANCE_IMPROVED_FORMAT = "Performance improved by %.1f%%";
            public static final String PERFORMANCE_DECREASED_FORMAT = "Performance decreased by %.1f%%";
        }

        /**
         * Date/time format patterns.
         */
        @UtilityClass
        public static final class DateFormats {
            public static final String DISPLAY_TIMESTAMP_PATTERN = "yyyy-MM-dd HH:mm:ss 'UTC'";
        }

        /**
         * Version information.
         */
        @UtilityClass
        public static final class Versions {
            public static final String REPORT_VERSION = "2.0";
        }

        /**
         * API endpoint paths.
         */
        @UtilityClass
        public static final class Api {
            public static final String LATEST_JSON = "latest.json";
            public static final String BENCHMARKS_JSON = "benchmarks.json";
            public static final String STATUS_JSON = "status.json";

            // API paths
            public static final String API_BENCHMARKS_PATH = "/api/benchmarks.json";
            public static final String BADGES_PATH = "/badges/";

            // Status values
            public static final String STATUS_HEALTHY = "healthy";
            public static final String STATUS_SUCCESS = "success";
        }
    }

    /**
     * Integration-related constants for configuration and setup.
     */
    @UtilityClass
    public static final class Integration {

        /**
         * System properties for integration configuration.
         */
        @UtilityClass
        public static final class Properties {
        }

        /**
         * JMH configuration properties.
         */
        @UtilityClass
        public static final class Jmh {
            public static final String INCLUDE = "jmh.include";
            public static final String FORKS = "jmh.forks";
            public static final String WARMUP_ITERATIONS = "jmh.warmupIterations";
            public static final String MEASUREMENT_ITERATIONS = "jmh.iterations";
            public static final String MEASUREMENT_TIME = "jmh.time";
            public static final String WARMUP_TIME = "jmh.warmupTime";
            public static final String THREADS = "jmh.threads";
            public static final String RESULT_FORMAT = "jmh.result.format";
        }
    }

    /**
     * File and directory constants for benchmark I/O operations.
     */
    @UtilityClass
    public static final class Files {

        /**
         * Directory paths.
         */
        @UtilityClass
        public static final class Directories {
            public static final String RESULTS_DIR = "target/benchmark-results";
            public static final String DATA_DIR = "data";
        }

        /**
         * HTML files.
         */
        @UtilityClass
        public static final class Html {
            public static final String INDEX = "index.html";
            public static final String TRENDS = "trends.html";
            public static final String DETAILED = "detailed.html";
            public static final String ERROR_404 = "404.html";
        }

        /**
         * Support files.
         */
        @UtilityClass
        public static final class Support {
            public static final String REPORT_STYLES_CSS = "report-styles.css";
            public static final String DATA_LOADER_JS = "data-loader.js";
            public static final String ROBOTS_TXT = "robots.txt";
            public static final String SITEMAP_XML = "sitemap.xml";
        }

        /**
         * Data files.
         */
        @UtilityClass
        public static final class Data {
            public static final String BENCHMARK_DATA_JSON = "benchmark-data.json";
            public static final String LAST_RUN_BADGE_JSON = "last-run-badge.json";
        }

        /**
         * File extensions.
         */
        @UtilityClass
        public static final class Extensions {
            public static final String HTML = ".html";
            public static final String JSON = ".json";
        }
    }
}
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
package de.cuioss.benchmarking.common.config;

import org.openjdk.jmh.results.format.ResultFormatType;

import java.io.File;

import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Files.Directories;

/**
 * Configuration for benchmark report generation.
 * Contains all report-specific settings that control how benchmark results
 * are processed and presented.
 * 
 * <p>Example usage:
 * <pre>{@code
 * var reportConfig = ReportConfiguration.builder()
 *     .withBenchmarkType(BenchmarkType.MICRO)
 *     .withThroughputBenchmarkName("measureThroughput")
 *     .withLatencyBenchmarkName("measureAverageTime")
 *     .withResultsDirectory("target/benchmark-results")
 *     .build();
 * }</pre>
 * 
 */
public record ReportConfiguration(
BenchmarkType benchmarkType,
String throughputBenchmarkName,
String latencyBenchmarkName,
String resultsDirectory,
String resultFile,
ResultFormatType resultFormat,
String projectName
) {


    /**
     * Creates a builder with default values.
     * 
     * @return a new builder with default values
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a builder from this configuration.
     * 
     * @return a new builder initialized with this configuration's values
     */
    public Builder toBuilder() {
        return new Builder()
                .withBenchmarkType(benchmarkType)
                .withThroughputBenchmarkName(throughputBenchmarkName)
                .withLatencyBenchmarkName(latencyBenchmarkName)
                .withResultsDirectory(resultsDirectory)
                .withResultFile(resultFile)
                .withResultFormat(resultFormat)
                .withProjectName(projectName);
    }

    /**
     * Gets the result file path, generating one if not explicitly set.
     * Creates the results directory if it doesn't exist.
     * 
     * @return the result file path
     */
    public String getOrCreateResultFile() {
        if (resultFile != null) {
            return resultFile;
        }

        // Create results directory if it doesn't exist
        File dir = new File(resultsDirectory);
        if (!dir.exists() && !dir.mkdirs() && !dir.exists()) {
            throw new IllegalStateException("Could not create results directory: " + resultsDirectory);
        }

        // Generate result file name based on benchmark type (non-null, enforced by build())
        String typePrefix = benchmarkType.name().toLowerCase();
        return resultsDirectory + "/" + typePrefix + "-result.json";
    }

    /**
     * Builder for ReportConfiguration.
     */
    public static class Builder {
        private BenchmarkType benchmarkType;
        private String throughputBenchmarkName;
        private String latencyBenchmarkName;
        private String resultsDirectory = Directories.RESULTS_DIR;
        private String resultFile;
        // jmh.result.format is resolved once in BenchmarkConfiguration.fromSystemProperties()
        // and passed in via withResultFormat — no second property read here
        private ResultFormatType resultFormat = ResultFormatType.JSON;
        private String projectName;

        public Builder withBenchmarkType(BenchmarkType type) {
            this.benchmarkType = type;
            return this;
        }

        public Builder withThroughputBenchmarkName(String name) {
            this.throughputBenchmarkName = name;
            return this;
        }

        public Builder withLatencyBenchmarkName(String name) {
            this.latencyBenchmarkName = name;
            return this;
        }

        public Builder withResultsDirectory(String dir) {
            this.resultsDirectory = dir;
            return this;
        }

        public Builder withResultFile(String file) {
            this.resultFile = file;
            return this;
        }

        public Builder withResultFormat(ResultFormatType format) {
            this.resultFormat = format;
            return this;
        }

        public Builder withProjectName(String name) {
            this.projectName = name;
            return this;
        }

        /**
         * Builds the configuration.
         * 
         * @return the built configuration
         * @throws IllegalArgumentException if required fields are not set
         */
        public ReportConfiguration build() {
            // Validate required fields
            if (benchmarkType == null) {
                throw new IllegalArgumentException("Benchmark type must be set");
            }
            if (throughputBenchmarkName == null || throughputBenchmarkName.isBlank()) {
                throw new IllegalArgumentException("Throughput benchmark name must be set");
            }
            if (latencyBenchmarkName == null || latencyBenchmarkName.isBlank()) {
                throw new IllegalArgumentException("Latency benchmark name must be set");
            }

            return new ReportConfiguration(
                    benchmarkType,
                    throughputBenchmarkName,
                    latencyBenchmarkName,
                    resultsDirectory,
                    resultFile,
                    resultFormat,
                    projectName
            );
        }

    }
}